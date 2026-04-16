package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const writeChunk = 256 * 1024 // 256 KB per Write call

var zeroChunk = make([]byte, writeChunk) // reused across all flows

// cidGenerator implements quic.ConnectionIDGenerator and captures the first
// generated ID so we can display the CID and P4 register bucket.
type cidGenerator struct {
	length int
	ch     chan []byte
	once   sync.Once
}

func newCIDGenerator(length int) *cidGenerator {
	return &cidGenerator{length: length, ch: make(chan []byte, 1)}
}

func (g *cidGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	id := make([]byte, g.length)
	if _, err := rand.Read(id); err != nil {
		return quic.ConnectionID{}, err
	}
	g.once.Do(func() { g.ch <- append([]byte(nil), id...) })
	return quic.ConnectionIDFromBytes(id), nil
}

func (g *cidGenerator) ConnectionIDLen() int { return g.length }

// firstCID returns the first generated connection ID (blocks briefly).
func (g *cidGenerator) firstCID() []byte {
	select {
	case id := <-g.ch:
		return id
	case <-time.After(500 * time.Millisecond):
		return nil
	}
}

type flowResult struct {
	flowID    int
	delivered int64
	elapsed   float64
}

func runFlow(ctx context.Context, udpAddr *net.UDPAddr, tlsConf *tls.Config,
	cidLen int, flowID int, dataSize int64, duration float64,
	interval float64, results chan<- flowResult) {

	gen := newCIDGenerator(cidLen)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		log.Printf("flow %d: listen udp: %v", flowID, err)
		results <- flowResult{flowID: flowID}
		return
	}
	tr := &quic.Transport{
		Conn:                 udpConn,
		ConnectionIDGenerator: gen,
	}
	defer tr.Close()

	conn, err := tr.Dial(ctx, udpAddr, tlsConf, &quic.Config{
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		MaxStreamReceiveWindow:         128 * 1024 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024 * 1024,
		MaxConnectionReceiveWindow:     128 * 1024 * 1024,
	})
	if err != nil {
		log.Printf("flow %d: dial: %v", flowID, err)
		results <- flowResult{flowID: flowID}
		return
	}
	defer conn.CloseWithError(0, "done")

	// Display local connection ID (= DCID in server→client packets).
	if cid := gen.firstCID(); cid != nil {
		bucket := crc32.ChecksumIEEE(cid) & 0x1FFFF
		fmt.Printf("  Flow %d: connected  CID=%x  bucket=0x%05x\n",
			flowID, cid, bucket)
	} else {
		fmt.Printf("  Flow %d: connected\n", flowID)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Printf("flow %d: open stream: %v", flowID, err)
		results <- flowResult{flowID: flowID}
		return
	}

	start := time.Now()
	var totalSent int64

	// Mutable state shared with interval reporter goroutine.
	var intervalBytes int64
	var intervalMu sync.Mutex
	intervalStart := start

	done := make(chan struct{})
	defer close(done)

	if interval > 0 {
		go func() {
			d := time.Duration(float64(time.Second) * interval)
			ticker := time.NewTicker(d)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case t := <-ticker.C:
					intervalMu.Lock()
					b := intervalBytes
					intervalBytes = 0
					dt := t.Sub(intervalStart).Seconds()
					intervalStart = t
					intervalMu.Unlock()
					mbps := float64(b) * 8 / (dt * 1e6)
					fmt.Printf("  Flow %d [%5.1fs]  %8.2f Mbps\n",
						flowID, t.Sub(start).Seconds(), mbps)
				}
			}
		}()
	}

	// Send loop. stream.Write blocks when the QUIC congestion/flow-control
	// window is full, so totalSent ≈ bytes actually in flight or delivered.
	var deadline time.Time
	if duration > 0 {
		deadline = start.Add(time.Duration(float64(time.Second) * duration))
	}
	for {
		if duration > 0 && time.Now().After(deadline) {
			break
		}
		n := int64(writeChunk)
		if dataSize > 0 {
			if totalSent >= dataSize {
				break
			}
			if rem := dataSize - totalSent; rem < n {
				n = rem
			}
		}
		written, err := stream.Write(zeroChunk[:n])
		if err != nil {
			break
		}
		totalSent += int64(written)
		intervalMu.Lock()
		intervalBytes += int64(written)
		intervalMu.Unlock()
	}
	elapsed := time.Since(start).Seconds()

	// Close write side → server sees EOF and processes the transfer.
	stream.Close()

	// Read server's exact byte count (ground truth).
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var serverTotal int64
	if reply, err := io.ReadAll(stream); err == nil && len(reply) > 0 {
		fmt.Sscanf(string(reply), "%d", &serverTotal)
	}

	delivered := serverTotal
	if delivered == 0 {
		delivered = totalSent // fall back to client count if server didn't respond
	}
	mbps := float64(delivered) * 8 / (elapsed * 1e6)
	fmt.Printf("  Flow %d: %.2f MB delivered in %.3fs  (%.2f Mbps)\n",
		flowID, float64(delivered)/1e6, elapsed, mbps)

	results <- flowResult{flowID: flowID, delivered: delivered, elapsed: elapsed}
}

func main() {
	// Go's flag.Parse stops at the first non-flag argument, so "client host -t 10"
	// leaves -t unparsed. Move bare (positional) args to the end first.
	{
		var flags, pos []string
		args := os.Args[1:]
		for i := 0; i < len(args); i++ {
			if strings.HasPrefix(args[i], "-") {
				flags = append(flags, args[i])
				// Consume the next token as the flag's value if it isn't itself a flag.
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					i++
					flags = append(flags, args[i])
				}
			} else {
				pos = append(pos, args[i])
			}
		}
		os.Args = append([]string{os.Args[0]}, append(flags, pos...)...)
	}

	parallel := flag.Int("P", 1, "parallel flows")
	n        := flag.Int64("n", 10_000_000, "bytes per flow (size-based mode)")
	t        := flag.Float64("t", 0, "duration in seconds (overrides -n)")
	i        := flag.Float64("i", 0, "reporting interval in seconds (0=off)")
	cidLen   := flag.Int("cid-length", 20, "connection ID length in bytes")
	port     := flag.Int("p", 443, "server port")
	flag.Parse()

	if flag.NArg() < 1 {
		log.Fatal("usage: client [flags] <host>")
	}
	host := flag.Arg(0)
	addr := fmt.Sprintf("%s:%d", host, *port)

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("resolve %s: %v", addr, err)
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"perf"},
		ServerName:         host,
	}

	mode := fmt.Sprintf("%.0fs", *t)
	if *t == 0 {
		mode = fmt.Sprintf("%.1f MB", float64(*n)/1e6)
	}
	fmt.Printf("Connecting to %s  —  %d flow(s), %s, CID=%dB\n",
		addr, *parallel, mode, *cidLen)
	if *i > 0 {
		fmt.Printf("Interval reporting every %.1fs\n", *i)
	}
	fmt.Println(strings.Repeat("-", 60))

	dataSize := *n
	if *t > 0 {
		dataSize = 0 // duration mode overrides size
	}

	ctx := context.Background()
	results := make(chan flowResult, *parallel)
	for id := 0; id < *parallel; id++ {
		go runFlow(ctx, udpAddr, tlsConf, *cidLen, id, dataSize, *t, *i, results)
	}

	var totalDelivered int64
	var maxElapsed float64
	for id := 0; id < *parallel; id++ {
		r := <-results
		totalDelivered += r.delivered
		if r.elapsed > maxElapsed {
			maxElapsed = r.elapsed
		}
	}

	fmt.Println(strings.Repeat("-", 60))
	if maxElapsed > 0 {
		agg := float64(totalDelivered) * 8 / (maxElapsed * 1e6)
		fmt.Printf("Total: %d flow(s)  %.2f MB delivered  %.2f Mbps aggregate\n",
			*parallel, float64(totalDelivered)/1e6, agg)
	}
}
