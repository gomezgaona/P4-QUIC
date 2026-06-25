package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const readBuf = 256 * 1024 // 256 KB per-stream read buffer

// zeroBuf is the source of download payload bytes (server→client). It is never
// written to, so sharing one read-only buffer across all download streams is safe.
var zeroBuf = make([]byte, readBuf)

// readLine reads bytes from stream up to and including the first '\n' and
// returns the line without the trailing newline. Used to read the per-stream
// request header the client sends first.
func readLine(stream quic.Stream) (string, error) {
	var b []byte
	one := make([]byte, 1)
	for {
		n, err := stream.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return string(b), nil
			}
			b = append(b, one[0])
		}
		if err != nil {
			return string(b), err
		}
	}
}

// serveDownload writes payload bytes server→client. With nbytes > 0 it sends
// exactly that many bytes; otherwise with durMs > 0 it sends until the deadline.
// The heavy traffic flows on the client-issued CID, which is the CID -single-cid
// pins and the client prints, making the byte experiment self-verifying.
func serveDownload(stream quic.Stream, nbytes, durMs int64) {
	var sent int64
	var deadline time.Time
	if nbytes <= 0 && durMs > 0 {
		deadline = time.Now().Add(time.Duration(durMs) * time.Millisecond)
	}
	for {
		if nbytes > 0 && sent >= nbytes {
			break
		}
		if nbytes <= 0 && durMs > 0 && time.Now().After(deadline) {
			break
		}
		n := int64(len(zeroBuf))
		if nbytes > 0 {
			if rem := nbytes - sent; rem < n {
				n = rem
			}
		}
		w, err := stream.Write(zeroBuf[:n])
		if err != nil {
			break
		}
		sent += int64(w)
	}
	atomic.AddInt64(&bytesTotal, sent)
	atomic.AddInt64(&streamsDone, 1)
}

// Aggregate counters -- printed once per second instead of a line per
// connection/stream, so tens of thousands of flows don't serialize on stdout.
var (
	connsOpen   int64
	connsTotal  int64
	streamsDone int64
	bytesTotal  int64
	verbose     bool
)

func handleStream(conn quic.Connection, stream quic.Stream) {
	defer stream.Close()

	// Every stream starts with a request header line: "<MODE> <nbytes> <durMs>".
	// MODE "DOWN" means the server pushes payload to the client (server→client
	// bulk); anything else (default "UP") means the client uploads to the server.
	hdr, err := readLine(stream)
	if err != nil && hdr == "" {
		return
	}
	var mode string
	var nbytes, durMs int64
	fmt.Sscanf(hdr, "%s %d %d", &mode, &nbytes, &durMs)
	if mode == "DOWN" {
		serveDownload(stream, nbytes, durMs)
		return
	}

	start := time.Now()
	var total int64
	buf := make([]byte, readBuf)

	for {
		n, err := stream.Read(buf)
		total += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}
	}

	atomic.AddInt64(&bytesTotal, total)
	atomic.AddInt64(&streamsDone, 1)
	if verbose {
		elapsed := time.Since(start).Seconds()
		mbps := float64(total) * 8 / (elapsed * 1e6)
		fmt.Printf("[%s] %v: %.2f MB in %.3fs  (%.2f Mbps)\n",
			time.Now().Format("15:04:05"), conn.RemoteAddr(),
			float64(total)/1e6, elapsed, mbps)
	}

	// Echo total bytes received so the client can verify delivery (protocol).
	fmt.Fprintf(stream, "%d", total)
}

func handleConn(conn quic.Connection) {
	defer conn.CloseWithError(0, "")
	atomic.AddInt64(&connsOpen, 1)
	atomic.AddInt64(&connsTotal, 1)
	defer atomic.AddInt64(&connsOpen, -1)
	if verbose {
		fmt.Printf("[%s] connected  %v\n",
			time.Now().Format("15:04:05"), conn.RemoteAddr())
	}
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handleStream(conn, stream)
	}
}

func main() {
	port := flag.Int("p", 443, "listen port")
	certF := flag.String("cert", "quic_cert.pem", "TLS certificate")
	keyF := flag.String("key", "quic_key.pem", "TLS key")
	cidLen := flag.Int("cid-length", 20, "connection ID length in bytes")
	sockBuf := flag.Int("sockbuf", 16*1024*1024, "UDP read/write buffer in bytes (needs net.core.rmem_max >= this)")
	initWin := flag.Int("init-window", 256*1024, "initial stream/connection receive window in bytes")
	maxWin := flag.Int("max-window", 4*1024*1024, "max stream/connection receive window in bytes (x #flows = peak memory)")
	idle := flag.Duration("idle", 60*time.Second, "max idle timeout")
	hsIdle := flag.Duration("handshake-idle", 30*time.Second, "handshake idle timeout")
	flag.BoolVar(&verbose, "v", false, "log every connection/stream (off = 1 aggregate line/sec)")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*certF, *keyF)
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"perf"},
	}
	quicConf := &quic.Config{
		InitialStreamReceiveWindow:     uint64(*initWin),
		MaxStreamReceiveWindow:         uint64(*maxWin),
		InitialConnectionReceiveWindow: uint64(*initWin),
		MaxConnectionReceiveWindow:     uint64(*maxWin),
		MaxIdleTimeout:                 *idle,
		HandshakeIdleTimeout:           *hsIdle,
	}

	udpConn, err := net.ListenPacket("udp", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}
	// Enlarge the kernel socket buffers so bursts don't overflow -> drop -> stall.
	if uc, ok := udpConn.(*net.UDPConn); ok {
		if err := uc.SetReadBuffer(*sockBuf); err != nil {
			log.Printf("SetReadBuffer(%d): %v (raise net.core.rmem_max)", *sockBuf, err)
		}
		uc.SetWriteBuffer(*sockBuf)
	}
	tr := &quic.Transport{Conn: udpConn, ConnectionIDLength: *cidLen}
	ln, err := tr.Listen(tlsConf, quicConf)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	fmt.Printf("QUIC perf server  port=%d  CID=%dB  win=%d..%d  sockbuf=%dKB\n",
		*port, *cidLen, *initWin, *maxWin, *sockBuf/1024)

	// Aggregate progress: one line/sec unless -v.
	if !verbose {
		go func() {
			for range time.Tick(time.Second) {
				fmt.Printf("[%s] conns: %d open / %d total | streams done: %d | recv: %.1f MB\n",
					time.Now().Format("15:04:05"),
					atomic.LoadInt64(&connsOpen), atomic.LoadInt64(&connsTotal),
					atomic.LoadInt64(&streamsDone), float64(atomic.LoadInt64(&bytesTotal))/1e6)
			}
		}()
	}

	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn)
	}
}
