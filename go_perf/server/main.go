package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

const readBuf = 256 * 1024 // 256 KB read buffer

func handleStream(conn quic.Connection, stream quic.Stream) {
	defer stream.Close()

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

	elapsed := time.Since(start).Seconds()
	mbps := float64(total) * 8 / (elapsed * 1e6)
	fmt.Printf("[%s] %v: %.2f MB in %.3fs  (%.2f Mbps)\n",
		time.Now().Format("15:04:05"), conn.RemoteAddr(),
		float64(total)/1e6, elapsed, mbps)

	// Echo total bytes received so the client can verify delivery.
	fmt.Fprintf(stream, "%d", total)
}

func handleConn(conn quic.Connection) {
	defer conn.CloseWithError(0, "")
	fmt.Printf("[%s] connected  %v\n",
		time.Now().Format("15:04:05"), conn.RemoteAddr())
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handleStream(conn, stream)
	}
}

func main() {
	port   := flag.Int("p", 443, "listen port")
	certF  := flag.String("cert", "quic_cert.pem", "TLS certificate")
	keyF   := flag.String("key", "quic_key.pem", "TLS key")
	cidLen := flag.Int("cid-length", 20, "connection ID length in bytes")
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
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		MaxStreamReceiveWindow:         128 * 1024 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024 * 1024,
		MaxConnectionReceiveWindow:     128 * 1024 * 1024,
	}

	udpConn, err := net.ListenPacket("udp", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}
	tr := &quic.Transport{
		Conn:               udpConn,
		ConnectionIDLength: *cidLen,
	}
	ln, err := tr.Listen(tlsConf, quicConf)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	fmt.Printf("QUIC perf server  port=%d  CID=%dB\n", *port, *cidLen)

	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn)
	}
}
