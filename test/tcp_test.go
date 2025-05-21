package main

import (
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Musixal/ZeroTCP"
)

var remotePort = 9092

var remoteAddr = &net.TCPAddr{
	IP:   net.ParseIP("127.0.0.1"),
	Port: remotePort,
}

func init() {
	runListener("lo", remotePort)
	go func() {
		log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
	}()
	time.Sleep(500 * time.Millisecond)
}

func BenchmarkEcho(b *testing.B) {
	conn, err := ZeroTCP.Dial("lo", remoteAddr)
	b.Log("bench")

	if err != nil {
		b.Fatal(err)
	}
	defer (*conn).Close()

	buf := make([]byte, 1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		n, err := (*conn).Write(buf)
		if err != nil {
			b.Fatal(n, err)
		}

		if n, err := (*conn).Read(buf); err != nil {
			b.Fatal(n, err)
		}
	}
}
