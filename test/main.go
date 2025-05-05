package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/Musixal/ZeroTCP"
)

func main() {
	mode := flag.String("mode", "", "Mode to run in: 'listen' or 'dial'")
	port := flag.Int("port", 8080, "Port to listen on or connect to")
	ip := flag.String("ip", "127.0.0.1", "IP address to connect to (dial mode only)")
	device := flag.String("device", "lo", "Network device to use (e.g., 'lo', 'eth0')")
	checksum := flag.Bool("checksum", true, "Enable TCP checksum calculation")
	size := flag.Int("size", 1024, "Size of data to transfer in bytes")
	count := flag.Int("count", 1, "Number of transfers to perform (dial mode only)")
	parallel := flag.Int("parallel", 1, "Number of parallel connections (dial mode only)")

	flag.Parse()

	if *mode == "" {
		fmt.Println("Please specify a mode with -mode (listen or dial)")
		flag.Usage()
		os.Exit(1)
	}

	switch *mode {
	case "listen":
		runListener(*device, *port, *checksum)
	case "dial":
		runDialer(*device, *ip, *port, *checksum, *size, *count, *parallel)
	default:
		fmt.Printf("Unknown mode: %s\n", *mode)
		flag.Usage()
		os.Exit(1)
	}
}

func runListener(device string, port int, checksum bool) {
	fmt.Printf("Starting listener on device %s, port %d (checksum: %v)\n", device, port, checksum)

	listener, err := ZeroTCP.NewListener(device, uint16(port), checksum)
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	fmt.Println("Waiting for connections...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	fmt.Printf("New connection from %s\n", remote)

	buf := make([]byte, 64*1024) // 64KB buffer
	totalBytes := 0
	start := time.Now()

	var err error
	var nt int
	for {
		nt, err = conn.Read(buf)
		if err != nil {
			fmt.Printf("Connection from %s closed. Read %d MB in %v\n",
				remote, totalBytes/1024/1024, time.Since(start))
			return
		}
		totalBytes += nt

		_, err = conn.Write(buf[:nt])
		if err != nil {
			log.Printf("Write failed: %v", err)
			return
		}

	}
}

func runDialer(device, ip string, port int, checksum bool, size, count, parallel int) {
	fmt.Printf("Starting dialer to %s:%d (checksum: %v, size: %d, count: %d, parallel: %d)\n",
		ip, port, checksum, size, count, parallel)

	results := make(chan time.Duration, count)
	sem := make(chan struct{}, parallel)

	dialer, err := ZeroTCP.NewDialer(device, ip, port, checksum)
	if err != nil {
		log.Printf("Failed to create dialer: %v", err)
		return
	}
	defer dialer.Close()

	for i := 0; i < count; i++ {
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			dialAndTransfer(dialer, device, ip, port, checksum, size, results)
		}()
	}

	totalSize := size * count

	// Wait for all goroutines to finish
	for i := 0; i < parallel; i++ {
		sem <- struct{}{}
	}

	close(results)

	var total time.Duration
	var min, max time.Duration
	first := true

	for duration := range results {
		total += duration
		if first {
			min, max = duration, duration
			first = false
		} else {
			if duration < min {
				min = duration
			}
			if duration > max {
				max = duration
			}
		}
	}

	avg := total / time.Duration(count)
	fmt.Printf("\nBenchmark results:\n")
	fmt.Printf("  Requests: %d\n", count)
	fmt.Printf("  Parallel: %d\n", parallel)
	fmt.Printf("  Min time: %v\n", min)
	fmt.Printf("  Max time: %v\n", max)
	fmt.Printf("  Avg time: %v\n", avg)
	fmt.Printf("  Requests/sec: %.2f\n", float64(count)/avg.Seconds())
	fmt.Printf("  MB/sec: %.2f\n", float64(totalSize)/1024/1024/avg.Seconds())

}

func dialAndTransfer(dialer *ZeroTCP.Dialer, device, ip string, port int, checksum bool, size int, results chan<- time.Duration) {
	start := time.Now()

	conn, err := dialer.Dial(fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.Printf("Dial failed: %v", err)
		return
	}
	defer conn.Close()

	fmt.Printf("New connection to %s:%d\n", ip, port)

	data := make([]byte, 1420)
	for i := range data {
		data[i] = byte(i % 256)
	}

	go func() {
		totalRead := 0
		buf := make([]byte, size)
		for {
			nr, err := conn.Read(buf)
			if err != nil {
				log.Printf("total read is %d MB", totalRead/1024/1024)
				return
			}
			totalRead += nr
		}
	}()

	written := 0
	for written < size {
		n, err := conn.Write(data)
		if err != nil {
			log.Printf("Write failed: %v", err)
			return
		}

		written += n
	}

	results <- time.Since(start)
	time.Sleep(2 * time.Second)
}
