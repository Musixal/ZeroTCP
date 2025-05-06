package ZeroTCP

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Constants for TCP/IP packet configuration
const (
	DefaultMSS = 1360 // Maximum Segment Size for TCP over Ethernet
)

// Connection represents a TCP connection
type Connection struct {
	id FlowID

	in        chan []byte
	out       chan []byte
	handshake chan gopacket.Packet
	closed    chan struct{}

	socket *pcap.Handle

	srcIP    net.IP
	dstIP    net.IP
	srcPort  layers.TCPPort
	dstPort  layers.TCPPort
	ipHeader *layers.IPv4

	seqNum uint32
	ackNum uint32

	mu       sync.Mutex   // for write
	readBuf  bytes.Buffer // internal buffer like TCP
	bufMutex sync.Mutex   // guards readBuf

	lastSeen time.Time
	checksum bool

	readDeadline  time.Time
	deadlineMutex sync.Mutex
}

// Errors
var (
	ErrClosed  = errors.New("connection closed")
	ErrTimeout = fmt.Errorf("i/o timeout")
	ErrNoData  = fmt.Errorf("no data to write")
)

var packetPool = &sync.Pool{
	New: func() interface{} {
		return gopacket.NewSerializeBuffer()
	},
}

func newConnection(id FlowID, socket *pcap.Handle, checksum bool) *Connection {
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    id.SrcIP[:],
		DstIP:    id.DstIP[:],
		Length:   20, // Will be adjusted by SerializeLayers
	}
	return &Connection{
		id:        id,
		in:        make(chan []byte, 10_000),
		out:       make(chan []byte, 10_000),
		handshake: make(chan gopacket.Packet, 1), // prevent blocking

		closed:   make(chan struct{}),
		socket:   socket,
		srcIP:    net.IP(id.SrcIP[:]),
		dstIP:    net.IP(id.DstIP[:]),
		srcPort:  layers.TCPPort(id.SrcPort),
		dstPort:  layers.TCPPort(id.DstPort),
		seqNum:   0, // should be set after handshake
		ackNum:   0, // should be set after handshake
		lastSeen: time.Now(),
		checksum: checksum,
		ipHeader: ip,
	}
}

func (c *Connection) Read(b []byte) (int, error) {
	// Fast-path: check deadline
	c.deadlineMutex.Lock()
	deadline := c.readDeadline
	hasDeadline := !deadline.IsZero()
	c.deadlineMutex.Unlock()

	if hasDeadline && time.Now().After(deadline) {
		c.Close()
		return 0, ErrTimeout
	}

	var timer *time.Timer
	var timeout <-chan time.Time
	if hasDeadline {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			c.Close()
			return 0, ErrTimeout
		}
		timer = time.NewTimer(remaining)
		timeout = timer.C
		defer timer.Stop()
	}

	// Loop until we can satisfy the read
	for {
		c.bufMutex.Lock()
		if c.readBuf.Len() > 0 {
			n, _ := c.readBuf.Read(b)
			c.bufMutex.Unlock()
			return n, nil
		}
		c.bufMutex.Unlock()

		select {
		case <-c.closed:
			return 0, ErrClosed

		case data, ok := <-c.in:
			if !ok {
				return 0, ErrClosed
			}
			// Buffer the data
			c.bufMutex.Lock()
			c.readBuf.Write(data)
			n, _ := c.readBuf.Read(b)
			c.bufMutex.Unlock()
			return n, nil

		case <-timeout:
			c.Close()
			return 0, ErrTimeout
		}
	}
}

func (c *Connection) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, ErrClosed
	default:
		c.mu.Lock()
		defer c.mu.Unlock()

		if len(b) == 0 {
			return 0, ErrNoData // No data to write
		}

		for offset := 0; offset < len(b); offset += DefaultMSS {
			end := offset + 1460
			if end > len(b) {
				end = len(b)
			}
			payload := b[offset:end]

			tcp := &layers.TCP{
				SrcPort:    layers.TCPPort(c.id.SrcPort),
				DstPort:    layers.TCPPort(c.id.DstPort),
				Seq:        c.seqNum,
				Ack:        c.ackNum,
				PSH:        true,
				ACK:        true,
				Window:     64240,
				DataOffset: 5,
			}

			if c.checksum {
				tcp.SetNetworkLayerForChecksum(c.ipHeader)
			}

			// Modify TCP options to match standard format
			tcp.Options = *tcpOptions()

			// Serialize packet
			buf := packetPool.Get().(gopacket.SerializeBuffer)
			defer packetPool.Put(buf)

			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: c.checksum,
			}

			err := gopacket.SerializeLayers(buf, opts,
				c.ipHeader,
				tcp,
				gopacket.Payload(payload),
			)
			if err != nil {
				return offset, fmt.Errorf("serialization error: %w", err)
			}

			if err := SendIPv4RawPacket(c.id.DstIP[:], buf.Bytes()); err != nil {
				return offset, fmt.Errorf("send error: %w", err)
			}
			//fmt.Println("write to addr: ", c.writeAddr)
			// Update sequence number
			c.seqNum += uint32(len(payload))
		}

		return len(b), nil
	}
}

// LocalAddr returns the local network address
func (c *Connection) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.id.SrcIP[:],
		Port: int(c.id.SrcPort),
	}
}

// RemoteAddr returns the remote network address
func (c *Connection) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.id.DstIP[:],
		Port: int(c.id.DstPort),
	}
}

// SetDeadline sets read and write deadlines
func (c *Connection) SetDeadline(t time.Time) error {
	c.deadlineMutex.Lock()
	defer c.deadlineMutex.Unlock()
	c.readDeadline = t
	return nil
}

// SetReadDeadline sets the read deadline
func (c *Connection) SetReadDeadline(t time.Time) error {
	// Not implemented
	return nil
}

// SetWriteDeadline sets the write deadline
func (c *Connection) SetWriteDeadline(t time.Time) error {
	// Not implemented
	return nil
}

func (c *Connection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.closed:
		return ErrClosed // Connection already closed
	default:
		close(c.closed)

		// Craft and send RST packet
		tcp := &layers.TCP{
			SrcPort:    c.srcPort,
			DstPort:    c.dstPort,
			Seq:        c.seqNum,
			Ack:        c.ackNum,
			RST:        true,  // Set RST flag
			ACK:        true,  // Set ACK flag
			Window:     64240, // Arbitrary window size
			DataOffset: 5,     // TCP header length (5 words = 20 bytes)
		}

		// Modify TCP options to match standard format
		tcp.Options = *tcpOptions()

		if c.checksum {
			tcp.SetNetworkLayerForChecksum(c.ipHeader)
		}

		// Serialize RST packet
		buf := packetPool.Get().(gopacket.SerializeBuffer)
		defer packetPool.Put(buf)

		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: c.checksum,
		}

		err := gopacket.SerializeLayers(buf, opts,
			c.ipHeader,
			tcp,
			gopacket.Payload(nil), // No payload, just the FIN packet
		)
		if err != nil {
			return fmt.Errorf("failed to serialize RST packet: %w", err)
		}

		// Send the RST packet
		if err := SendIPv4RawPacket(c.dstIP, buf.Bytes()); err != nil {
			return fmt.Errorf("failed to send RST packet: %w", err)
		}

		// Close all channels and mark as closed
		close(c.in)
		close(c.out)
		close(c.handshake)

		return nil
	}
}

func (c *Connection) IsClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}
