package ZeroTCP

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

// Listener listens for incoming TCP connections
type Listener struct {
	handle      *afpacket.TPacket
	deviceName  string
	port        uint16
	acceptChan  chan *Connection
	closed      chan struct{}
	mu          *sync.RWMutex // For FlowIDs
	connections map[FlowID]*Connection
}

// NewListener creates a new TCP listener
func Listen(deviceName string, port uint16) (*Listener, error) {
	// Open AF_PACKET socket with ring buffer
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(deviceName),
		afpacket.OptFrameSize(65536),
		afpacket.OptBlockSize(1<<20), // 1MB block
		afpacket.OptNumBlocks(64),
		afpacket.OptPollTimeout(time.Millisecond*100),
		afpacket.OptAddVLANHeader(false),
	)
	if err != nil {
		return nil, fmt.Errorf("error opening afpacket handle: %v", err)
	}

	filter := []bpf.Instruction{
		//  0) load Ethernet[23] → the IP Protocol
		bpf.LoadAbsolute{Off: 23, Size: 1},

		//  1) if proto == 6 (TCP) → fall through; else → jump to instr 5 (drop)
		bpf.JumpIf{
			Cond:      bpf.JumpEqual,
			Val:       6,
			SkipTrue:  0,
			SkipFalse: 3, // 1+3 = 4, then next is 5
		},

		//  2) load TCP dest-port @ Ethernet(14)+IP(20)+Offset(2) = 36
		bpf.LoadAbsolute{Off: 36, Size: 2},

		//  3) if port == P → fall through; else → jump to instr 5 (drop)
		bpf.JumpIf{
			Cond:      bpf.JumpEqual,
			Val:       uint32(port),
			SkipTrue:  0,
			SkipFalse: 1, // 3+1 = 4, then next is 5
		},

		//  4) accept
		bpf.RetConstant{Val: 0xFFFFFFFF},

		//  5) drop
		bpf.RetConstant{Val: 0},
	}

	// Compile the filter into raw format
	rawInsns, err := bpf.Assemble(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to assemble BPF: %v", err)
	}

	err = handle.SetBPF(rawInsns)
	if err != nil {
		return nil, fmt.Errorf("failed to apply BPF: %v", err)
	}

	l := &Listener{
		handle:      handle,
		deviceName:  deviceName,
		port:        port,
		acceptChan:  make(chan *Connection, 10), // Buffer up to 10 conn for accepting
		connections: make(map[FlowID]*Connection),
		closed:      make(chan struct{}),
		mu:          &sync.RWMutex{},
	}

	//Block incoming traffic with a source port of x
	args := []string{"-A", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", "DROP"}

	err = runIptablesWithSudo(args)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("error setting iptables rule: %v", err)
	} else {
		fmt.Println("Rule applied successfully!")
	}
	go l.listenLoop()
	go l.CleanStaleConnections()

	return l, nil
}

func (l *Listener) listenLoop() {
	packetSource := gopacket.NewPacketSource(l.handle, layers.LayerTypeEthernet)

	for {
		select {
		case <-l.closed:
			return

		case packet, ok := <-packetSource.Packets():
			if !ok {
				return
			}

			if packet == nil {
				continue
			}

			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)

			if ipLayer == nil || tcpLayer == nil {
				continue
			}

			ip := ipLayer.(*layers.IPv4)
			tcp := tcpLayer.(*layers.TCP)

			id := *NewFlowID(ip.SrcIP, ip.DstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort)).Reverse()

			l.mu.RLock()
			conn, exists := l.connections[id]
			l.mu.RUnlock()

			if !exists && tcp.SYN && !tcp.ACK {
				go l.handshake(id, tcp)
				continue
			}

			if !exists {
				continue
			}

			if conn.IsClosed() {
				l.UnregisterConnection(id)
				continue
			}

			if tcp.ACK && tcp.PSH {
				select {
				case conn.in <- tcp.Payload:
					conn.ackNum = tcp.Seq + uint32(len(tcp.Payload))
					conn.lastSeen = time.Now()

				default:
					fmt.Printf("conn.in full for %s\n", conn.RemoteAddr())
				}
				continue
			}

			if tcp.ACK && tcp.RST {
				fmt.Println("RST packet received, unregistering")
				go l.UnregisterConnection(id)
				conn.Close()
				continue
			}

			if tcp.ACK && !tcp.SYN && !tcp.PSH {
				select {
				case conn.handshake <- packet:
				default:
					fmt.Printf("handshake channel full for %s\n", conn.RemoteAddr())
				}
				continue
			}
		}
	}

}

func (l *Listener) handshake(id FlowID, tcp *layers.TCP) {
	// Generate random initial sequence number
	seqNum := uint32(time.Now().UnixNano() & 0xFFFFFFFF)

	// Step 1: Send SYN-ACK
	ipv4 := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    id.SrcIP[:],
		DstIP:    id.DstIP[:],
		IHL:      5,
		Length:   20,
	}

	tcpResp := layers.TCP{
		SrcPort: layers.TCPPort(id.SrcPort),
		DstPort: layers.TCPPort(id.DstPort),
		Seq:     seqNum,
		Ack:     tcp.Seq + 1,
		SYN:     true,
		ACK:     true,

		DataOffset: 5,
	}

	// Modify TCP options to match standard format
	tcp.Options = *tcpOptions()

	tcpResp.SetNetworkLayerForChecksum(&ipv4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, &ipv4, &tcpResp)
	if err != nil {
		fmt.Printf("error serialize layers: %s", err)
		return
	}

	// Register new connection
	newConn := newConnection(id, l.handle)
	l.RegisterConnection(id, newConn)

	if err := SendIPv4RawPacket(id.DstIP[:], buf.Bytes()); err != nil {
		fmt.Printf("error serialize layers2: %s", err)
		l.UnregisterConnection(id)
		return
	}

	// Step 2: Wait for ACK
	timeout := time.After(3 * time.Second)
	select {
	case <-timeout:
		fmt.Println("timeout waiting for ack")
		l.UnregisterConnection(id)
		return

	case packet := <-newConn.handshake:
		if packet == nil {
			l.UnregisterConnection(id)
			return
		}
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			l.UnregisterConnection(id)
			return
		}

		select {
		case <-l.closed:
			newConn.Close()
			return
		case l.acceptChan <- newConn:
		default:
			fmt.Println("listener accept channel is full, discarding connection...")
		}
	}

	//conn.seqNum = seqNum + 1
	// conn.ackNum = tcp.Seq +

}

// Accept waits for and returns the next connection to the listener
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.acceptChan:
		return conn, nil
	case <-l.closed:
		return nil, ErrClosed
	}
}

// Addr returns the listener's network address
func (l *Listener) Addr() net.Addr {
	ip, err := getDeviceIP(l.deviceName)
	if err != nil {
		ip = net.IPv4(0, 0, 0, 0)
	}
	return &net.TCPAddr{
		IP:   ip,
		Port: int(l.port),
	}
}

func (l *Listener) RegisterConnection(id FlowID, conn *Connection) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.connections[id] = conn
}

func (l *Listener) UnregisterConnection(id FlowID) {
	fmt.Println("unregister connection with flowid", id.String())
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.connections, id)
}

// CleanStaleConnections removes connections with `lastSeen` older than 1 minute
func (l *Listener) CleanStaleConnections() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-l.closed:
			return
		case <-ticker.C:

			threshold := time.Now().Add(-1 * time.Minute) // 1-minute cutoff

			l.mu.Lock()
			for id, conn := range l.connections {
				if conn.lastSeen.Before(threshold) {
					//	fmt.Printf("Removing connection %s due to inactivity", conn.RemoteAddr())
					delete(l.connections, id) // Remove it from the connections map
					conn.Close()              // Close the connection safely

				}
			}
			l.mu.Unlock()
		}
	}
}

// Close closes the listener
func (l *Listener) Close() error {
	// Remove the iptables rule
	args := []string{"-D", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", l.port), "-j", "DROP"}

	err := runIptablesWithSudo(args)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Rule deleted successfully!")
	}

	close(l.closed)

	// close all connections
	for _, conn := range l.connections {
		conn.Close()
	}

	l.handle.Close()
	return nil
}
