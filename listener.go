package ZeroTCP

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Listener listens for incoming TCP connections
type Listener struct {
	handle      *pcap.Handle
	deviceName  string
	port        uint16
	acceptChan  chan *Connection
	closed      chan struct{}
	checksum    bool
	mu          *sync.RWMutex // For FlowIDs
	connections map[FlowID]*Connection
}

// NewListener creates a new TCP listener
func NewListener(deviceName string, port uint16, checksum bool) (*Listener, error) {
	handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap handle: %v", err)
	}

	filter := fmt.Sprintf("tcp dst port %d", port)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("error setting BPF filter: %v", err)
	}

	l := &Listener{
		handle:      handle,
		deviceName:  deviceName,
		port:        port,
		acceptChan:  make(chan *Connection, 10),
		connections: make(map[FlowID]*Connection),
		closed:      make(chan struct{}),
		checksum:    checksum,
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

// listenLoop handles incoming connections
func (l *Listener) listenLoop() {
	packetSource := gopacket.NewPacketSource(l.handle, l.handle.LinkType())

	for {
		select {
		case <-l.closed:
			return
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return
			}

			// Parse IP and TCP layer
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)

			if ipLayer == nil || tcpLayer == nil {
				continue
			}

			ip := ipLayer.(*layers.IPv4)
			tcp := tcpLayer.(*layers.TCP)

			// Create FlowID
			id := *NewFlowID(ip.SrcIP, ip.DstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort)).Reverse()

			// Check the FlowID in the existing connections
			l.mu.RLock()
			conn, exists := l.connections[id]
			l.mu.RUnlock()

			if !exists && tcp.SYN && !tcp.ACK { //  handle SYN packets
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

			if tcp.ACK && tcp.PSH { // Payload signal
				select {
				case conn.in <- tcp.Payload:
					// Update sequence number to acknowledge received data
					conn.ackNum = tcp.Seq + uint32(len(tcp.Payload))
					conn.lastSeen = time.Now()
					fmt.Printf("delivered %d bytes to flowid %s\n", len(tcp.Payload), &id)
				default:
					fmt.Printf("payload channel for conn %s is full, discarding \n", conn.RemoteAddr())
				}
				continue
			}

			if tcp.ACK && tcp.RST { // Connection Terminated
				fmt.Println("RST packet recieved, unregister connection: ", id)
				l.UnregisterConnection(id)
				conn.Close()
				continue
			}

			if tcp.ACK && !tcp.SYN { // Handshake signal
				select {
				case conn.handshake <- packet:
				default:
					fmt.Printf("handshake channel for conn %s is full, discarding \n", conn.RemoteAddr())
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

	if l.checksum {
		tcpResp.SetNetworkLayerForChecksum(&ipv4)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: l.checksum,
	}

	err := gopacket.SerializeLayers(buf, opts, &ipv4, &tcpResp)
	if err != nil {
		fmt.Printf("error serialize layers: %s", err)
		return
	}

	// Register new connection
	newConn := newConnection(id, l.handle, l.checksum)
	l.RegisterConnection(id, newConn)

	if err := SendIPv4RawPacket(id.DstIP[:], buf.Bytes()); err != nil {
		fmt.Printf("error  serialize layers2: %s", err)
		l.UnregisterConnection(id)
		return
	}

	// Step 2: Wait for ACK
	timeout := time.After(5 * time.Second)
	select {
	case <-timeout:
		fmt.Println("timeout waiting for ack")
		return

	case packet := <-newConn.handshake:
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
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-l.closed:
			return
		case <-ticker.C:
			l.mu.Lock()
			defer l.mu.Unlock()

			threshold := time.Now().Add(-1 * time.Minute) // 1-minute cutoff

			for id, conn := range l.connections {
				if conn.lastSeen.Before(threshold) {
					fmt.Printf("Removing connection %s due to inactivity", conn.RemoteAddr())
					delete(l.connections, id) // Remove it from the connections map
					conn.Close()              // Close the connection safely

				}
			}
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
