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

type Dialer struct {
	handle      *pcap.Handle
	deviceName  string
	connections map[FlowID]*Connection
	mu          *sync.RWMutex
	closed      chan struct{}
	checksum    bool
	port        int
}

func NewDialer(deviceName string, remoteIP string, port int, checksum bool) (*Dialer, error) {
	// Open pcap handle
	handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap handle: %v", err)
	}

	// Set BPF filter to only capture packets from remoteIP
	filter := fmt.Sprintf("ip and src host %s", remoteIP)

	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("error setting BPF filter: %v", err)
	}

	d := &Dialer{
		handle:      handle,
		deviceName:  deviceName,
		connections: make(map[FlowID]*Connection),
		mu:          &sync.RWMutex{},
		closed:      make(chan struct{}),
		checksum:    checksum,
		port:        port,
	}

	//Block incoming traffic with a source port of x
	args := []string{"-A", "INPUT", "-p", "tcp", "--sport", fmt.Sprintf("%d", port), "-j", "DROP"}

	err = runIptablesWithSudo(args)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("error setting iptables rule: %v", err)
	} else {
		fmt.Println("Rule applied successfully!")
	}

	// Start handler in a goroutine
	go d.handlerLoop()
	go d.CleanStaleConnections()

	return d, nil
}

func (d *Dialer) handlerLoop() {
	packetSource := gopacket.NewPacketSource(d.handle, d.handle.LinkType())

	for {
		select {
		case <-d.closed:
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

			// Create FlowID and Reverse it
			id := *NewFlowID(ip.SrcIP, ip.DstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort)).Reverse()

			// Check the FlowID in the existing connections
			d.mu.RLock()
			conn, exists := d.connections[id]
			d.mu.RUnlock()

			if !exists {
				continue
			}

			if conn.IsClosed() {
				d.UnregisterConnection(id)
				continue
			}

			if tcp.SYN && tcp.ACK { // Handshake signal
				select {
				case conn.handshake <- packet:

				default:
					fmt.Println("handshake channel is full already")
				}
				continue
			}

			if tcp.ACK && tcp.PSH { // Payload signal
				select {
				case conn.in <- tcp.Payload:
					conn.lastSeen = time.Now()

				default:
					fmt.Println("payload channel is full already")
				}
				continue
			}

			if tcp.ACK && tcp.RST { // Connection Terminated
				fmt.Println("RST packet recieved, unregister connection: ", id)
				d.UnregisterConnection(id)
				conn.Close()
				continue
			}
		}
	}
}

// Dial establishes a TCP connection
func (d *Dialer) Dial(remoteAddr string) (net.Conn, error) {
	// Parse remote address
	addr, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %v", err)
	}

	remoteIP := addr.IP.To4()
	if remoteIP == nil {
		return nil, fmt.Errorf("non-IPv4 address not supported: %v", addr.IP)
	}

	remotePort := uint16(addr.Port)

	// Get local IP address for the interface
	localIP, err := getOutboundIP(remoteIP)
	if err != nil {
		return nil, fmt.Errorf("failed to determine local address: %v", err)
	}

	// Use a random high port for source
	localPort := uint16(30000 + (time.Now().UnixNano() % 35000))

	// Generate random initial sequence number
	seqNum := uint32(time.Now().UnixNano() & 0xFFFFFFFF)

	// TCP Handshake
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    localIP,
		DstIP:    remoteIP,
		IHL:      5,
		Length:   20, // Will be adjusted by SerializeLayers
	}

	// Set manually in the TCP layer, ack?
	tcp := layers.TCP{
		SrcPort:    layers.TCPPort(localPort),
		DstPort:    layers.TCPPort(remotePort),
		Seq:        seqNum,
		SYN:        true,
		Window:     64240,
		DataOffset: 5,
	}

	// Modify TCP options to match standard format
	tcp.Options = *tcpOptions()

	// Serialize packet
	buf := packetPool.Get().(gopacket.SerializeBuffer)
	defer packetPool.Put(buf)

	// Set network layer for checksum calculation if needed
	if d.checksum {
		tcp.SetNetworkLayerForChecksum(&ip)
	}

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: d.checksum,
	}

	// err = gopacket.SerializeLayers(buf, opts, &ip, &tcp)
	err = gopacket.SerializeLayers(buf, opts, &ip, &tcp)
	if err != nil {
		return nil, fmt.Errorf("error serializing SYN packet: %v", err)
	}

	// Send the SYN packet
	if err := SendIPv4RawPacket(remoteIP, buf.Bytes()); err != nil {
		return nil, fmt.Errorf("error sending SYN: %v", err)
	}

	// Create the flow ID
	id := NewFlowID(localIP, remoteIP, localPort, remotePort)

	// Creating and registering new connection
	conn := newConnection(*id, d.handle, d.checksum)
	d.RegisterConnection(*id, conn)

	// Step 2: Wait for SYN-ACK
	var receivedSeq uint32
	var receivedAck uint32

	timeout := time.After(5 * time.Second)

	select {
	case <-timeout:
		d.UnregisterConnection(*id)
		return nil, fmt.Errorf("timeout waiting for SYN-ACK")
	case packet := <-conn.handshake:
		// Parse TCP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if tcpLayer == nil {
			d.UnregisterConnection(*id)
			return nil, fmt.Errorf("tcp layer is nil")
		}
		tcpPacket, _ := tcpLayer.(*layers.TCP)

		receivedSeq = uint32(tcpPacket.Seq)
		receivedAck = uint32(tcpPacket.Ack)
	}

	// Step 3: Send ACK
	tcp = layers.TCP{
		SrcPort:    layers.TCPPort(localPort),
		DstPort:    layers.TCPPort(remotePort),
		Seq:        receivedAck,
		Ack:        receivedSeq + 1,
		SYN:        false,
		ACK:        true,
		Window:     64240,
		DataOffset: 5,
	}

	// Modify TCP options to match standard format
	tcp.Options = *tcpOptions()

	conn.seqNum = receivedAck     // Update sequence number
	conn.ackNum = receivedSeq + 1 // Update acknowledgment number

	if d.checksum {
		tcp.SetNetworkLayerForChecksum(&ip)
	}

	buf = gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, opts, &ip, &tcp)
	if err != nil {
		d.UnregisterConnection(*id)
		return nil, fmt.Errorf("error serializing ACK packet: %v", err)
	}

	// Send the ACK packet
	if err := SendIPv4RawPacket(conn.dstIP, buf.Bytes()); err != nil {
		d.UnregisterConnection(*id)
		return nil, fmt.Errorf("error sending ACK: %v", err)
	}

	return conn, nil
}

func (d *Dialer) RegisterConnection(id FlowID, conn *Connection) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connections[id] = conn
}

func (d *Dialer) UnregisterConnection(id FlowID) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.connections, id)
}

// CleanStaleConnections removes connections with `lastSeen` older than 1 minute
func (d *Dialer) CleanStaleConnections() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.closed:
			return
		case <-ticker.C:
			d.mu.Lock()
			defer d.mu.Unlock()

			threshold := time.Now().Add(-1 * time.Minute) // 1-minute cutoff

			for id, conn := range d.connections {
				if conn.lastSeen.Before(threshold) {
					fmt.Printf("Removing connection %s due to inactivity", conn.RemoteAddr())
					delete(d.connections, id) // Remove it from the connections map
					conn.Close()              // Close the connection safely
				}
			}
		}
	}
}

// Close closes the pcap handle
func (d *Dialer) Close() error {
	// Remove iptable Rule
	args := []string{"-D", "INPUT", "-p", "tcp", "--sport", fmt.Sprintf("%d", d.port), "-j", "DROP"}

	err := runIptablesWithSudo(args)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Rule deleted successfully!")
	}

	close(d.closed)

	// close all connections
	for _, conn := range d.connections {
		conn.Close()
	}

	d.handle.Close()
	fmt.Println("pcap closed")
	return nil
}
