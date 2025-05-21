package ZeroTCP

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

type Dialer struct {
	addr       *net.TCPAddr
	handle     *afpacket.TPacket
	deviceName string
	conn       *Connection
	closed     chan struct{}
}

func Dial(deviceName string, addr *net.TCPAddr) (*net.Conn, error) {
	// Open AF_PACKET socket with ring buffer
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(deviceName),
		afpacket.OptFrameSize(65536),
		afpacket.OptBlockSize(1<<20), // 1MB block
		afpacket.OptNumBlocks(64),
		afpacket.OptPollTimeout(time.Millisecond*100),
	)
	if err != nil {
		return nil, fmt.Errorf("error opening afpacket handle: %v", err)
	}

	// filter := fmt.Sprintf("tcp and src host %s and src port %d", addr.IP.String(), addr.Port)
	// Convert 4‐byte IPv4 into a big‐endian uint32:
	ip4 := addr.IP.To4()
	if ip4 == nil {
		log.Fatal("not an IPv4 address")
	}
	ipVal := binary.BigEndian.Uint32(ip4)
	portVal := uint32(addr.Port)

	filter := []bpf.Instruction{
		// 0) Check Ethernet type == 0x0800 (IPv4)
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{
			Cond:      bpf.JumpEqual,
			Val:       0x0800,
			SkipTrue:  0,
			SkipFalse: 7, // if not IPv4 → skip to drop
		},

		// 1) Check IP protocol == TCP (6)
		//    IP proto is at byte offset 14+9 = 23
		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{
			Cond:      bpf.JumpEqual,
			Val:       6,
			SkipTrue:  0,
			SkipFalse: 5, // if not TCP → skip to drop
		},

		// 2) Check IP source address == ipVal
		//    Src IP starts at 14+12 = 26, length=4
		bpf.LoadAbsolute{Off: 26, Size: 4},
		bpf.JumpIf{
			Cond:      bpf.JumpEqual,
			Val:       ipVal,
			SkipTrue:  0,
			SkipFalse: 3, // if src IP mismatch → skip to drop
		},

		// 3) Check TCP source port == portVal
		//    With a 20‐byte IP header, TCP header starts at offset 14+20 = 34
		//    Src port is the first 2 bytes
		bpf.LoadAbsolute{Off: 34, Size: 2},
		bpf.JumpIf{
			Cond:      bpf.JumpEqual,
			Val:       portVal,
			SkipTrue:  0,
			SkipFalse: 1, // if port mismatch → skip to drop
		},

		// 4) All tests passed → accept
		bpf.RetConstant{Val: 0xFFFFFFFF},

		// 5) One of the tests failed → drop
		bpf.RetConstant{Val: 0},
	}

	// To apply:
	insns, err := bpf.Assemble(filter)
	if err != nil {
		log.Fatal("BPF assembly failed:", err)
	}
	if err := handle.SetBPF(insns); err != nil {
		log.Fatal("apply BPF failed:", err)
	}

	d := &Dialer{
		addr:       addr,
		handle:     handle,
		deviceName: deviceName,
		closed:     make(chan struct{}),
	}

	//Block incoming traffic with a source port of x
	args := []string{
		"-A", "INPUT",
		"-p", "tcp",
		"--src", addr.IP.String(),
		"--sport", fmt.Sprintf("%d", addr.Port),
		"-j", "DROP",
	}

	err = runIptablesWithSudo(args)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("error setting iptables rule: %v", err)
	} else {
		fmt.Println("Rule applied successfully!")
	}

	conn, err := d.dial(addr)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("error dial: %v", err)
	}
	return &conn, err
}

func (d *Dialer) handlerLoop() {
	packetSource := gopacket.NewPacketSource(d.handle, layers.LinkTypeEthernet)

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
			tcp := tcpLayer.(*layers.TCP)

			if d.conn.IsClosed() {
				return
			}

			if tcp.SYN && tcp.ACK { // Handshake signal
				select {
				case d.conn.handshake <- packet:

				default:
					fmt.Println("handshake channel is full already")
				}
				continue
			}

			if tcp.ACK && tcp.PSH { // Payload signal
				select {
				case d.conn.in <- tcp.Payload:
					d.conn.lastSeen = time.Now()

				default:
					fmt.Println("payload channel is full already")
				}
				continue
			}

			if tcp.ACK && tcp.RST { // Connection Terminated
				fmt.Println("RST packet recieved, unregister connection: ", d.conn.id)
				d.conn.Close()
				return
			}
		}
	}
}

// Dial establishes a TCP connection
func (d *Dialer) dial(remoteAddr *net.TCPAddr) (net.Conn, error) {
	remotePort := remoteAddr.AddrPort().Port()

	// Get local IP address for the interface
	localIP, err := getOutboundIP(remoteAddr.IP)
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
		DstIP:    remoteAddr.IP,
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
	tcp.SetNetworkLayerForChecksum(&ip)

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// err = gopacket.SerializeLayers(buf, opts, &ip, &tcp)
	err = gopacket.SerializeLayers(buf, opts, &ip, &tcp)
	if err != nil {
		return nil, fmt.Errorf("error serializing SYN packet: %v", err)
	}

	// Send the SYN packet
	if err := SendIPv4RawPacket(remoteAddr.IP, buf.Bytes()); err != nil {
		return nil, fmt.Errorf("error sending SYN: %v", err)
	}

	// Create the flow ID
	id := NewFlowID(localIP, remoteAddr.IP, localPort, remotePort)

	// Creating and registering new connection
	conn := newConnection(*id, d.handle)
	d.conn = conn

	// Step 2: Wait for SYN-ACK
	var receivedSeq uint32
	var receivedAck uint32

	timeout := time.After(5 * time.Second)

	// Start handler in a goroutine
	go d.handlerLoop()
	go d.CleanStaleConnections()

	select {
	case <-timeout:
		//d.UnregisterConnection(*id)
		return nil, fmt.Errorf("timeout waiting for SYN-ACK")
	case packet := <-d.conn.handshake:
		// Parse TCP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if tcpLayer == nil {
			//d.UnregisterConnection(*id)
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

	tcp.SetNetworkLayerForChecksum(&ip)

	buf = gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, opts, &ip, &tcp)
	if err != nil {
		//	d.UnregisterConnection(*id)
		return nil, fmt.Errorf("error serializing ACK packet: %v", err)
	}

	// Send the ACK packet
	if err := SendIPv4RawPacket(conn.id.DstIP[:], buf.Bytes()); err != nil {
		//d.UnregisterConnection(*id)
		return nil, fmt.Errorf("error sending ACK: %v", err)
	}

	return conn, nil
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
			//d.mu.Lock()
			//defer d.mu.Unlock()

			threshold := time.Now().Add(-1 * time.Minute) // 1-minute cutoff

			//for id, conn := range d.connections {
			if d.conn.lastSeen.Before(threshold) {
				//	fmt.Printf("Removing connection %s due to inactivity", d.conn.RemoteAddr())
				//delete(d.connections, id) // Remove it from the connections map
				d.conn.Close() // Close the connection safely
			}
			//}
		}
	}
}

// Close closes the pcap handle
func (d *Dialer) Close() error {
	// Remove iptable Rule
	args := []string{
		"-D", "INPUT",
		"-p", "tcp",
		"--src", d.addr.IP.String(),
		"--sport", fmt.Sprintf("%d", d.addr.Port),
		"-j", "DROP",
	}

	err := runIptablesWithSudo(args)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Rule deleted successfully!")
	}

	close(d.closed)

	d.conn.Close()
	d.handle.Close()
	fmt.Println("pcap closed")
	return nil
}
