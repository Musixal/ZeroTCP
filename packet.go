package ZeroTCP

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildTCPPacket creates a new TCP packet
func buildTCPPacket(srcPort, dstPort uint16, srcIP, dstIP net.IP, seq, ack uint32, flags byte, payload []byte, computeChecksum bool) []byte {
	// Initialize buffer
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: computeChecksum,
		FixLengths:       true,
	}

	// Create TCP layer
	tcp := &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        seq,
		Ack:        ack,
		DataOffset: 5, // 5 * 4 = 20 bytes (standard TCP header size)
		Window:     65535,
	}

	// Set TCP flags
	if (flags & TCP_SYN) != 0 {
		tcp.SYN = true
	}
	if (flags & TCP_ACK) != 0 {
		tcp.ACK = true
	}
	if (flags & TCP_FIN) != 0 {
		tcp.FIN = true
	}
	if (flags & TCP_RST) != 0 {
		tcp.RST = true
	}
	if (flags & TCP_PSH) != 0 {
		tcp.PSH = true
	}
	if (flags & TCP_URG) != 0 {
		tcp.URG = true
	}

	// Set payload if provided
	if payload != nil {
		tcp.Payload = payload
	}

	// Create IPv4 layer for checksum calculation
	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	// Compute TCP checksum
	if computeChecksum {
		tcp.SetNetworkLayerForChecksum(ip)
	}

	// Serialize TCP layer
	err := gopacket.SerializeLayers(buf, opts, tcp)
	if err != nil {
		return nil
	}

	return buf.Bytes()
}

// buildIPv4Header creates a new IPv4 header
func buildIPv4Header(srcIP, dstIP net.IP, payloadLen int, computeChecksum bool) []byte {
	// Initialize buffer
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: computeChecksum,
		FixLengths:       true,
	}

	// Create IPv4 layer
	ip := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Id:         uint16(time.Now().UnixNano() & 0xffff), // Random ID
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolTCP,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}

	// Serialize IPv4 layer
	err := gopacket.SerializeLayers(buf, opts, ip)
	if err != nil {
		return nil
	}

	return buf.Bytes()
}
