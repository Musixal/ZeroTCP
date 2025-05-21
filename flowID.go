package ZeroTCP

import (
	"fmt"
	"net"
)

// FlowID uniquely identifies a TCP connection
type FlowID struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

// NewFlowID creates a new FlowID from IP addresses and ports
func NewFlowID(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) *FlowID {
	var sid, did [4]byte
	copy(sid[:], srcIP.To4())
	copy(did[:], dstIP.To4())
	return &FlowID{
		SrcIP:   sid,
		DstIP:   did,
		SrcPort: srcPort,
		DstPort: dstPort,
	}
}

// String returns a string representation of the flow ID
func (f *FlowID) String() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
		f.SrcIP[0], f.SrcIP[1], f.SrcIP[2], f.SrcIP[3], f.SrcPort,
		f.DstIP[0], f.DstIP[1], f.DstIP[2], f.DstIP[3], f.DstPort)
}

// Reverse returns a new FlowID with source and destination swapped
func (f *FlowID) Reverse() *FlowID {
	return &FlowID{
		SrcIP:   f.DstIP,
		DstIP:   f.SrcIP,
		SrcPort: f.DstPort,
		DstPort: f.SrcPort,
	}
}
