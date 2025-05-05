package ZeroTCP

import (
	"fmt"
	"net"
	"syscall"
)

func SendIPv4RawPacket(dstIP net.IP, packet []byte) error {
	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("socket error: %w", err)
	}
	defer syscall.Close(fd)

	// Tell kernel not to add its own IP header
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return fmt.Errorf("setsockopt IP_HDRINCL error: %w", err)
	}

	// Destination address struct
	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], dstIP.To4())

	// Send raw packet
	err = syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		return fmt.Errorf("sendto error: %w", err)
	}

	return nil
}
