package ZeroTCP

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket/layers"
)

// getOutboundIP gets the preferred outbound IP address for reaching the specified remote address
func getOutboundIP(remote net.IP) (net.IP, error) {
	// If remote is localhost, use localhost
	if remote.IsLoopback() {
		return net.ParseIP("127.0.0.1"), nil
	}

	// Try to find a suitable interface
	conn, err := net.Dial("udp", remote.String()+":12345")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

// isPrivateIP determines if an IP address is private
func isPrivateIP(ip net.IP) bool {
	// Check if IP is private (RFC 1918)
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
	}
	return false
}

// IsLocalIP determines if an IP address is local
func IsLocalIP(ip net.IP) bool {
	return ip.IsLoopback() || isPrivateIP(ip)
}

// GetLocalInterfaces returns a list of local IP addresses
func GetLocalInterfaces() ([]net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if ip4 := v.IP.To4(); ip4 != nil {
					ips = append(ips, ip4)
				}
			}
		}
	}

	if len(ips) == 0 {
		return nil, errors.New("no IPv4 addresses found")
	}
	return ips, nil
}

func processTCP(tcp *layers.TCP) {
	fmt.Printf("TCP Flags:\n")
	fmt.Printf("  FIN: %t\n", tcp.FIN)
	fmt.Printf("  SYN: %t\n", tcp.SYN)
	fmt.Printf("  RST: %t\n", tcp.RST)
	fmt.Printf("  PSH: %t\n", tcp.PSH)
	fmt.Printf("  ACK: %t\n", tcp.ACK)
	fmt.Printf("  URG: %t\n", tcp.URG)
	fmt.Printf("  ECE: %t\n", tcp.ECE)
	fmt.Printf("  CWR: %t\n", tcp.CWR)
	fmt.Printf("  NS:  %t\n", tcp.NS) // Reserved flag (RFC 3540)
}

func tcpOptions() *[]layers.TCPOption {
	// Modify TCP options to match standard format
	options := []layers.TCPOption{
		{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x05, 0xb4}, // MSS 1460
		},
		{
			OptionType:   layers.TCPOptionKindWindowScale,
			OptionLength: 3,
			OptionData:   []byte{0x07}, // Window scale factor 7
		},
		{
			OptionType:   layers.TCPOptionKindSACKPermitted,
			OptionLength: 2,
		},
		{
			OptionType: layers.TCPOptionKindNop,
		},
		{
			OptionType: layers.TCPOptionKindNop,
		},
	}

	return &options
}
