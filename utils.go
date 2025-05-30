package ZeroTCP

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"syscall"

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

// getDeviceIP returns the IPv4 address of the given network interface
func getDeviceIP(deviceName string) (net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Name == deviceName {
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}

			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					ip := v.IP.To4()
					if ip != nil {
						return ip, nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("no IPv4 address found for device %s", deviceName)
}

// runIptablesWithSudo executes the iptables command with sudo
func runIptablesWithSudo(args []string) error {
	// Prepend "sudo" to the command
	fullCommand := append([]string{"iptables"}, args...)
	cmd := exec.Command("sudo", fullCommand...)

	// Execute the command and capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute iptables command: %v\noutput: %s", err, output)
	}

	fmt.Printf("Command executed successfully: %s\n", output)
	return nil
}

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
