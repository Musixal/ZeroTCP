package ZeroTCP

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PCAPSocket represents a packet capture socket for sending and receiving packets
type PCAPSocket struct {
	handle    *pcap.Handle
	device    string
	localIP   net.IP
	connected bool
	mu        sync.Mutex
}

// NewPCAPSocket creates a new PCAP socket
func NewPCAPSocket(device string) (*PCAPSocket, error) {
	if device == "" {
		var err error
		device, err = findDefaultDevice()
		if err != nil {
			return nil, fmt.Errorf("failed to find default device: %v", err)
		}
	}

	// Get local IP associated with the device
	localIP, err := getDeviceIP(device)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP for device %s: %v", device, err)
	}

	// Open device in promiscuous mode with 1 second timeout
	handle, err := pcap.OpenLive(device, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open device %s: %v", device, err)
	}

	return &PCAPSocket{
		handle:    handle,
		device:    device,
		localIP:   localIP,
		connected: true,
	}, nil
}

// Close closes the PCAP socket
func (p *PCAPSocket) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.connected {
		return nil
	}

	p.handle.Close()
	p.connected = false
	return nil
}

// WritePacket sends a packet to the specified destination
func (p *PCAPSocket) WritePacket(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.connected {
		return ErrClosed
	}

	return p.handle.WritePacketData(data)
}

// ReadPacket reads a packet from the socket
func (p *PCAPSocket) ReadPacket() ([]byte, *layers.IPv4, *layers.TCP, error) {
	if !p.connected {
		return nil, nil, nil, ErrClosed
	}

	// Read packet
	data, _, err := p.handle.ReadPacketData()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error reading packet: %v", err)
	}
	fmt.Println("in the read packet")
	// Parse packet
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	// Get IPv4 layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, nil, nil, fmt.Errorf("packet is not IPv4")
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Get TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, nil, nil, fmt.Errorf("packet is not TCP")
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	// Get application payload
	var payload []byte
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		payload = applicationLayer.Payload()
	}

	return payload, ip, tcp, nil
}

// SetFilter sets a BPF filter on the socket
func (p *PCAPSocket) SetFilter(filter string) error {
	return p.handle.SetBPFFilter(filter)
}

// findDefaultDevice looks for a suitable network interface
func findDefaultDevice() (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}

	// Try to find a non-loopback device with an IPv4 address
	for _, device := range devices {
		if !strings.Contains(device.Name, "lo") && !strings.Contains(device.Name, "loopback") {
			for _, address := range device.Addresses {
				ip := address.IP
				if ip.To4() != nil && !ip.IsLoopback() {
					return device.Name, nil
				}
			}
		}
	}

	// Fall back to loopback if no other device is available
	for _, device := range devices {
		if strings.Contains(device.Name, "lo") || strings.Contains(device.Name, "loopback") {
			return device.Name, nil
		}
	}

	return "", fmt.Errorf("no suitable network interface found")
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
