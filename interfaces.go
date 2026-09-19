package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket/pcap"
)

// InterfaceSummary provides a concise overview of a network device's status and addresses.
type InterfaceSummary struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IPv4Addrs   []string `json:"ipv4_addrs"`
	IsLoopback  bool     `json:"is_loopback"`
}

// ListInterfaces queries libpcap to enumerate all detected network devices.
func ListInterfaces() ([]pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("libpcap device discovery failed: %w", err)
	}
	return devices, nil
}

// GetInterfaceSummaries transforms libpcap device lists into structured summary models.
func GetInterfaceSummaries() ([]InterfaceSummary, error) {
	devices, err := ListInterfaces()
	if err != nil {
		return nil, err
	}

	summaries := make([]InterfaceSummary, 0, len(devices))
	for _, dev := range devices {
		summary := InterfaceSummary{
			Name:        dev.Name,
			Description: dev.Description,
			IPv4Addrs:   make([]string, 0),
			IsLoopback:  dev.Name == "lo" || dev.Name == "lo0",
		}

		for _, addr := range dev.Addresses {
			if ip := addr.IP.To4(); ip != nil {
				summary.IPv4Addrs = append(summary.IPv4Addrs, ip.String())
				if ip.IsLoopback() {
					summary.IsLoopback = true
				}
			}
		}

		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// FindDefaultInterface attempts to locate an active network interface with a configured IPv4 address.
func FindDefaultInterface() (string, error) {
	devices, err := ListInterfaces()
	if err != nil {
		return "", err
	}

	if len(devices) == 0 {
		return "", errors.New("no network interfaces available on system")
	}

	// 1. First priority: Non-loopback device with an active IPv4 address
	for _, dev := range devices {
		if dev.Name == "lo" || dev.Name == "lo0" {
			continue
		}
		for _, addr := range dev.Addresses {
			if ip := addr.IP.To4(); ip != nil && !ip.IsLoopback() {
				return dev.Name, nil
			}
		}
	}

	// 2. Second priority: Any non-loopback device
	for _, dev := range devices {
		if dev.Name != "lo" && dev.Name != "lo0" {
			return dev.Name, nil
		}
	}

	// 3. Fallback: Return first available device
	return devices[0].Name, nil
}

// CheckRawPrivileges checks whether the process has root privileges (UID 0).
func CheckRawPrivileges() bool {
	return os.Geteuid() == 0
}

// IsLocalSubnet evaluates if an IP address belongs to RFC 1918 private space, loopback, or link-local.
func IsLocalSubnet(ip net.IP) bool {
	if ip == nil {
		return false
	}

	if ip.IsLoopback() {
		return true
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		// 10.0.0.0/8
		if ipv4[0] == 10 {
			return true
		}
		// 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
		if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ipv4[0] == 192 && ipv4[1] == 168 {
			return true
		}
		// 169.254.0.0/16 (Link-Local)
		if ipv4[0] == 169 && ipv4[1] == 254 {
			return true
		}
		return false
	}

	// IPv6 Link-Local / Unique Local Addresses
	return ip.IsLinkLocalUnicast() || ip.IsPrivate()
}
