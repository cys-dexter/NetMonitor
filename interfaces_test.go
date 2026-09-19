package main

import (
	"net"
	"testing"
)

func TestIsLocalSubnet(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"10.255.255.254", true},
		{"172.16.0.1", true},
		{"172.31.255.254", true},
		{"172.15.255.255", false},
		{"172.32.0.1", false},
		{"192.168.1.1", true},
		{"192.168.254.254", true},
		{"192.169.1.1", false},
		{"169.254.1.100", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
		{"fe80::1", true},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			parsed := net.ParseIP(tt.ip)
			result := IsLocalSubnet(parsed)
			if result != tt.expected {
				t.Errorf("IsLocalSubnet(%s) = %v; expected %v", tt.ip, result, tt.expected)
			}
		})
	}

	if IsLocalSubnet(nil) != false {
		t.Errorf("expected IsLocalSubnet(nil) to be false")
	}
}

func TestCheckRawPrivileges(t *testing.T) {
	_ = CheckRawPrivileges()
}
