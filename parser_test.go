package main

import (
	"net"
	"strings"
	"testing"
)

func TestFingerprintOS(t *testing.T) {
	tests := []struct {
		ttl        uint8
		isIPv6     bool
		expectedOS string
		initTTL    uint8
		hops       uint8
	}{
		{64, false, "Likely Linux / Unix / macOS / Android (Base ~64, Heuristic)", 64, 0},
		{63, false, "Likely Linux / Unix / macOS / Android (Base ~64, Heuristic)", 64, 1},
		{54, false, "Likely Linux / Unix / macOS / Android (Base ~64, Heuristic)", 64, 10},
		{128, false, "Likely Windows Desktop / Server (Base ~128, Heuristic)", 128, 0},
		{127, false, "Likely Windows Desktop / Server (Base ~128, Heuristic)", 128, 1},
		{115, false, "Likely Windows Desktop / Server (Base ~128, Heuristic)", 128, 13},
		{255, false, "Likely Cisco / Solaris / Network Gear (Base ~255, Heuristic)", 255, 0},
		{250, false, "Likely Cisco / Solaris / Network Gear (Base ~255, Heuristic)", 255, 5},
		{0, false, "Unknown (TTL 0 / Local)", 0, 0},
		{64, true, "Likely Linux / Unix / macOS / Android (Base ~64, Heuristic)", 64, 0},
		{128, true, "Likely Windows Desktop / Server (Base ~128, Heuristic)", 128, 0},
	}

	for _, tt := range tests {
		osName, initTTL, hops := FingerprintOS(tt.ttl, tt.isIPv6)
		if osName != tt.expectedOS {
			t.Errorf("TTL %d (IPv6=%v): expected OS %s, got %s", tt.ttl, tt.isIPv6, tt.expectedOS, osName)
		}
		if initTTL != tt.initTTL {
			t.Errorf("TTL %d: expected initTTL %d, got %d", tt.ttl, tt.initTTL, initTTL)
		}
		if hops != tt.hops {
			t.Errorf("TTL %d: expected hops %d, got %d", tt.ttl, tt.hops, hops)
		}
	}
}

func TestDetectTTLAnomaly(t *testing.T) {
	localIPv4 := net.ParseIP("192.168.1.50")
	publicIPv4 := net.ParseIP("8.8.8.8")
	localIPv6 := net.ParseIP("fe80::1")

	// 1. Local IPv4 subnet with TTL 63 (intermediate hop / NAT indicator)
	anomaly, desc := DetectTTLAnomaly(63, localIPv4, true, false)
	if !anomaly || !strings.Contains(desc, "Suspected Intermediate Hop") {
		t.Errorf("expected NAT indicator for TTL 63 on local IPv4, got anomaly=%v desc=%s", anomaly, desc)
	}

	// 2. Local IPv4 subnet with TTL 127 (Windows intermediate hop / NAT indicator)
	anomaly, desc = DetectTTLAnomaly(127, localIPv4, true, false)
	if !anomaly || !strings.Contains(desc, "Suspected Intermediate Hop") {
		t.Errorf("expected NAT indicator for TTL 127 on local IPv4, got anomaly=%v desc=%s", anomaly, desc)
	}

	// 3. Normal local IPv4 with TTL 64
	anomaly, _ = DetectTTLAnomaly(64, localIPv4, true, false)
	if anomaly {
		t.Errorf("unexpected anomaly for standard local TTL 64")
	}

	// 4. Public packet with TTL 63 (normal internet hop distance)
	anomaly, _ = DetectTTLAnomaly(63, publicIPv4, false, false)
	if anomaly {
		t.Errorf("unexpected anomaly for public internet packet with TTL 63")
	}

	// 5. Local IPv6 hop decrement (reported as routing hop, not NAT)
	anomaly, desc = DetectTTLAnomaly(63, localIPv6, true, true)
	if !anomaly || !strings.Contains(desc, "Local IPv6 Routing Hop") {
		t.Errorf("expected IPv6 routing hop indicator, got anomaly=%v desc=%s", anomaly, desc)
	}

	// 6. Critical TTL depletion (TTL 2)
	anomaly, desc = DetectTTLAnomaly(2, localIPv4, true, false)
	if !anomaly || !strings.Contains(desc, "High Hop Count / Depleted TTL Indicator") {
		t.Errorf("expected Depleted TTL Indicator for TTL 2, got anomaly=%v desc=%s", anomaly, desc)
	}

	// 7. Zero TTL
	anomaly, _ = DetectTTLAnomaly(0, localIPv4, true, false)
	if anomaly {
		t.Errorf("unexpected anomaly for TTL 0")
	}
}

func TestDetectIdentityMismatch(t *testing.T) {
	// Apple hardware with Windows OS signature
	isMismatch, desc := DetectIdentityMismatch("workstation", "Apple, Inc.", "Likely Windows Desktop / Server (Base ~128, Heuristic)")
	if !isMismatch || !strings.Contains(desc, "Potential Hardware/OS Discrepancy") {
		t.Errorf("expected identity discrepancy for Apple + Windows TTL, got mismatch=%v desc=%s", isMismatch, desc)
	}

	// Cisco hardware with Windows OS signature
	isMismatch, desc = DetectIdentityMismatch("network_gear", "Cisco Systems, Inc.", "Likely Windows Desktop / Server (Base ~128, Heuristic)")
	if !isMismatch || !strings.Contains(desc, "Potential Hardware/OS Discrepancy") {
		t.Errorf("expected identity discrepancy for Cisco + Windows TTL, got mismatch=%v desc=%s", isMismatch, desc)
	}

	// Normal Apple hardware with Linux/Unix/macOS signature
	isMismatch, _ = DetectIdentityMismatch("workstation", "Apple, Inc.", "Likely Linux / Unix / macOS / Android (Base ~64, Heuristic)")
	if isMismatch {
		t.Errorf("unexpected identity discrepancy for Apple + macOS signature")
	}

	// Unknown or randomized vendor
	isMismatch, _ = DetectIdentityMismatch("workstation", "Unknown Vendor (Unregistered OUI)", "Likely Windows Desktop / Server")
	if isMismatch {
		t.Errorf("unexpected identity discrepancy for Unknown Vendor")
	}
}

func TestInspectUnencryptedProtocols(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.10")
	dstIP := net.ParseIP("192.168.1.20")

	// Telnet port 23 with IAC command sequence
	telnetPayload := []byte{0xFF, 0xFB, 0x01} // IAC WILL ECHO
	evt := InspectUnencryptedProtocols(srcIP, dstIP, 54321, 23, telnetPayload)
	if evt == nil || evt.Protocol != "Telnet" || evt.Severity != SeverityAlert {
		t.Fatalf("expected Telnet alert on port 23 with IAC payload, got %v", evt)
	}

	// FTP port 21 with USER command
	ftpPayload := []byte("USER anonymous\r\n")
	evt = InspectUnencryptedProtocols(srcIP, dstIP, 54322, 21, ftpPayload)
	if evt == nil || evt.Protocol != "FTP" || evt.Severity != SeverityAlert {
		t.Fatalf("expected FTP alert on port 21, got %v", evt)
	}

	// HTTP GET on port 80
	httpPayload := []byte("GET /status HTTP/1.1\r\nHost: example.internal\r\n\r\n")
	evt = InspectUnencryptedProtocols(srcIP, dstIP, 54323, 80, httpPayload)
	if evt == nil || evt.Protocol != "HTTP" || evt.Severity != SeverityAlert {
		t.Fatalf("expected HTTP alert on port 80 with GET request, got %v", evt)
	}

	// Port 80 with non-HTTP binary payload (should not be falsely asserted as verified HTTP)
	nonHTTPPayload := []byte{0x00, 0x01, 0x02, 0x03}
	evt = InspectUnencryptedProtocols(srcIP, dstIP, 54324, 80, nonHTTPPayload)
	if evt != nil {
		t.Fatalf("expected nil for port 80 with arbitrary binary payload, got %v", evt)
	}

	// HTTPS traffic on port 443 (encrypted)
	evt = InspectUnencryptedProtocols(srcIP, dstIP, 54325, 443, []byte{0x16, 0x03, 0x01, 0x00, 0x50})
	if evt != nil {
		t.Fatalf("expected nil for encrypted HTTPS port 443, got %v", evt)
	}

	// Zero length payload on arbitrary port
	evt = InspectUnencryptedProtocols(srcIP, dstIP, 12345, 9999, nil)
	if evt != nil {
		t.Fatalf("expected nil for arbitrary unmonitored port, got %v", evt)
	}
}

func TestInspectLegacyNameResolution(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.15")
	dstIP := net.ParseIP("224.0.0.252")

	// LLMNR port 5355
	evt := InspectLegacyNameResolution(srcIP, dstIP, 51234, 5355)
	if evt == nil || evt.Protocol != "LLMNR" || evt.Severity != SeveritySuspicious {
		t.Fatalf("expected LLMNR event for port 5355, got %v", evt)
	}

	// NBT-NS port 137
	evt = InspectLegacyNameResolution(srcIP, dstIP, 137, 137)
	if evt == nil || evt.Protocol != "NBT-NS" || evt.Severity != SeveritySuspicious {
		t.Fatalf("expected NBT-NS event for port 137, got %v", evt)
	}

	// Normal web traffic port 80
	evt = InspectLegacyNameResolution(srcIP, dstIP, 50000, 80)
	if evt != nil {
		t.Fatalf("expected nil for port 80 in legacy name resolution check, got %v", evt)
	}
}

func TestLookupVendor(t *testing.T) {
	// Apple MAC
	appleMAC, _ := net.ParseMAC("00:03:93:12:34:56")
	vendor, cat := LookupVendor(appleMAC)
	if !strings.Contains(vendor, "Apple") || cat != "workstation" {
		t.Errorf("expected Apple, Inc., got vendor=%s cat=%s", vendor, cat)
	}

	// Cisco MAC
	ciscoMAC, _ := net.ParseMAC("00:00:0c:ab:cd:ef")
	vendor, cat = LookupVendor(ciscoMAC)
	if !strings.Contains(vendor, "Cisco") || cat != "network_gear" {
		t.Errorf("expected Cisco Systems, got vendor=%s cat=%s", vendor, cat)
	}

	// Broadcast MAC
	bcastMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	vendor, _ = LookupVendor(bcastMAC)
	if !strings.Contains(vendor, "Broadcast") {
		t.Errorf("expected Broadcast MAC, got %s", vendor)
	}

	// Multicast IPv4 MAC (01:00:5e:...)
	mcast4MAC, _ := net.ParseMAC("01:00:5e:00:00:01")
	vendor, _ = LookupVendor(mcast4MAC)
	if !strings.Contains(vendor, "IPv4 Multicast") {
		t.Errorf("expected IPv4 Multicast, got %s", vendor)
	}

	// Multicast IPv6 MAC (33:33:...)
	mcast6MAC, _ := net.ParseMAC("33:33:00:00:00:01")
	vendor, _ = LookupVendor(mcast6MAC)
	if !strings.Contains(vendor, "IPv6 Multicast") {
		t.Errorf("expected IPv6 Multicast, got %s", vendor)
	}

	// Randomized MAC (bit 1 of byte 0 set: 0x02)
	randMAC, _ := net.ParseMAC("02:00:00:11:22:33")
	vendor, _ = LookupVendor(randMAC)
	if !strings.Contains(vendor, "Randomized") {
		t.Errorf("expected Randomized MAC, got %s", vendor)
	}

	// Short / invalid MAC
	vendor, _ = LookupVendor([]byte{0x01, 0x02})
	if !strings.Contains(vendor, "Unknown") {
		t.Errorf("expected Unknown for short MAC, got %s", vendor)
	}
}
