package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FingerprintOS infers the likely host operating system, initial TTL, and hops traversed from observed TTL/Hop Limit.
//
// NOTE: TTL-based OS identification is a passive heuristic. Initial TTL values are software-configurable
// (e.g. sysctl net.ipv4.ip_default_ttl) and can vary under VPN encapsulation, tunneling, or non-standard kernels.
func FingerprintOS(ttl uint8, isIPv6 bool) (inferredOS string, initialTTL uint8, hops uint8) {
	if ttl == 0 {
		return "Unknown (TTL 0 / Local)", 0, 0
	}

	switch {
	case ttl <= 64:
		initialTTL = 64
		hops = 64 - ttl
		inferredOS = "Likely Linux / Unix / macOS / Android (Base ~64, Heuristic)"
	case ttl <= 128:
		initialTTL = 128
		hops = 128 - ttl
		inferredOS = "Likely Windows Desktop / Server (Base ~128, Heuristic)"
	default:
		initialTTL = 255
		hops = 255 - ttl
		inferredOS = "Likely Cisco / Solaris / Network Gear (Base ~255, Heuristic)"
	}

	return inferredOS, initialTTL, hops
}

// DetectTTLAnomaly evaluates if an observed TTL indicates intermediate hops, NAT tethering, or routing issues.
//
// HEURISTIC NOTICE: Single-hop decrements on local subnets are indicators of NAT gateways, tethered hotspots,
// or virtual machine bridges. They do not constitute definitive proof of unauthorized routing.
func DetectTTLAnomaly(ttl uint8, srcIP net.IP, isLocalSubnet bool, isIPv6 bool) (bool, string) {
	if ttl == 0 {
		return false, ""
	}

	// On local broadcast domains (direct L2 communication), hosts normally transmit with standard initial TTL.
	// In IPv4, arrival with TTL 63 or 127 suggests an intermediate hop (tethered smartphone, travel router, or VM NAT).
	if isLocalSubnet && !isIPv6 {
		if ttl == 63 {
			return true, "Suspected Intermediate Hop / NAT Indicator (TTL 63 observed on local subnet; expected initial ~64)"
		}
		if ttl == 127 {
			return true, "Suspected Intermediate Hop / NAT Indicator (TTL 127 observed on local subnet; expected initial ~128)"
		}
	} else if isLocalSubnet && isIPv6 {
		// IPv6 does not typically use NAT. Flag unexpected hop decrements as an indicator of an internal router/switch hop.
		if ttl == 63 || ttl == 127 {
			return true, fmt.Sprintf("Possible Local IPv6 Routing Hop Indicator (Hop Limit: %d)", ttl)
		}
	}

	// Unusually low TTL indicative of extended path distance or routing loop
	if ttl > 0 && ttl < 4 {
		return true, fmt.Sprintf("High Hop Count / Depleted TTL Indicator: TTL=%d (Possible routing loop or remote path)", ttl)
	}

	return false, ""
}

// DetectIdentityMismatch checks for discrepancies between MAC hardware vendor and inferred operating system.
//
// HEURISTIC NOTICE: Discrepancies may stem from virtual machines with bridged adapters, dual-boot setups,
// custom sysctl TTL tuning, or MAC address spoofing. Reported strictly as an investigative indicator.
func DetectIdentityMismatch(vendorCategory, vendorName, inferredOS string) (bool, string) {
	if vendorName == "" || strings.Contains(vendorName, "Unknown") || strings.Contains(vendorName, "Randomized") {
		return false, ""
	}

	// Apple hardware exhibiting Windows OS TTL signature
	if strings.Contains(strings.ToLower(vendorName), "apple") && strings.Contains(inferredOS, "Windows") {
		return true, fmt.Sprintf("Potential Hardware/OS Discrepancy (Heuristic: %s OUI vs Windows TTL baseline)", vendorName)
	}

	// Dedicated network equipment (Cisco, Arista, Ubiquiti) exhibiting Windows desktop signature
	if vendorCategory == "network_gear" && strings.Contains(inferredOS, "Windows") {
		return true, fmt.Sprintf("Potential Hardware/OS Discrepancy (Heuristic: Network Hardware OUI [%s] vs Windows TTL baseline)", vendorName)
	}

	// Microsoft hardware (e.g. Surface) exhibiting Cisco/Network gear TTL (255)
	if strings.Contains(strings.ToLower(vendorName), "microsoft") && strings.Contains(inferredOS, "Cisco") {
		return true, fmt.Sprintf("Potential Hardware/OS Discrepancy (Heuristic: Microsoft OUI [%s] vs Network Gear TTL 255 baseline)", vendorName)
	}

	return false, ""
}

// InspectUnencryptedProtocols verifies transport payloads to confirm unencrypted protocols violating security hygiene.
//
// Port alone is treated as a hint; application-layer signatures are inspected to avoid false positives.
func InspectUnencryptedProtocols(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) *SecurityEvent {
	now := time.Now()

	// Port 23: Telnet inspection
	if srcPort == 23 || dstPort == 23 {
		isTelnet := false
		if len(payload) > 0 {
			// Telnet IAC (Interpret As Command: 0xFF) or printable text
			if payload[0] == 0xFF || hasPrintableASCII(payload, 5) {
				isTelnet = true
			}
		} else {
			isTelnet = true // Handshake / connection setup
		}

		if isTelnet {
			return &SecurityEvent{
				Timestamp: now,
				SourceIP:  srcIP,
				DestIP:    dstIP,
				SrcPort:   srcPort,
				DstPort:   dstPort,
				Protocol:  "Telnet",
				Category:  CategoryCleartext,
				Severity:  SeverityAlert,
				Message:   fmt.Sprintf("Insecure Protocol Indicator (Cleartext Telnet Session: %s:%d -> %s:%d)", srcIP, srcPort, dstIP, dstPort),
				Details:   "Telnet transmits authentication credentials and commands unencrypted in cleartext. Recommended remediation: migrate to SSH.",
			}
		}
	}

	// Port 21: FTP Control Channel
	if srcPort == 21 || dstPort == 21 {
		isFTP := false
		if len(payload) > 0 {
			if isFTPCommandOrResponse(payload) {
				isFTP = true
			}
		} else {
			isFTP = true
		}

		if isFTP {
			snippet := extractPayloadSnippet(payload, 30)
			return &SecurityEvent{
				Timestamp: now,
				SourceIP:  srcIP,
				DestIP:    dstIP,
				SrcPort:   srcPort,
				DstPort:   dstPort,
				Protocol:  "FTP",
				Category:  CategoryCleartext,
				Severity:  SeverityAlert,
				Message:   fmt.Sprintf("Insecure Protocol Indicator (Cleartext FTP Session: %s:%d -> %s:%d)", srcIP, srcPort, dstIP, dstPort),
				Details:   fmt.Sprintf("FTP control commands transmit unencrypted credentials. Payload preview: %s", snippet),
			}
		}
	}

	// Port 110: POP3
	if srcPort == 110 || dstPort == 110 {
		return &SecurityEvent{
			Timestamp: now,
			SourceIP:  srcIP,
			DestIP:    dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Protocol:  "POP3",
			Category:  CategoryCleartext,
			Severity:  SeverityAlert,
			Message:   fmt.Sprintf("Insecure Protocol Indicator (Cleartext POP3: %s:%d -> %s:%d)", srcIP, srcPort, dstIP, dstPort),
			Details:   "Unencrypted POP3 email traffic detected. Recommended remediation: migrate to POP3S (port 995) with TLS.",
		}
	}

	// Port 143: IMAP
	if srcPort == 143 || dstPort == 143 {
		return &SecurityEvent{
			Timestamp: now,
			SourceIP:  srcIP,
			DestIP:    dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Protocol:  "IMAP",
			Category:  CategoryCleartext,
			Severity:  SeverityAlert,
			Message:   fmt.Sprintf("Insecure Protocol Indicator (Cleartext IMAP: %s:%d -> %s:%d)", srcIP, srcPort, dstIP, dstPort),
			Details:   "Unencrypted IMAP email traffic detected. Recommended remediation: migrate to IMAPS (port 993) with TLS.",
		}
	}

	// Port 80 / 8080: HTTP Cleartext Web Traffic
	if (dstPort == 80 || dstPort == 8080 || srcPort == 80 || srcPort == 8080) && len(payload) > 0 {
		if isHTTPRequest(payload) || isHTTPResponse(payload) {
			snippet := extractPayloadSnippet(payload, 45)
			return &SecurityEvent{
				Timestamp: now,
				SourceIP:  srcIP,
				DestIP:    dstIP,
				SrcPort:   srcPort,
				DstPort:   dstPort,
				Protocol:  "HTTP",
				Category:  CategoryCleartext,
				Severity:  SeverityAlert,
				Message:   fmt.Sprintf("Insecure Protocol Indicator (Cleartext HTTP Traffic: %s:%d -> %s:%d)", srcIP, srcPort, dstIP, dstPort),
				Details:   fmt.Sprintf("Verified cleartext HTTP web payload. Preview: %s", snippet),
			}
		}
	}

	return nil
}

// InspectDNSLayer inspects UDP port 53 DNS queries and logs active resolution activity.
func InspectDNSLayer(packet gopacket.Packet, srcIP, dstIP net.IP, srcPort, dstPort uint16) []*SecurityEvent {
	var events []*SecurityEvent
	now := time.Now()

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return events
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok || dns == nil {
		return events
	}

	for _, q := range dns.Questions {
		queryName := string(q.Name)
		queryType := q.Type.String()
		if queryName == "" {
			continue
		}

		event := &SecurityEvent{
			Timestamp: now,
			SourceIP:  srcIP,
			DestIP:    dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Protocol:  "DNS",
			Category:  CategoryDNS,
			Severity:  SeverityInfo,
			Message:   fmt.Sprintf("DNS Query Observed: %s requested lookup for %s [%s]", srcIP, queryName, queryType),
			Details:   fmt.Sprintf("Transaction ID: 0x%04X, Class: %s", dns.ID, q.Class.String()),
		}
		events = append(events, event)
	}

	return events
}

// InspectLegacyNameResolution audits UDP 5355 (LLMNR) and UDP 137 (NBT-NS) broadcast traffic.
func InspectLegacyNameResolution(srcIP, dstIP net.IP, srcPort, dstPort uint16) *SecurityEvent {
	now := time.Now()

	// Port 5355: Link-Local Multicast Name Resolution (LLMNR)
	if dstPort == 5355 || srcPort == 5355 {
		return &SecurityEvent{
			Timestamp: now,
			SourceIP:  srcIP,
			DestIP:    dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Protocol:  "LLMNR",
			Category:  CategoryLegacyNameRes,
			Severity:  SeveritySuspicious,
			Message:   fmt.Sprintf("Legacy Protocol Indicator (LLMNR Broadcast: %s -> %s)", srcIP, dstIP),
			Details:   "LLMNR broadcasts should be disabled per security benchmarks (RFC 4795). Prone to local name spoofing and credential relay.",
		}
	}

	// Port 137: NetBIOS Name Service (NBT-NS)
	if dstPort == 137 || srcPort == 137 {
		return &SecurityEvent{
			Timestamp: now,
			SourceIP:  srcIP,
			DestIP:    dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Protocol:  "NBT-NS",
			Category:  CategoryLegacyNameRes,
			Severity:  SeveritySuspicious,
			Message:   fmt.Sprintf("Legacy Protocol Indicator (NetBIOS-NS Broadcast: %s -> %s)", srcIP, dstIP),
			Details:   "NetBIOS Name Service broadcast detected. Recommended: disable NetBIOS over TCP/IP across endpoints to prevent MITM poison attacks.",
		}
	}

	return nil
}

func isHTTPRequest(payload []byte) bool {
	verbs := [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
		[]byte("TRACE "),
		[]byte("CONNECT "),
	}
	for _, v := range verbs {
		if bytes.HasPrefix(payload, v) {
			return true
		}
	}
	return false
}

func isHTTPResponse(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte("HTTP/1.0")) ||
		bytes.HasPrefix(payload, []byte("HTTP/1.1")) ||
		bytes.HasPrefix(payload, []byte("HTTP/2.0"))
}

func isFTPCommandOrResponse(payload []byte) bool {
	// Common FTP commands
	commands := [][]byte{
		[]byte("USER "),
		[]byte("PASS "),
		[]byte("PORT "),
		[]byte("PASV"),
		[]byte("LIST"),
		[]byte("RETR "),
		[]byte("STOR "),
		[]byte("QUIT"),
		[]byte("TYPE "),
		[]byte("SYST"),
	}
	for _, cmd := range commands {
		if bytes.HasPrefix(payload, cmd) {
			return true
		}
	}
	// Common FTP server responses (3-digit code + space)
	if len(payload) >= 4 && (bytes.HasPrefix(payload, []byte("220 ")) ||
		bytes.HasPrefix(payload, []byte("331 ")) ||
		bytes.HasPrefix(payload, []byte("230 ")) ||
		bytes.HasPrefix(payload, []byte("530 "))) {
		return true
	}
	return false
}

func hasPrintableASCII(payload []byte, minLen int) bool {
	count := 0
	for _, b := range payload {
		if b >= 32 && b <= 126 {
			count++
			if count >= minLen {
				return true
			}
		} else {
			count = 0
		}
	}
	return false
}

func extractPayloadSnippet(payload []byte, maxLen int) string {
	if len(payload) == 0 {
		return "(empty payload)"
	}
	n := len(payload)
	if n > maxLen {
		n = maxLen
	}
	cleaned := strings.Map(func(r rune) rune {
		if r >= 32 && r <= 126 {
			return r
		}
		return '.'
	}, string(payload[:n]))

	if len(payload) > maxLen {
		cleaned += "..."
	}
	return cleaned
}
