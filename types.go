package main

import (
	"net"
	"time"
)

// Severity represents the alert priority of a security event.
type Severity string

const (
	SeverityInfo       Severity = "INFO"
	SeveritySuspicious Severity = "SUSPICIOUS"
	SeverityAlert      Severity = "ALERT"
)

// SecurityStatus represents the security posture of an active host based on passive observations.
type SecurityStatus string

const (
	StatusSafe       SecurityStatus = "SAFE"
	StatusSuspicious SecurityStatus = "SUSPICIOUS"
	StatusAlert      SecurityStatus = "ALERT"
)

// EventCategory classifies the nature of the detected network event.
type EventCategory string

const (
	CategoryCleartext        EventCategory = "CLEARTEXT_TRAFFIC"
	CategoryDNS              EventCategory = "DNS_QUERY"
	CategoryLegacyNameRes    EventCategory = "LEGACY_NAME_RES"
	CategoryTTLAnomaly       EventCategory = "TTL_HOP_INDICATOR"
	CategoryIdentityMismatch EventCategory = "HARDWARE_OS_DISCREPANCY"
	CategoryNewHost          EventCategory = "NEW_HOST"
)

// SecurityEvent records an audited network compliance or security event.
type SecurityEvent struct {
	ID        int64         `json:"id"`
	Timestamp time.Time     `json:"timestamp"`
	SourceIP  net.IP        `json:"source_ip"`
	DestIP    net.IP        `json:"dest_ip"`
	SrcPort   uint16        `json:"src_port"`
	DstPort   uint16        `json:"dst_port"`
	Protocol  string        `json:"protocol"`
	Category  EventCategory `json:"category"`
	Severity  Severity      `json:"severity"`
	Message   string        `json:"message"`
	Details   string        `json:"details"`
}

// HostInfo maintains live telemetry and heuristics for an observed network endpoint.
type HostInfo struct {
	IP                net.IP           `json:"ip"`
	MAC               net.HardwareAddr `json:"mac"`
	Vendor            string           `json:"vendor"`
	VendorCategory    string           `json:"vendor_category"`
	InferredOS        string           `json:"inferred_os"`
	LastSeenTTL       uint8            `json:"last_seen_ttl"`
	InitialTTL        uint8            `json:"initial_ttl"`
	HopsTraversed     uint8            `json:"hops_traversed"`
	IsIPv6            bool             `json:"is_ipv6"`
	SecurityStatus    SecurityStatus   `json:"security_status"`
	DetectedProtocols map[string]int   `json:"detected_protocols"`
	ActiveAnomalies   []string         `json:"active_anomalies"`
	PacketCount       uint64           `json:"packet_count"`
	ByteCount         uint64           `json:"byte_count"`
	FirstSeen         time.Time        `json:"first_seen"`
	LastSeen          time.Time        `json:"last_seen"`
}

// TopTalker summarizes volume metrics for a high-traffic host.
type TopTalker struct {
	IP      string `json:"ip"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// StatsSnapshot captures aggregate network telemetry and reliability metrics for real-time reporting.
type StatsSnapshot struct {
	TotalPackets          uint64            `json:"total_packets"`
	TotalBytes            uint64            `json:"total_bytes"`
	ActiveHostsCount      int               `json:"active_hosts_count"`
	ActiveFlowsCount      int               `json:"active_flows_count"`
	TotalEventsCount      int               `json:"total_events_count"`
	AlertCount            uint64            `json:"alert_count"`
	SuspiciousCount       uint64            `json:"suspicious_count"`
	UnencryptedDetections uint64            `json:"unencrypted_detections"`
	DNSQueriesCount       uint64            `json:"dns_queries_count"`
	LegacyResCount        uint64            `json:"legacy_res_count"`
	AnomaliesCount        uint64            `json:"anomalies_count"`
	PcapDropped           uint64            `json:"pcap_dropped"`
	PcapIfDropped         uint64            `json:"pcap_if_dropped"`
	QueueDropped          uint64            `json:"queue_dropped"`
	ProtocolCounts        map[string]uint64 `json:"protocol_counts"`
	Uptime                time.Duration     `json:"uptime"`
}
