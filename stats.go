package main

import (
	"net"
	"sort"
	"sync"
	"time"
)

// NetworkState manages thread-safe state for hosts, events, protocol counters, and reliability metrics.
type NetworkState struct {
	mu sync.RWMutex

	hosts                 map[string]*HostInfo
	events                []*SecurityEvent
	eventIDSeq            int64
	maxEvents             int
	conntrack             *ConnectionTracker
	protocolCounts        map[string]uint64
	ipPacketCounts        map[string]uint64
	ipByteCounts          map[string]uint64
	totalPackets          uint64
	totalBytes            uint64
	alertCount            uint64
	suspiciousCount       uint64
	unencryptedCount      uint64
	dnsQueriesCount       uint64
	legacyResCount        uint64
	anomaliesCount        uint64
	pcapDropped           uint64
	pcapIfDropped         uint64
	queueDropped          uint64
	startTime             time.Time
}

// NewNetworkState initializes and returns an instance of NetworkState.
func NewNetworkState(maxEvents int, conntrack *ConnectionTracker) *NetworkState {
	if maxEvents <= 0 {
		maxEvents = 1000
	}
	return &NetworkState{
		hosts:          make(map[string]*HostInfo),
		events:         make([]*SecurityEvent, 0, maxEvents),
		maxEvents:      maxEvents,
		conntrack:      conntrack,
		protocolCounts: make(map[string]uint64),
		ipPacketCounts: make(map[string]uint64),
		ipByteCounts:   make(map[string]uint64),
		startTime:      time.Now(),
	}
}

// RecordHostPacket updates host telemetry, OS heuristics, and traffic metrics in a thread-safe manner.
func (s *NetworkState) RecordHostPacket(ip net.IP, mac net.HardwareAddr, ttl uint8, protocol string, byteLen int, isIPv6 bool) (*HostInfo, bool) {
	if ip == nil {
		return nil, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.totalPackets++
	s.totalBytes += uint64(byteLen)

	ipStr := ip.String()
	s.ipPacketCounts[ipStr]++
	s.ipByteCounts[ipStr] += uint64(byteLen)

	if protocol != "" {
		s.protocolCounts[protocol]++
	}

	host, exists := s.hosts[ipStr]
	isNew := false
	now := time.Now()

	if !exists {
		isNew = true
		vendor, vendorCat := LookupVendor(mac)
		inferredOS, initTTL, hops := FingerprintOS(ttl, isIPv6)

		host = &HostInfo{
			IP:                ip,
			MAC:               mac,
			Vendor:            vendor,
			VendorCategory:    vendorCat,
			InferredOS:        inferredOS,
			LastSeenTTL:       ttl,
			InitialTTL:        initTTL,
			HopsTraversed:     hops,
			IsIPv6:            isIPv6,
			SecurityStatus:    StatusSafe,
			DetectedProtocols: make(map[string]int),
			ActiveAnomalies:   make([]string, 0),
			PacketCount:       1,
			ByteCount:         uint64(byteLen),
			FirstSeen:         now,
			LastSeen:          now,
		}

		if protocol != "" {
			host.DetectedProtocols[protocol] = 1
		}
		s.hosts[ipStr] = host
	} else {
		host.PacketCount++
		host.ByteCount += uint64(byteLen)
		host.LastSeen = now

		// Update MAC if previously empty
		if len(host.MAC) == 0 && len(mac) > 0 {
			host.MAC = mac
			vendor, vendorCat := LookupVendor(mac)
			host.Vendor = vendor
			host.VendorCategory = vendorCat
		}

		// Update TTL information if changed
		if ttl > 0 && host.LastSeenTTL != ttl {
			host.LastSeenTTL = ttl
			inferredOS, initTTL, hops := FingerprintOS(ttl, isIPv6)
			host.InferredOS = inferredOS
			host.InitialTTL = initTTL
			host.HopsTraversed = hops
		}

		if protocol != "" {
			host.DetectedProtocols[protocol]++
		}
	}

	return host, isNew
}

// IncrementProtocol updates protocol counters independently for application-layer protocols.
func (s *NetworkState) IncrementProtocol(proto string) {
	if proto == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.protocolCounts[proto]++
}

// RecordPcapDrops records kernel and interface packet drop counters retrieved from libpcap.
func (s *NetworkState) RecordPcapDrops(dropped, ifDropped uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pcapDropped = dropped
	s.pcapIfDropped = ifDropped
}

// RecordQueueDrop increments the count of packets dropped due to internal channel saturation.
func (s *NetworkState) RecordQueueDrop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queueDropped++
}

// AddAnomaly registers an identified anomaly on a host and elevates its security status.
func (s *NetworkState) AddAnomaly(ip net.IP, anomaly string, isAlert bool) {
	if ip == nil || anomaly == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.anomaliesCount++

	ipStr := ip.String()
	host, exists := s.hosts[ipStr]
	if !exists {
		return
	}

	for _, existing := range host.ActiveAnomalies {
		if existing == anomaly {
			return
		}
	}

	host.ActiveAnomalies = append(host.ActiveAnomalies, anomaly)

	if isAlert {
		host.SecurityStatus = StatusAlert
	} else if host.SecurityStatus != StatusAlert {
		host.SecurityStatus = StatusSuspicious
	}
}

// AddEvent records a security or compliance event to the circular ring buffer.
func (s *NetworkState) AddEvent(event *SecurityEvent) {
	if event == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.eventIDSeq++
	event.ID = s.eventIDSeq

	switch event.Severity {
	case SeverityAlert:
		s.alertCount++
	case SeveritySuspicious:
		s.suspiciousCount++
	}

	switch event.Category {
	case CategoryCleartext:
		s.unencryptedCount++
	case CategoryDNS:
		s.dnsQueriesCount++
	case CategoryLegacyNameRes:
		s.legacyResCount++
	case CategoryTTLAnomaly, CategoryIdentityMismatch:
		s.anomaliesCount++
	}

	if event.SourceIP != nil {
		if host, exists := s.hosts[event.SourceIP.String()]; exists {
			if event.Severity == SeverityAlert {
				host.SecurityStatus = StatusAlert
			} else if event.Severity == SeveritySuspicious && host.SecurityStatus != StatusAlert {
				host.SecurityStatus = StatusSuspicious
			}
		}
	}

	// Bounded ring buffer eviction
	if len(s.events) >= s.maxEvents {
		s.events = append(s.events[1:], event)
	} else {
		s.events = append(s.events, event)
	}
}

// GetHostsSnapshot returns a cloned, sorted slice of all tracked hosts.
func (s *NetworkState) GetHostsSnapshot() []*HostInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*HostInfo, 0, len(s.hosts))
	for _, h := range s.hosts {
		hostCopy := *h
		hostCopy.ActiveAnomalies = make([]string, len(h.ActiveAnomalies))
		copy(hostCopy.ActiveAnomalies, h.ActiveAnomalies)

		hostCopy.DetectedProtocols = make(map[string]int, len(h.DetectedProtocols))
		for k, v := range h.DetectedProtocols {
			hostCopy.DetectedProtocols[k] = v
		}

		result = append(result, &hostCopy)
	}

	sort.Slice(result, func(i, j int) bool {
		priority := func(status SecurityStatus) int {
			switch status {
			case StatusAlert:
				return 0
			case StatusSuspicious:
				return 1
			default:
				return 2
			}
		}
		pI, pJ := priority(result[i].SecurityStatus), priority(result[j].SecurityStatus)
		if pI != pJ {
			return pI < pJ
		}
		return result[i].LastSeen.After(result[j].LastSeen)
	})

	return result
}

// GetEventsSnapshot returns up to 'limit' most recent security events.
func (s *NetworkState) GetEventsSnapshot(limit int) []*SecurityEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.events)
	if total == 0 {
		return nil
	}

	start := 0
	if limit > 0 && total > limit {
		start = total - limit
	}

	result := make([]*SecurityEvent, total-start)
	copy(result, s.events[start:])
	return result
}

// ClearEvents flushes the security event history.
func (s *NetworkState) ClearEvents() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = make([]*SecurityEvent, 0, s.maxEvents)
}

// GetTopTalkers returns the highest bandwidth-consuming IP addresses.
func (s *NetworkState) GetTopTalkers(limit int) []TopTalker {
	s.mu.RLock()
	defer s.mu.RUnlock()

	talkers := make([]TopTalker, 0, len(s.ipByteCounts))
	for ip, bytes := range s.ipByteCounts {
		talkers = append(talkers, TopTalker{
			IP:      ip,
			Bytes:   bytes,
			Packets: s.ipPacketCounts[ip],
		})
	}

	sort.Slice(talkers, func(i, j int) bool {
		return talkers[i].Bytes > talkers[j].Bytes
	})

	if limit > 0 && len(talkers) > limit {
		return talkers[:limit]
	}

	return talkers
}

// GetStats returns an aggregate summary of monitoring statistics and drop telemetry.
func (s *NetworkState) GetStats() StatsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	flowsCount := 0
	if s.conntrack != nil {
		flowsCount = s.conntrack.ActiveFlowCount()
	}

	protoCopy := make(map[string]uint64, len(s.protocolCounts))
	for k, v := range s.protocolCounts {
		protoCopy[k] = v
	}

	return StatsSnapshot{
		TotalPackets:          s.totalPackets,
		TotalBytes:            s.totalBytes,
		ActiveHostsCount:      len(s.hosts),
		ActiveFlowsCount:      flowsCount,
		TotalEventsCount:      len(s.events),
		AlertCount:            s.alertCount,
		SuspiciousCount:       s.suspiciousCount,
		UnencryptedDetections: s.unencryptedCount,
		DNSQueriesCount:       s.dnsQueriesCount,
		LegacyResCount:        s.legacyResCount,
		AnomaliesCount:        s.anomaliesCount,
		PcapDropped:           s.pcapDropped,
		PcapIfDropped:         s.pcapIfDropped,
		QueueDropped:          s.queueDropped,
		ProtocolCounts:        protoCopy,
		Uptime:                time.Since(s.startTime),
	}
}
