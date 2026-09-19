package main

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// FlowKey uniquely identifies a bidirectional communication channel (5-tuple).
type FlowKey struct {
	EndpointA string `json:"endpoint_a"`
	EndpointB string `json:"endpoint_b"`
	PortA     uint16 `json:"port_a"`
	PortB     uint16 `json:"port_b"`
	Protocol  string `json:"protocol"`
}

// String returns a canonical string representation of the flow key.
func (k FlowKey) String() string {
	return fmt.Sprintf("%s:%d <-> %s:%d [%s]", k.EndpointA, k.PortA, k.EndpointB, k.PortB, k.Protocol)
}

// Flow records live traffic telemetry, duration, and state for an active network conversation.
type Flow struct {
	Key       FlowKey   `json:"key"`
	Packets   uint64    `json:"packets"`
	Bytes     uint64    `json:"bytes"`
	State     string    `json:"state"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Duration returns the total active time elapsed for the flow.
func (f *Flow) Duration() time.Duration {
	return f.LastSeen.Sub(f.FirstSeen)
}

// TCPFlags captures relevant TCP control flags for session state tracking.
type TCPFlags struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
	URG bool
}

// ConnectionTracker maintains thread-safe state for all active network conversations.
type ConnectionTracker struct {
	mu          sync.RWMutex
	flows       map[string]*Flow
	maxFlows    int
	flowTimeout time.Duration
}

// NewConnectionTracker initializes a ConnectionTracker with bounded capacity and timeout thresholds.
func NewConnectionTracker(maxFlows int, timeout time.Duration) *ConnectionTracker {
	if maxFlows <= 0 {
		maxFlows = 5000
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &ConnectionTracker{
		flows:       make(map[string]*Flow, maxFlows),
		maxFlows:    maxFlows,
		flowTimeout: timeout,
	}
}

// CanonicalizeKey normalizes endpoint ordering so traffic in either direction maps to the same flow.
func CanonicalizeKey(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto string) FlowKey {
	srcStr := srcIP.String()
	dstStr := dstIP.String()

	// Compare IP strings to produce deterministic ordering
	if bytes.Compare(srcIP, dstIP) > 0 || (bytes.Equal(srcIP, dstIP) && srcPort > dstPort) {
		return FlowKey{
			EndpointA: dstStr,
			EndpointB: srcStr,
			PortA:     dstPort,
			PortB:     srcPort,
			Protocol:  proto,
		}
	}

	return FlowKey{
		EndpointA: srcStr,
		EndpointB: dstStr,
		PortA:     srcPort,
		PortB:     dstPort,
		Protocol:  proto,
	}
}

// RecordPacket updates flow volume, duration, and TCP state transitions.
func (ct *ConnectionTracker) RecordPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto string, byteLen int, flags TCPFlags) *Flow {
	if srcIP == nil || dstIP == nil {
		return nil
	}

	key := CanonicalizeKey(srcIP, dstIP, srcPort, dstPort, proto)
	keyStr := key.String()

	ct.mu.Lock()
	defer ct.mu.Unlock()

	now := time.Now()
	flow, exists := ct.flows[keyStr]

	if !exists {
		// Enforce capacity bounds
		if len(ct.flows) >= ct.maxFlows {
			ct.evictStaleInternal(now)
			// If still at capacity, drop the oldest flow
			if len(ct.flows) >= ct.maxFlows {
				ct.dropOldestInternal()
			}
		}

		initialState := "ESTABLISHED"
		if proto == "TCP" {
			if flags.SYN && !flags.ACK {
				initialState = "SYN_SENT"
			} else if flags.SYN && flags.ACK {
				initialState = "SYN_RECV"
			}
		} else if proto == "UDP" {
			initialState = "UDP_ACTIVE"
		} else if proto == "ICMP" || proto == "ICMPv4" || proto == "ICMPv6" {
			initialState = "ICMP_ACTIVE"
		}

		flow = &Flow{
			Key:       key,
			Packets:   1,
			Bytes:     uint64(byteLen),
			State:     initialState,
			FirstSeen: now,
			LastSeen:  now,
		}
		ct.flows[keyStr] = flow
	} else {
		flow.Packets++
		flow.Bytes += uint64(byteLen)
		flow.LastSeen = now

		// Update TCP state transitions
		if proto == "TCP" {
			if flags.RST {
				flow.State = "RESET"
			} else if flags.FIN {
				flow.State = "FIN_WAIT"
			} else if flags.SYN && flags.ACK {
				flow.State = "ESTABLISHED"
			} else if flow.State == "SYN_SENT" && flags.ACK {
				flow.State = "ESTABLISHED"
			}
		}
	}

	return flow
}

// EvictStale removes inactive flows whose idle duration exceeds the configured timeout.
func (ct *ConnectionTracker) EvictStale() int {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	return ct.evictStaleInternal(time.Now())
}

func (ct *ConnectionTracker) evictStaleInternal(now time.Time) int {
	evicted := 0
	for k, f := range ct.flows {
		if now.Sub(f.LastSeen) > ct.flowTimeout {
			delete(ct.flows, k)
			evicted++
		}
	}
	return evicted
}

func (ct *ConnectionTracker) dropOldestInternal() {
	var oldestKey string
	var oldestTime time.Time

	for k, f := range ct.flows {
		if oldestKey == "" || f.LastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = f.LastSeen
		}
	}

	if oldestKey != "" {
		delete(ct.flows, oldestKey)
	}
}

// GetActiveFlows returns a copy of top active flows sorted by most recent activity.
func (ct *ConnectionTracker) GetActiveFlows(limit int) []*Flow {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	list := make([]*Flow, 0, len(ct.flows))
	for _, f := range ct.flows {
		copyFlow := *f
		list = append(list, &copyFlow)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].LastSeen.After(list[j].LastSeen)
	})

	if limit > 0 && len(list) > limit {
		return list[:limit]
	}

	return list
}

// ActiveFlowCount returns the total number of currently tracked conversations.
func (ct *ConnectionTracker) ActiveFlowCount() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	return len(ct.flows)
}
