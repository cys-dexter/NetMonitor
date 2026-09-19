package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestNetworkStateHostTracking(t *testing.T) {
	ct := NewConnectionTracker(100, 10*time.Second)
	state := NewNetworkState(10, ct)

	ip1 := net.ParseIP("192.168.1.100")
	mac1, _ := net.ParseMAC("00:03:93:aa:bb:cc") // Apple

	// First packet (IPv4)
	host, isNew := state.RecordHostPacket(ip1, mac1, 64, "TCP", 1500, false)
	if !isNew {
		t.Fatalf("expected isNew=true for first host packet")
	}
	if host.PacketCount != 1 || host.ByteCount != 1500 {
		t.Errorf("expected 1 pkt / 1500 bytes, got %d pkts / %d bytes", host.PacketCount, host.ByteCount)
	}
	if !strings.Contains(host.InferredOS, "Linux") {
		t.Errorf("unexpected inferred OS: %s", host.InferredOS)
	}

	// Second packet from same host
	host, isNew = state.RecordHostPacket(ip1, mac1, 64, "TCP", 500, false)
	if isNew {
		t.Fatalf("expected isNew=false for second host packet")
	}
	if host.PacketCount != 2 || host.ByteCount != 2000 {
		t.Errorf("expected 2 pkts / 2000 bytes, got %d pkts / %d bytes", host.PacketCount, host.ByteCount)
	}

	// IPv6 host
	ip6 := net.ParseIP("fe80::1234")
	host6, isNew6 := state.RecordHostPacket(ip6, mac1, 64, "TCP", 100, true)
	if !isNew6 || !host6.IsIPv6 {
		t.Errorf("expected IPv6 host to be recorded with IsIPv6=true")
	}
}

func TestNetworkStateAnomalyAndStatusElevation(t *testing.T) {
	ct := NewConnectionTracker(100, 10*time.Second)
	state := NewNetworkState(10, ct)

	ip := net.ParseIP("192.168.1.105")
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	host, _ := state.RecordHostPacket(ip, mac, 64, "UDP", 100, false)
	if host.SecurityStatus != StatusSafe {
		t.Fatalf("initial security status should be SAFE, got %s", host.SecurityStatus)
	}

	// Add suspicious anomaly
	state.AddAnomaly(ip, "Suspected Intermediate Hop Indicator", false)
	snapshots := state.GetHostsSnapshot()
	if len(snapshots) != 1 || snapshots[0].SecurityStatus != StatusSuspicious {
		t.Fatalf("expected status SUSPICIOUS, got %s", snapshots[0].SecurityStatus)
	}

	// Add critical alert
	state.AddAnomaly(ip, "Insecure Telnet Protocol Session", true)
	snapshots = state.GetHostsSnapshot()
	if len(snapshots) != 1 || snapshots[0].SecurityStatus != StatusAlert {
		t.Fatalf("expected status ALERT, got %s", snapshots[0].SecurityStatus)
	}
}

func TestNetworkStateRingBuffer(t *testing.T) {
	ct := NewConnectionTracker(100, 10*time.Second)
	maxEvents := 3
	state := NewNetworkState(maxEvents, ct)

	for i := 1; i <= 5; i++ {
		state.AddEvent(&SecurityEvent{
			Message:  "Test Event",
			Protocol: "TCP",
			Severity: SeverityInfo,
		})
	}

	events := state.GetEventsSnapshot(10)
	if len(events) != maxEvents {
		t.Fatalf("expected ring buffer to retain exactly %d events, got %d", maxEvents, len(events))
	}

	if events[0].ID != 3 || events[2].ID != 5 {
		t.Errorf("expected event IDs 3..5, got %d..%d", events[0].ID, events[2].ID)
	}

	state.ClearEvents()
	events = state.GetEventsSnapshot(10)
	if len(events) != 0 {
		t.Fatalf("expected 0 events after ClearEvents(), got %d", len(events))
	}
}

func TestNetworkStateDropTelemetry(t *testing.T) {
	ct := NewConnectionTracker(100, 10*time.Second)
	state := NewNetworkState(10, ct)

	state.RecordPcapDrops(42, 5)
	state.RecordQueueDrop()
	state.RecordQueueDrop()

	stats := state.GetStats()
	if stats.PcapDropped != 42 {
		t.Errorf("expected 42 pcap drops, got %d", stats.PcapDropped)
	}
	if stats.PcapIfDropped != 5 {
		t.Errorf("expected 5 pcap if drops, got %d", stats.PcapIfDropped)
	}
	if stats.QueueDropped != 2 {
		t.Errorf("expected 2 queue drops, got %d", stats.QueueDropped)
	}
}

func TestNetworkStateTopTalkers(t *testing.T) {
	ct := NewConnectionTracker(100, 10*time.Second)
	state := NewNetworkState(10, ct)

	ipLow := net.ParseIP("10.0.0.1")
	ipHigh := net.ParseIP("10.0.0.2")

	state.RecordHostPacket(ipLow, nil, 64, "TCP", 100, false)
	state.RecordHostPacket(ipHigh, nil, 64, "TCP", 5000, false)

	talkers := state.GetTopTalkers(2)
	if len(talkers) != 2 {
		t.Fatalf("expected 2 talkers, got %d", len(talkers))
	}

	if talkers[0].IP != ipHigh.String() {
		t.Errorf("expected highest volume IP to be %s, got %s", ipHigh.String(), talkers[0].IP)
	}
	if talkers[0].Bytes != 5000 {
		t.Errorf("expected 5000 bytes for top talker, got %d", talkers[0].Bytes)
	}
}

func TestConnectionTracker(t *testing.T) {
	ct := NewConnectionTracker(5, 50*time.Millisecond)

	ipA := net.ParseIP("192.168.1.10")
	ipB := net.ParseIP("192.168.1.20")

	// Outgoing SYN packet (A -> B)
	flow := ct.RecordPacket(ipA, ipB, 50000, 80, "TCP", 64, TCPFlags{SYN: true})
	if flow == nil || flow.State != "SYN_SENT" {
		t.Fatalf("expected flow state SYN_SENT, got %v", flow)
	}

	// Return SYN-ACK packet (B -> A)
	flow = ct.RecordPacket(ipB, ipA, 80, 50000, "TCP", 64, TCPFlags{SYN: true, ACK: true})
	if flow == nil || flow.State != "ESTABLISHED" {
		t.Fatalf("expected flow state ESTABLISHED, got %v", flow)
	}
	if flow.Packets != 2 {
		t.Errorf("expected bidirectional flow to track 2 packets, got %d", flow.Packets)
	}

	// FIN packet
	flow = ct.RecordPacket(ipA, ipB, 50000, 80, "TCP", 64, TCPFlags{FIN: true})
	if flow.State != "FIN_WAIT" {
		t.Errorf("expected flow state FIN_WAIT, got %s", flow.State)
	}

	// Capacity enforcement test: fill beyond maxFlows (5)
	for i := 1; i <= 10; i++ {
		src := net.ParseIP("10.0.0.1")
		dst := net.IPv4(10, 0, 0, byte(i+10))
		ct.RecordPacket(src, dst, uint16(20000+i), 80, "TCP", 100, TCPFlags{SYN: true})
	}

	if ct.ActiveFlowCount() > 5 {
		t.Errorf("expected active flows capped at 5, got %d", ct.ActiveFlowCount())
	}

	// Expiration test
	time.Sleep(70 * time.Millisecond)
	evicted := ct.EvictStale()
	if evicted == 0 {
		t.Errorf("expected expired flows to be evicted")
	}
	if ct.ActiveFlowCount() != 0 {
		t.Errorf("expected 0 active flows after eviction, got %d", ct.ActiveFlowCount())
	}
}
