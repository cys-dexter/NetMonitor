package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// CaptureEngine orchestrates live packet capture, worker pools, and protocol dispatch.
type CaptureEngine struct {
	cfg        AppConfig
	state      *NetworkState
	conntrack  *ConnectionTracker
	handle     *pcap.Handle
	packetChan chan gopacket.Packet
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

// NewCaptureEngine creates a new CaptureEngine configured with state and flow tracking.
func NewCaptureEngine(cfg AppConfig, state *NetworkState, conntrack *ConnectionTracker) *CaptureEngine {
	return &CaptureEngine{
		cfg:        cfg,
		state:      state,
		conntrack:  conntrack,
		packetChan: make(chan gopacket.Packet, 8192),
		stopChan:   make(chan struct{}),
	}
}

// Start opens the pcap handle, sets BPF filters, and spawns the ingestion and worker goroutines.
func (c *CaptureEngine) Start(ctx context.Context) error {
	slog.Info("Starting packet capture engine",
		"interface", c.cfg.InterfaceName,
		"promiscuous", c.cfg.Promiscuous,
		"snap_len", c.cfg.SnapLen,
		"bpf_filter", c.cfg.BPFFilter,
	)

	handle, err := pcap.OpenLive(c.cfg.InterfaceName, c.cfg.SnapLen, c.cfg.Promiscuous, c.cfg.Timeout)
	if err != nil {
		return fmt.Errorf("failed to open interface '%s' for packet capture: %w", c.cfg.InterfaceName, err)
	}
	c.handle = handle

	if c.cfg.BPFFilter != "" {
		if err := c.handle.SetBPFFilter(c.cfg.BPFFilter); err != nil {
			c.handle.Close()
			return fmt.Errorf("failed to compile BPF filter '%s': %w", c.cfg.BPFFilter, err)
		}
		slog.Info("BPF filter applied successfully", "filter", c.cfg.BPFFilter)
	}

	numWorkers := 4
	for i := 0; i < numWorkers; i++ {
		c.wg.Add(1)
		go c.workerLoop(ctx, i)
	}

	c.wg.Add(1)
	go c.captureLoop(ctx)

	// Maintenance ticker for flow eviction and kernel drop monitoring
	c.wg.Add(1)
	go c.maintenanceLoop(ctx)

	return nil
}

// captureLoop streams packets from libpcap into the worker channel.
func (c *CaptureEngine) captureLoop(ctx context.Context) {
	defer c.wg.Done()
	defer close(c.packetChan)

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	packets := packetSource.Packets()

	droppedCount := uint64(0)

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			if packet == nil {
				continue
			}

			select {
			case c.packetChan <- packet:
			default:
				droppedCount++
				c.state.RecordQueueDrop()
				if droppedCount%1000 == 0 {
					slog.Warn("Packet queue saturation, dropping packets to maintain real-time latency",
						"dropped_total", droppedCount)
				}
			}
		}
	}
}

// workerLoop parses packet headers and executes anomaly detection and connection tracking.
func (c *CaptureEngine) workerLoop(ctx context.Context, workerID int) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-c.packetChan:
			if !ok {
				return
			}
			c.processPacket(packet)
		}
	}
}

// maintenanceLoop periodically polls kernel packet drops and evicts stale network flows.
func (c *CaptureEngine) maintenanceLoop(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		case <-ticker.C:
			// 1. Query kernel pcap statistics
			if c.handle != nil {
				if pStats, err := c.handle.Stats(); err == nil && pStats != nil {
					c.state.RecordPcapDrops(uint64(pStats.PacketsDropped), uint64(pStats.PacketsIfDropped))
				}
			}

			// 2. Evict expired flows
			if c.conntrack != nil {
				evicted := c.conntrack.EvictStale()
				if evicted > 0 {
					slog.Debug("Evicted stale connections from flow tracker", "evicted_count", evicted)
				}
			}
		}
	}
}

// processPacket extracts L2, L3, and L4 headers, fingerprints hosts, and audits network hygiene.
func (c *CaptureEngine) processPacket(packet gopacket.Packet) {
	if packet == nil {
		return
	}

	var (
		srcMAC   net.HardwareAddr
		srcIP    net.IP
		dstIP    net.IP
		ttl      uint8
		protocol string
		isIPv6   bool
	)

	// 1. Ethernet Header
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if eth, ok := ethLayer.(*layers.Ethernet); ok {
			srcMAC = eth.SrcMAC
			_ = eth.DstMAC // Safely ignore unused destination MAC
		}
	}

	// 2. IP Header (IPv4 or IPv6)
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		if ip4, ok := ip4Layer.(*layers.IPv4); ok {
			srcIP = ip4.SrcIP
			dstIP = ip4.DstIP
			ttl = ip4.TTL
			protocol = ip4.Protocol.String()
			isIPv6 = false
		}
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		if ip6, ok := ip6Layer.(*layers.IPv6); ok {
			srcIP = ip6.SrcIP
			dstIP = ip6.DstIP
			ttl = ip6.HopLimit
			protocol = ip6.NextHeader.String()
			isIPv6 = true
		}
	}

	if srcIP == nil {
		return
	}

	byteLen := len(packet.Data())

	// 3. Record Host Metrics & Telemetry
	host, isNew := c.state.RecordHostPacket(srcIP, srcMAC, ttl, protocol, byteLen, isIPv6)

	if isNew && host != nil {
		slog.Info("New network host observed",
			"ip", srcIP.String(),
			"mac", srcMAC.String(),
			"vendor", host.Vendor,
			"inferred_os", host.InferredOS,
		)

		c.state.AddEvent(&SecurityEvent{
			Timestamp: time.Now(),
			SourceIP:  srcIP,
			DestIP:    dstIP,
			Protocol:  protocol,
			Category:  CategoryNewHost,
			Severity:  SeverityInfo,
			Message:   fmt.Sprintf("New Host Discovered: %s [Vendor: %s | %s]", srcIP, host.Vendor, host.InferredOS),
			Details:   fmt.Sprintf("MAC: %s, Observed TTL/HopLimit: %d", srcMAC, ttl),
		})
	}

	// 4. Heuristic Anomaly Detection: TTL Variation & NAT / Hop Indicators
	isLocal := IsLocalSubnet(srcIP)
	if hasAnomaly, desc := DetectTTLAnomaly(ttl, srcIP, isLocal, isIPv6); hasAnomaly {
		c.state.AddAnomaly(srcIP, desc, false)
		c.state.AddEvent(&SecurityEvent{
			Timestamp: time.Now(),
			SourceIP:  srcIP,
			DestIP:    dstIP,
			Protocol:  protocol,
			Category:  CategoryTTLAnomaly,
			Severity:  SeveritySuspicious,
			Message:   fmt.Sprintf("%s on host %s", desc, srcIP),
			Details:   fmt.Sprintf("Source MAC: %s, Current TTL: %d, Subnet: Local RFC1918", srcMAC, ttl),
		})
	}

	// 5. Heuristic Anomaly Detection: MAC OUI vs Inferred OS Mismatch
	if host != nil {
		if isMismatch, mismatchDesc := DetectIdentityMismatch(host.VendorCategory, host.Vendor, host.InferredOS); isMismatch {
			c.state.AddAnomaly(srcIP, mismatchDesc, true)
			c.state.AddEvent(&SecurityEvent{
				Timestamp: time.Now(),
				SourceIP:  srcIP,
				DestIP:    dstIP,
				Protocol:  protocol,
				Category:  CategoryIdentityMismatch,
				Severity:  SeverityAlert,
				Message:   mismatchDesc,
				Details:   fmt.Sprintf("Host: %s, MAC: %s, OUI: %s, TTL: %d", srcIP, srcMAC, host.Vendor, ttl),
			})
		}
	}

	// 6. Transport Layer & Flow Tracking
	var tcpFlags TCPFlags
	var srcPort, dstPort uint16

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)

			tcpFlags = TCPFlags{
				SYN: tcp.SYN,
				ACK: tcp.ACK,
				FIN: tcp.FIN,
				RST: tcp.RST,
				PSH: tcp.PSH,
				URG: tcp.URG,
			}

			if c.conntrack != nil {
				c.conntrack.RecordPacket(srcIP, dstIP, srcPort, dstPort, "TCP", byteLen, tcpFlags)
			}

			if alert := InspectUnencryptedProtocols(srcIP, dstIP, srcPort, dstPort, tcp.Payload); alert != nil {
				c.state.AddEvent(alert)
				c.state.AddAnomaly(srcIP, fmt.Sprintf("Insecure %s Traffic Indicator", alert.Protocol), true)
				c.state.IncrementProtocol(alert.Protocol)
			}
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)

			if c.conntrack != nil {
				c.conntrack.RecordPacket(srcIP, dstIP, srcPort, dstPort, "UDP", byteLen, tcpFlags)
			}

			// Check DNS queries (Port 53)
			if srcPort == 53 || dstPort == 53 {
				c.state.IncrementProtocol("DNS")
				dnsEvents := InspectDNSLayer(packet, srcIP, dstIP, srcPort, dstPort)
				for _, evt := range dnsEvents {
					c.state.AddEvent(evt)
				}
			}

			// Check LLMNR (5355) / NetBIOS-NS (137)
			if srcPort == 5355 || dstPort == 5355 || srcPort == 137 || dstPort == 137 {
				if legEvt := InspectLegacyNameResolution(srcIP, dstIP, srcPort, dstPort); legEvt != nil {
					c.state.AddEvent(legEvt)
					c.state.AddAnomaly(srcIP, fmt.Sprintf("Legacy %s Broadcast Indicator", legEvt.Protocol), false)
					c.state.IncrementProtocol(legEvt.Protocol)
				}
			}
		}
	}
}

// Stop cleanly terminates capture and releases pcap resources.
func (c *CaptureEngine) Stop() {
	select {
	case <-c.stopChan:
		return
	default:
		close(c.stopChan)
	}

	if c.handle != nil {
		c.handle.Close()
	}

	c.wg.Wait()
	slog.Info("Packet capture engine stopped successfully")
}
