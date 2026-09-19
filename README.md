# NetMonitor 🛡️🛰️

**Defensive Network Monitoring & Protocol Diagnostics Tool**  
**Developed by Ahmad — GitHub: [cys-dexter](https://github.com/cys-dexter)**

NetMonitor is a defensive network monitoring tool written in Go 1.21. It provides real-time packet capture, passive operating system heuristics, intermediate hop/NAT indicator detection, 5-tuple connection flow tracking, and network hygiene auditing (cleartext protocols, DNS queries, and legacy resolution broadcasts) through an interactive Terminal User Interface (TUI) and structured JSON logging via `log/slog`.

---

## Developer Attribution

* **Developer:** Ahmad
* **GitHub:** [cys-dexter](https://github.com/cys-dexter)
* **Project:** NetMonitor
* **Language:** Go 1.21

---

## Architectural Layout

The codebase strictly adheres to single-responsibility modular architecture:

```text
/home/ahmad/.gemini/antigravity/scratch/netmonitor/
├── config.go            # CLI flag parsing, configuration data structures, and validation
├── logger.go            # Structured logging (log/slog) with dedicated file handler
├── interfaces.go        # Device enumeration, IPv4/IPv6 extraction, and privilege checks
├── capture.go           # libpcap/gopacket capture engine, worker pool, and drop monitoring
├── parser.go            # Protocol decoding, passive TTL OS heuristics, and hygiene audit
├── oui.go               # Static 24-bit OUI database & hardware vendor classifier
├── conntrack.go         # 5-tuple TCP/UDP flow tracking with bounded memory and auto-expiry
├── stats.go             # Thread-safe telemetry store, Top Talkers, and event ring buffer
├── ui.go                # Dual-mode split-screen TUI (Host Inventory & Connection Tracker)
├── main.go              # Lean application bootstrap, dependency injection, and signal handling
├── config_test.go       # Unit tests for CLI flags, defaults, and developer identity
├── interfaces_test.go   # Unit tests for subnet classification and interface discovery
├── parser_test.go       # Unit tests for TTL heuristics, OUI lookup, and protocol parsers
├── stats_test.go        # Unit tests for statistics, ring buffer, drop telemetry, and conntrack
├── go.mod               # Go module dependencies
└── README.md            # Comprehensive architecture and operator manual
```

---

## Core Capabilities & Detection Methodology

### 1. Packet Sniffing & Header Parsing Engine
* Captures raw frames on selected network interfaces in promiscuous mode using `libpcap` and `gopacket`.
* Decouples ingestion from analysis via an `8192`-element buffered packet channel feeding 4 concurrent worker goroutines.
* Real-time drop telemetry tracks both kernel-level libpcap drops (`handle.Stats()`) and internal channel queue drops.
* Decodes L2 Ethernet headers, L3 IPv4/IPv6 headers, and L4 TCP/UDP/ICMP transport protocols.

### 2. Passive OS Fingerprinting (Heuristic)
* Infers likely host operating systems based on standard initial Time-To-Live (TTL) baselines:
  * **Base ~64**: Likely Linux / Unix / macOS / iOS / Android
  * **Base ~128**: Likely Windows Desktop / Server
  * **Base ~255**: Likely Cisco / Solaris / Network Infrastructure
* Calculates estimated network hops traversed: $\text{Hops} = \text{InitialTTL} - \text{ObservedTTL}$.

### 3. Network Anomaly & Hop Indicators
* **Intermediate Hop / NAT Indicators**: Flags packets originating on local private subnets (RFC 1918) that arrive with decremented TTL values (`TTL == 63` or `127`). These indicate an intermediate routing hop such as a tethered smartphone hotspot, rogue travel router, or virtual machine NAT bridge.
* **Hardware/OS Discrepancy Indicators**: Cross-references IEEE OUI vendor signatures against inferred host OS baselines (e.g. Apple hardware exhibiting Windows TTL signatures) to highlight potential virtual machine bridging or custom network stacks.
* **Depleted TTL Indicators**: Detects packets with critically low TTLs ($< 4$), pointing to potential routing loops or remote network paths.

### 4. 5-Tuple Connection Tracking (Flow Engine)
* Bidirectional tracking of concurrent TCP and UDP conversations (`Endpoint A <-> Endpoint B [Proto]`).
* Tracks TCP state transitions (`SYN_SENT`, `SYN_RECV`, `ESTABLISHED`, `FIN_WAIT`, `RESET`), packet volume, byte counts, and duration.
* Enforces bounded memory: a background garbage collector evicts stale flows exceeding `flow-timeout` and caps concurrent flows at `max-flows` (default: 5,000).

### 5. Network Hygiene & Compliance Auditing
* **Cleartext Protocols**: Validates application-layer payloads for insecure protocols:
  * **Telnet (Port 23)**: Verified via IAC command sequences (`0xFF`) or terminal text.
  * **FTP (Port 21)**: Verified via FTP control verbs (`USER`, `PASS`, etc.) or response codes.
  * **HTTP (Port 80/8080)**: Verified via HTTP verbs (`GET`, `POST`, etc.) or HTTP response headers.
  * **POP3 (Port 110) & IMAP (Port 143)**: Cleartext email protocols.
* **DNS Query Logging**: Decodes UDP port 53 DNS questions, logging queried domains, record types (A, AAAA, PTR), and transaction IDs.
* **Legacy Name Resolution**: Identifies UDP port 5355 (LLMNR) and port 137 (NetBIOS-NS) broadcasts that should be disabled per CIS/NIST security benchmarks.

### 6. Dual-Mode Terminal User Interface (TUI)
* Built with `tview` and `tcell` in a high-contrast split-screen format:
  * **Top Section**: Real-time auto-scrolling security event log with color coding: Red (`ALERT`), Yellow (`SUSPICIOUS`), and Green (`INFO`).
  * **Bottom Section**: Interactive dual-mode table:
    * **Mode A (Host Inventory)**: IP, MAC, Hardware Vendor, TTL, Inferred OS, Security Status, and Active Indicators.
    * **Mode B (Live Connection Tracker)**: Endpoint A, Endpoint B, Protocol, State, Packets, Volume, and Duration.
  * Press **`t`** to toggle between Hosts and Live Connections.
  * Press **`?`** or **`h`** to display the About modal with developer credentials and heuristic disclaimers.

---

## Heuristic & Analytical Limitations

* **Heuristics vs. Proof**: Passive fingerprinting and anomaly detection are **investigative indicators**, not confirmed security incidents.
* **TTL Customization**: Initial TTL values are software-configurable (e.g. via `sysctl net.ipv4.ip_default_ttl` on Linux or Registry keys on Windows). Encapsulating traffic through VPNs or IPsec tunnels also alters observed TTL values.
* **MAC Address Randomization**: Modern mobile and desktop operating systems employ MAC randomization (RFC 7844) by default on Wi-Fi networks. OUI identification indicates the manufacturer registered to the MAC prefix, not absolute device identity.
* **Promiscuous Mode on Switched Networks**: Promiscuous mode packet capture on a standard switched Ethernet network only observes broadcast, multicast, and unicast traffic directed to or from the monitoring host. To inspect full segment traffic, configure a SPAN/mirror port on your network switch or connect to a network TAP.

---

## Prerequisites & Installation

### 1. Install System Dependencies
NetMonitor requires `libpcap` development libraries and Go 1.21+:

#### Debian / Ubuntu:
```bash
sudo apt update
sudo apt install -y golang-go libpcap-dev
```

#### RHEL / Fedora / CentOS:
```bash
sudo dnf install -y golang libpcap-devel
```

#### Arch Linux:
```bash
sudo pacman -S go libpcap
```

#### macOS (Homebrew):
```bash
brew install go libpcap
```

---

## Building & Testing

```bash
cd /home/ahmad/.gemini/antigravity/scratch/netmonitor

# Download dependencies
go mod tidy

# Run comprehensive test suite
go test -v ./...

# Build standalone binary
go build -o netmonitor .
```

---

## Running NetMonitor

NetMonitor requires raw socket access to capture packets in promiscuous mode.

### Option A: Run with `sudo` (Recommended)
```bash
# List discovered network interfaces
./netmonitor -l

# Start monitoring on a specific interface
sudo ./netmonitor -i eth0

# Monitor with a BPF filter and debug logging
sudo ./netmonitor -i eth0 -f "not port 22" --log-level DEBUG --log-file ./audit.log
```

### Option B: Run without `sudo` (Linux Capabilities)
```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./netmonitor
./netmonitor -i eth0
```

---

## CLI Flags

| Flag | Long Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `-i` | `--interface` | Auto | Interface to monitor. Auto-selects active default route if omitted. |
| `-l` | `--list` | false | List discovered network devices and IP addresses, then exit. |
| `-f` | `--filter` | `""` | Berkeley Packet Filter (BPF) string (e.g., `"tcp or udp"`). |
| `-p` | `--no-promisc` | false | Disable promiscuous capture mode. |
| `-v` | `--version` | false | Display NetMonitor version and developer information. |
| | `--log-file` | `netmonitor.log` | Destination path for structured JSON audit logs. |
| | `--log-level` | `INFO` | Logging threshold (`DEBUG`, `INFO`, `WARN`, `ERROR`). |
| | `--max-flows` | `5000` | Maximum concurrent connections tracked before eviction. |

---

## TUI Keyboard Shortcuts

| Key | Action |
| :--- | :--- |
| `q` / `Ctrl+C` | Gracefully terminate packet capture and exit the application. |
| `t` | **Toggle View**: Switch bottom panel between **Active Host Inventory** and **Live Connection Tracker**. |
| `?` / `h` | **About Modal**: Display tool information, developer attribution, and keybinding guide. |
| `c` | Clear the event log view and flush the security event ring buffer. |
| `Tab` | Switch active focus between the *Security Events* panel and the bottom table. |
| `↑` / `↓` | Navigate table rows or scroll history in the event log. |

---

## Security & Privacy Considerations

* **Data Exposure**: NetMonitor captures network headers and previews unencrypted payloads strictly to detect insecure communication protocols. Ensure monitoring is conducted in compliance with organizational acceptable-use policies and local privacy regulations.
* **Privilege Separation**: Running NetMonitor with `setcap cap_net_raw,cap_net_admin=eip` is preferable to executing as full `root` when possible.
* **Log Security**: Structured logs contain network metadata and should be protected with appropriate file permissions (`chmod 0600`).
