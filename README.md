# NetMonitor 🛡️🛰️

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat\&logo=go)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey)](https://github.com/cys-dexter/NetMonitor)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Defensive Network Monitoring & Protocol Diagnostics Tool**
*Developed by Ahmad — GitHub: [@cys-dexter](https://github.com/cys-dexter)*

---

## 📖 Overview

**NetMonitor** is a high-performance defensive network monitoring and protocol diagnostics tool written in **Go 1.21+**.

It provides real-time packet capture and analysis, passive operating-system fingerprinting, network-hop and NAT indicators, 5-tuple connection tracking, and network hygiene auditing.

The application combines an interactive **Terminal User Interface (TUI)** with structured **JSON audit logging** powered by Go's `log/slog` package.

NetMonitor is designed for **defensive monitoring, troubleshooting, network visibility, and security auditing** within authorized environments.

---

## 👨‍💻 Developer

* **Developer:** Ahmad
* **GitHub:** [@cys-dexter](https://github.com/cys-dexter)
* **Project:** NetMonitor
* **Language:** Go 1.21+

---

## 🏗️ Architecture

NetMonitor follows a modular, single-responsibility architecture in which each component has a clearly defined role.

```text
netmonitor/
├── config.go            # CLI flag parsing, configuration, and validation
├── logger.go            # Structured logging with log/slog and file output
├── interfaces.go        # Network interface discovery, IP extraction, and privilege checks
├── capture.go           # libpcap/gopacket capture engine, worker pool, and drop monitoring
├── parser.go            # Protocol decoding, TTL heuristics, and network hygiene analysis
├── oui.go               # Static 24-bit OUI database and hardware vendor classification
├── conntrack.go         # 5-tuple TCP/UDP flow tracking with bounded memory and expiration
├── stats.go             # Thread-safe telemetry, top talkers, and event ring buffer
├── ui.go                # Dual-mode split-screen Terminal User Interface
├── main.go              # Application bootstrap, dependency injection, and signal handling
├── config_test.go       # Configuration and CLI unit tests
├── interfaces_test.go   # Interface discovery and subnet classification tests
├── parser_test.go       # TTL, OUI, and protocol parser tests
├── stats_test.go        # Statistics, ring buffer, drop telemetry, and conntrack tests
├── go.mod               # Go module dependencies
└── README.md            # Project documentation and operator guide
```

---

# ⚡ Core Capabilities

## 1. Packet Capture & Protocol Analysis

NetMonitor provides real-time packet capture and protocol decoding through `libpcap` and `gopacket`.

Key capabilities include:

* Captures raw network frames from a selected interface.
* Supports promiscuous capture mode.
* Uses an `8192`-element buffered packet channel to decouple packet ingestion from analysis.
* Processes packets through **4 concurrent worker goroutines**.
* Monitors packet drops at both the kernel/libpcap layer and internal processing queue.
* Decodes:

  * Ethernet / Layer 2 headers
  * IPv4 / IPv6 / Layer 3 headers
  * TCP
  * UDP
  * ICMP

---

## 2. Passive OS Fingerprinting

NetMonitor uses **passive TTL-based heuristics** to estimate the likely operating-system family associated with observed traffic.

Typical initial TTL baselines include:

| Initial TTL | Likely Platform Family                     |
| ----------- | ------------------------------------------ |
| ~64         | Linux, Unix, macOS, iOS, Android           |
| ~128        | Windows Desktop / Server                   |
| ~255        | Cisco, Solaris, and network infrastructure |

The estimated number of traversed hops is calculated using:

```text
Estimated Hops = Initial TTL - Observed TTL
```

These results are **heuristic indicators**, not definitive operating-system identification.

---

## 3. Network Anomaly & Hop Indicators

NetMonitor analyzes packet metadata for indicators that may help identify unusual routing or network configurations.

### Intermediate Hop / NAT Indicators

Packets originating from private RFC 1918 address space may be flagged when their observed TTL suggests an additional routing hop, including common values such as:

* `TTL = 63`
* `TTL = 127`

These patterns may be consistent with environments involving:

* Mobile tethering or hotspot routing
* Travel routers
* Virtual-machine NAT bridges
* Other intermediate routing configurations

### Hardware / OS Discrepancy Indicators

The tool cross-references:

* IEEE OUI vendor information
* Observed MAC prefixes
* Passive TTL-based OS heuristics

A mismatch can be surfaced as an **investigative indicator** that may warrant further examination.

### Depleted TTL Indicators

Packets with extremely low observed TTL values:

```text
TTL < 4
```

are flagged because they may indicate unusual routing paths, routing loops, or traffic traversing multiple network hops.

---

# 4. 5-Tuple Connection Tracking

NetMonitor maintains bounded state for active TCP and UDP conversations using 5-tuple flow identification.

Each tracked flow can include:

* Source endpoint
* Destination endpoint
* Transport protocol
* Packet count
* Byte volume
* Connection duration
* TCP state

TCP state transitions include:

```text
SYN_SENT
SYN_RECV
ESTABLISHED
FIN_WAIT
RESET
```

The connection tracker uses bounded memory management:

* Configurable flow expiration through `flow-timeout`
* Maximum concurrent flow limit through `max-flows`
* Default maximum: **5,000 concurrent flows**
* Background cleanup of stale connections

---

# 5. Network Hygiene & Protocol Auditing

NetMonitor performs passive inspection of selected application-layer traffic to identify cleartext protocols and legacy name-resolution mechanisms.

## Cleartext Protocol Detection

### Telnet — Port 23

Detection may be based on:

* Telnet IAC command sequences (`0xFF`)
* Recognizable terminal/session text

### FTP — Port 21

Detection may use:

* FTP control commands such as `USER` and `PASS`
* Standard FTP response codes

### HTTP — Ports 80 / 8080

Detection may use:

* HTTP methods such as `GET` and `POST`
* HTTP response headers

### POP3 — Port 110

Identifies unencrypted POP3 email traffic.

### IMAP — Port 143

Identifies unencrypted IMAP email traffic.

---

## DNS Monitoring

NetMonitor decodes DNS queries transmitted over UDP port `53` and can log:

* Queried domain names
* DNS record types
* Transaction IDs

Common record types include:

```text
A
AAAA
PTR
```

---

## Legacy Name Resolution

The tool identifies legacy broadcast-based name-resolution traffic, including:

* **LLMNR — UDP 5355**
* **NetBIOS Name Service — UDP 137**

These protocols may be reviewed as part of network-hardening and security-audit activities.

---

# 🖥️ 6. Terminal User Interface

NetMonitor provides a high-contrast split-screen TUI built with `tview` and `tcell`.

### Security Event Panel

The upper section provides a real-time, auto-scrolling security event log.

Events are categorized by severity:

* 🔴 `ALERT`
* 🟡 `SUSPICIOUS`
* 🟢 `INFO`

### Interactive Data Panel

The lower section supports two views.

#### Mode A — Host Inventory

Displays information such as:

* IP address
* MAC address
* Hardware vendor
* Observed TTL
* Inferred OS
* Security status
* Active indicators

#### Mode B — Live Connection Tracker

Displays:

* Endpoint A
* Endpoint B
* Protocol
* Connection state
* Packet count
* Traffic volume
* Duration

Press **`t`** to switch between the two views.

Press **`?`** or **`h`** to open the About and keyboard-shortcuts dialog.

---

# ⚠️ Heuristic & Analytical Limitations

NetMonitor's detection mechanisms should be treated as **investigative indicators rather than definitive security findings**.

### TTL Is Not Proof of an Operating System

Initial TTL values can be modified by software and operating-system configuration.

For example, Linux systems may expose configurable IPv4 TTL settings, while tunneling technologies such as VPNs and IPsec can alter observed packet characteristics.

### MAC Randomization

Modern operating systems may use MAC-address randomization on Wi-Fi networks.

Therefore, OUI analysis identifies the organization associated with a MAC prefix; it does **not** guarantee the physical or logical identity of a device.

### Promiscuous Mode on Switched Networks

Promiscuous mode does not automatically provide visibility into every packet traversing a modern switched network.

A monitoring host will generally observe:

* Broadcast traffic
* Multicast traffic
* Traffic addressed to or from the monitoring host

For broader segment visibility, an authorized network administrator may configure:

* A SPAN / mirror port
* A network TAP
* Another appropriate monitoring architecture

---

# 📦 Requirements

NetMonitor requires:

* **Go 1.21+**
* **libpcap development libraries**
* Linux or macOS
* Appropriate privileges for raw packet capture

---

# 🛠️ Installation

## Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y golang-go libpcap-dev
```

## RHEL / Fedora / CentOS

```bash
sudo dnf install -y golang libpcap-devel
```

## Arch Linux

```bash
sudo pacman -S go libpcap
```

## macOS

Using Homebrew:

```bash
brew install go libpcap
```

---

# 🔨 Build & Test

Clone the repository:

```bash
git clone https://github.com/cys-dexter/NetMonitor.git
cd NetMonitor
```

Download and synchronize dependencies:

```bash
go mod tidy
```

Run the complete test suite:

```bash
go test -v ./...
```

Build the standalone binary:

```bash
go build -o netmonitor .
```

---

# 🚀 Running NetMonitor

Packet capture requires appropriate access to raw network interfaces.

## Option A — Run with sudo

List available network interfaces:

```bash
./netmonitor -l
```

Start monitoring on a specific interface:

```bash
sudo ./netmonitor -i eth0
```

Run with a BPF filter and debug logging:

```bash
sudo ./netmonitor \
  -i eth0 \
  -f "not port 22" \
  --log-level DEBUG \
  --log-file ./audit.log
```

---

## Option B — Linux Capabilities

On supported Linux systems, the binary can be granted the required capabilities instead of running the application as full root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./netmonitor
```

Then run:

```bash
./netmonitor -i eth0
```

Use the least-privilege approach appropriate for your environment and security policy.

---

# 🎛️ CLI Options

| Short | Long Flag      | Default          | Description                                                                               |
| ----- | -------------- | ---------------- | ----------------------------------------------------------------------------------------- |
| `-i`  | `--interface`  | Auto             | Network interface to monitor. Automatically selects an active default route when omitted. |
| `-l`  | `--list`       | `false`          | Lists discovered network interfaces and IP addresses, then exits.                         |
| `-f`  | `--filter`     | `""`             | Berkeley Packet Filter (BPF), e.g. `"tcp or udp"`.                                        |
| `-p`  | `--no-promisc` | `false`          | Disables promiscuous capture mode.                                                        |
| `-v`  | `--version`    | `false`          | Displays NetMonitor version and developer information.                                    |
| —     | `--log-file`   | `netmonitor.log` | Output path for structured JSON audit logs.                                               |
| —     | `--log-level`  | `INFO`           | Logging threshold: `DEBUG`, `INFO`, `WARN`, or `ERROR`.                                   |
| —     | `--max-flows`  | `5000`           | Maximum number of concurrent tracked flows.                                               |

---

# ⌨️ Keyboard Shortcuts

| Key            | Action                                                           |
| -------------- | ---------------------------------------------------------------- |
| `q` / `Ctrl+C` | Gracefully stop packet capture and exit NetMonitor.              |
| `t`            | Toggle between Host Inventory and Live Connection Tracker.       |
| `?` / `h`      | Open the About dialog and keyboard-shortcut guide.               |
| `c`            | Clear the event log and flush the security-event ring buffer.    |
| `Tab`          | Move focus between the Security Events panel and the data table. |
| `↑` / `↓`      | Navigate table rows or scroll through event history.             |

---

# 🔐 Security & Privacy Considerations

NetMonitor is intended for **authorized defensive monitoring and diagnostics**.

### Captured Data

The application may inspect network headers and limited unencrypted payload information when required for protocol identification.

Only monitor networks and systems for which you have appropriate authorization.

### Privilege Separation

Where supported, using Linux capabilities such as:

```text
cap_net_raw
cap_net_admin
```

can reduce the need to run the entire application as `root`.

### Log Protection

Structured audit logs may contain sensitive network metadata.

Protect log files with appropriate filesystem permissions, for example:

```bash
chmod 0600 netmonitor.log
```

Review organizational policies and applicable privacy requirements before deploying the tool in production environments.

---

## 📄 License

NetMonitor is released under the **MIT License**.

---

## 👨‍💻 Author

**Ahmad**

GitHub: [@cys-dexter](https://github.com/cys-dexter)

**NetMonitor — Defensive Network Visibility & Protocol Diagnostics**
