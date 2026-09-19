package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// OUIVendor stores vendor metadata associated with an Organizationally Unique Identifier.
type OUIVendor struct {
	Name     string `json:"name"`
	Category string `json:"category"` // "workstation", "server", "network_gear", "mobile_iot", "virtual_machine", "general"
}

// DeviceInfo represents complete network host metadata including threat/suspicious analysis.
type DeviceInfo struct {
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Vendor      string `json:"vendor"`
	Category    string `json:"category"`
	TTL         int    `json:"ttl"`
	OSGuess     string `json:"os_guess"`
	IsSuspicious bool  `json:"is_suspicious"`
	Reason      string `json:"suspicious_reason,omitempty"`
}

// Mutex for safe concurrent writes/reads to ouiDatabase
var ouiMutex sync.RWMutex

// ouiDatabase provides a static lookup table mapping 24-bit OUI prefixes to manufacturer metadata.
var ouiDatabase = map[string]OUIVendor{
	// Apple, Inc.
	"00:03:93": {Name: "Apple, Inc.", Category: "workstation"},
	"00:05:02": {Name: "Apple, Inc.", Category: "workstation"},
	"00:0a:95": {Name: "Apple, Inc.", Category: "workstation"},
	"00:0d:93": {Name: "Apple, Inc.", Category: "workstation"},
	"00:10:fa": {Name: "Apple, Inc.", Category: "workstation"},
	"00:11:24": {Name: "Apple, Inc.", Category: "workstation"},
	"00:14:51": {Name: "Apple, Inc.", Category: "workstation"},
	"00:16:cb": {Name: "Apple, Inc.", Category: "workstation"},
	"00:17:f2": {Name: "Apple, Inc.", Category: "workstation"},
	"00:19:e3": {Name: "Apple, Inc.", Category: "workstation"},
	"00:1b:63": {Name: "Apple, Inc.", Category: "workstation"},
	"00:1c:b3": {Name: "Apple, Inc.", Category: "workstation"},
	"00:1d:4f": {Name: "Apple, Inc.", Category: "workstation"},
	"00:1e:52": {Name: "Apple, Inc.", Category: "workstation"},
	"00:1e:c2": {Name: "Apple, Inc.", Category: "workstation"},
	"00:1f:5b": {Name: "Apple, Inc.", Category: "workstation"},
	"00:1f:f3": {Name: "Apple, Inc.", Category: "workstation"},
	"00:21:e9": {Name: "Apple, Inc.", Category: "workstation"},
	"00:22:41": {Name: "Apple, Inc.", Category: "workstation"},
	"00:23:12": {Name: "Apple, Inc.", Category: "workstation"},
	"00:23:32": {Name: "Apple, Inc.", Category: "workstation"},
	"00:23:6c": {Name: "Apple, Inc.", Category: "workstation"},
	"00:24:36": {Name: "Apple, Inc.", Category: "workstation"},
	"00:25:00": {Name: "Apple, Inc.", Category: "workstation"},
	"00:25:4b": {Name: "Apple, Inc.", Category: "workstation"},
	"00:25:bc": {Name: "Apple, Inc.", Category: "workstation"},
	"00:26:08": {Name: "Apple, Inc.", Category: "workstation"},
	"00:26:4a": {Name: "Apple, Inc.", Category: "workstation"},
	"00:26:bb": {Name: "Apple, Inc.", Category: "workstation"},
	"3c:07:54": {Name: "Apple, Inc.", Category: "workstation"},
	"a4:83:e7": {Name: "Apple, Inc.", Category: "workstation"},
	"ac:bc:32": {Name: "Apple, Inc.", Category: "workstation"},
	"bc:d1:1f": {Name: "Apple, Inc.", Category: "workstation"},
	"f0:18:98": {Name: "Apple, Inc.", Category: "workstation"},
	"f0:98:9d": {Name: "Apple, Inc.", Category: "workstation"},
	"f4:5c:89": {Name: "Apple, Inc.", Category: "workstation"},
	"f8:ff:c2": {Name: "Apple, Inc.", Category: "workstation"},

	// Microsoft Corp.
	"00:03:ff": {Name: "Microsoft Corporation", Category: "workstation"},
	"00:0d:3a": {Name: "Microsoft Corporation", Category: "workstation"},
	"00:12:5a": {Name: "Microsoft Corporation", Category: "workstation"},
	"00:15:5d": {Name: "Microsoft Hyper-V", Category: "virtual_machine"},
	"00:1d:d8": {Name: "Microsoft Corporation", Category: "workstation"},
	"00:50:f2": {Name: "Microsoft Corporation", Category: "workstation"},
	"28:18:78": {Name: "Microsoft Corporation", Category: "workstation"},
	"7c:1e:52": {Name: "Microsoft Surface", Category: "workstation"},
	"dc:b4:c4": {Name: "Microsoft Corporation", Category: "workstation"},

	// Cisco Systems
	"00:00:0c": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:01:42": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:01:43": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:01:63": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:01:64": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:01:96": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:01:97": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:01:c7": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:01:c9": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:02:16": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:02:17": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:02:4a": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:02:4b": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:02:7d": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:02:7e": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:05:31": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:05:32": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:05:5e": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:05:5f": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:07:0d": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:07:0e": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:0b:be": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:0b:bf": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:0c:30": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:0c:31": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:0c:85": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:11:20": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:12:00": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:1a:a1": {Name: "Cisco Systems, Inc.", Category: "network_gear"},
	"00:24:c4": {Name: "Cisco Systems, Inc.", Category: "network_gear"},

	// Intel Corporation
	"00:02:b3": {Name: "Intel Corporation", Category: "workstation"},
	"00:03:47": {Name: "Intel Corporation", Category: "workstation"},
	"00:04:23": {Name: "Intel Corporation", Category: "workstation"},
	"00:07:e9": {Name: "Intel Corporation", Category: "workstation"},
	"00:0e:0c": {Name: "Intel Corporation", Category: "workstation"},
	"00:0e:35": {Name: "Intel Corporation", Category: "workstation"},
	"00:11:11": {Name: "Intel Corporation", Category: "workstation"},
	"00:13:02": {Name: "Intel Corporation", Category: "workstation"},
	"00:15:00": {Name: "Intel Corporation", Category: "workstation"},
	"00:16:6f": {Name: "Intel Corporation", Category: "workstation"},
	"00:1b:21": {Name: "Intel Corporation", Category: "workstation"},
	"00:1c:c0": {Name: "Intel Corporation", Category: "workstation"},
	"00:21:5c": {Name: "Intel Corporation", Category: "workstation"},
	"34:13:e8": {Name: "Intel Corporation", Category: "workstation"},
	"48:51:b7": {Name: "Intel Corporation", Category: "workstation"},
	"68:05:ca": {Name: "Intel Corporation", Category: "workstation"},
	"84:3a:4b": {Name: "Intel Corporation", Category: "workstation"},
	"a4:4c:c8": {Name: "Intel Corporation", Category: "workstation"},
	"c8:5b:76": {Name: "Intel Corporation", Category: "workstation"},

	// Dell Inc.
	"00:06:5b": {Name: "Dell Inc.", Category: "workstation"},
	"00:08:74": {Name: "Dell Inc.", Category: "workstation"},
	"00:0b:db": {Name: "Dell Inc.", Category: "workstation"},
	"00:0d:56": {Name: "Dell Inc.", Category: "workstation"},
	"00:11:43": {Name: "Dell Inc.", Category: "workstation"},
	"00:14:22": {Name: "Dell Inc.", Category: "workstation"},
	"00:15:c5": {Name: "Dell Inc.", Category: "workstation"},
	"00:18:8b": {Name: "Dell Inc.", Category: "workstation"},
	"00:19:b9": {Name: "Dell Inc.", Category: "workstation"},
	"00:1c:23": {Name: "Dell Inc.", Category: "workstation"},
	"00:21:70": {Name: "Dell Inc.", Category: "workstation"},
	"18:03:73": {Name: "Dell Inc.", Category: "workstation"},
	"24:b6:fd": {Name: "Dell Inc.", Category: "workstation"},
	"34:17:eb": {Name: "Dell Inc.", Category: "workstation"},
	"44:a8:42": {Name: "Dell Inc.", Category: "workstation"},
	"74:86:7a": {Name: "Dell Inc.", Category: "workstation"},
	"84:2b:2b": {Name: "Dell Inc.", Category: "workstation"},
	"b8:2a:72": {Name: "Dell Inc.", Category: "workstation"},

	// Hewlett Packard (HP)
	"00:01:e6": {Name: "HP Inc.", Category: "workstation"},
	"00:08:02": {Name: "HP Inc.", Category: "workstation"},
	"00:0e:7f": {Name: "HP Inc.", Category: "workstation"},
	"00:11:0a": {Name: "HP Inc.", Category: "workstation"},
	"00:14:c2": {Name: "HP Inc.", Category: "workstation"},
	"00:17:08": {Name: "HP Inc.", Category: "workstation"},
	"00:18:71": {Name: "HP Inc.", Category: "workstation"},
	"00:1a:4b": {Name: "HP Inc.", Category: "workstation"},
	"00:21:5a": {Name: "HP Inc.", Category: "workstation"},
	"10:1f:74": {Name: "HP Inc.", Category: "workstation"},
	"14:58:d0": {Name: "HP Inc.", Category: "workstation"},
	"3c:d9:2b": {Name: "HP Inc.", Category: "workstation"},
	"78:e7:d1": {Name: "HP Inc.", Category: "workstation"},
	"a0:d3:c1": {Name: "HP Inc.", Category: "workstation"},

	// Raspberry Pi Foundation
	"b8:27:eb": {Name: "Raspberry Pi Foundation", Category: "workstation"},
	"dc:a6:32": {Name: "Raspberry Pi Foundation", Category: "workstation"},
	"e4:5f:01": {Name: "Raspberry Pi Foundation", Category: "workstation"},
	"28:cd:c1": {Name: "Raspberry Pi Foundation", Category: "workstation"},

	// Virtual Machines / Hypervisors
	"00:05:69": {Name: "VMware, Inc.", Category: "virtual_machine"},
	"00:0c:29": {Name: "VMware, Inc.", Category: "virtual_machine"},
	"00:1c:14": {Name: "VMware, Inc.", Category: "virtual_machine"},
	"00:50:56": {Name: "VMware, Inc.", Category: "virtual_machine"},
	"08:00:27": {Name: "Oracle VirtualBox", Category: "virtual_machine"},
	"0a:00:27": {Name: "Oracle VirtualBox", Category: "virtual_machine"},
	"52:54:00": {Name: "QEMU / KVM Virtual NIC", Category: "virtual_machine"},

	// Google LLC
	"00:1a:11": {Name: "Google LLC", Category: "server"},
	"3c:5a:37": {Name: "Google LLC", Category: "mobile_iot"},
	"54:60:09": {Name: "Google LLC", Category: "mobile_iot"},
	"70:ee:50": {Name: "Google LLC", Category: "mobile_iot"},
	"94:eb:cd": {Name: "Google LLC", Category: "mobile_iot"},
	"a4:77:33": {Name: "Google LLC", Category: "mobile_iot"},
	"d8:6c:63": {Name: "Google LLC", Category: "mobile_iot"},
	"f4:03:04": {Name: "Google LLC", Category: "mobile_iot"},

	// Samsung Electronics
	"00:00:f0": {Name: "Samsung Electronics", Category: "mobile_iot"},
	"00:07:ab": {Name: "Samsung Electronics", Category: "mobile_iot"},
	"00:12:47": {Name: "Samsung Electronics", Category: "mobile_iot"},
	"00:16:6b": {Name: "Samsung Electronics", Category: "mobile_iot"},
	"00:21:19": {Name: "Samsung Electronics", Category: "mobile_iot"},
	"08:fc:88": {Name: "Samsung Electronics", Category: "mobile_iot"},
	"24:4b:03": {Name: "Samsung Electronics", Category: "mobile_iot"},
	"38:0b:40": {Name: "Samsung Electronics", Category: "mobile_iot"},
	"50:01:d9": {Name: "Samsung Electronics", Category: "mobile_iot"},
	"84:25:db": {Name: "Samsung Electronics", Category: "mobile_iot"},
	"a0:82:1f": {Name: "Samsung Electronics", Category: "mobile_iot"},
	"cc:07:ab": {Name: "Samsung Electronics", Category: "mobile_iot"},
	"e4:7c:f9": {Name: "Samsung Electronics", Category: "mobile_iot"},

	// Espressif Systems (ESP8266/ESP32 IoT devices)
	"18:fe:34": {Name: "Espressif Systems", Category: "mobile_iot"},
	"24:0a:c4": {Name: "Espressif Systems", Category: "mobile_iot"},
	"24:6f:28": {Name: "Espressif Systems", Category: "mobile_iot"},
	"2c:3a:e8": {Name: "Espressif Systems", Category: "mobile_iot"},
	"30:ae:a4": {Name: "Espressif Systems", Category: "mobile_iot"},
	"3c:61:05": {Name: "Espressif Systems", Category: "mobile_iot"},
	"3c:71:bf": {Name: "Espressif Systems", Category: "mobile_iot"},
	"4c:11:ae": {Name: "Espressif Systems", Category: "mobile_iot"},
	"54:5a:a6": {Name: "Espressif Systems", Category: "mobile_iot"},
	"68:c6:3a": {Name: "Espressif Systems", Category: "mobile_iot"},
	"84:0d:8e": {Name: "Espressif Systems", Category: "mobile_iot"},
	"84:f3:eb": {Name: "Espressif Systems", Category: "mobile_iot"},
	"a4:cf:12": {Name: "Espressif Systems", Category: "mobile_iot"},
	"bc:dd:c2": {Name: "Espressif Systems", Category: "mobile_iot"},

	// TP-Link Technologies
	"00:0a:eb": {Name: "TP-Link Corporation", Category: "network_gear"},
	"00:14:78": {Name: "TP-Link Corporation", Category: "network_gear"},
	"00:19:e0": {Name: "TP-Link Corporation", Category: "network_gear"},
	"00:21:27": {Name: "TP-Link Corporation", Category: "network_gear"},
	"14:cf:92": {Name: "TP-Link Corporation", Category: "network_gear"},
	"1c:3b:f3": {Name: "TP-Link Corporation", Category: "network_gear"},
	"30:de:4b": {Name: "TP-Link Corporation", Category: "network_gear"},
	"50:c7:bf": {Name: "TP-Link Corporation", Category: "network_gear"},
	"74:05:a5": {Name: "TP-Link Corporation", Category: "network_gear"},
	"90:f6:52": {Name: "TP-Link Corporation", Category: "network_gear"},
	"b0:4e:26": {Name: "TP-Link Corporation", Category: "network_gear"},
	"c0:25:e9": {Name: "TP-Link Corporation", Category: "network_gear"},
	"ec:08:6b": {Name: "TP-Link Corporation", Category: "network_gear"},

	// Netgear
	"00:09:5b": {Name: "Netgear Inc.", Category: "network_gear"},
	"00:0f:b5": {Name: "Netgear Inc.", Category: "network_gear"},
	"00:14:6c": {Name: "Netgear Inc.", Category: "network_gear"},
	"00:18:4d": {Name: "Netgear Inc.", Category: "network_gear"},
	"00:1b:2f": {Name: "Netgear Inc.", Category: "network_gear"},
	"00:1e:2a": {Name: "Netgear Inc.", Category: "network_gear"},
	"00:24:b2": {Name: "Netgear Inc.", Category: "network_gear"},
	"10:da:43": {Name: "Netgear Inc.", Category: "network_gear"},
	"20:4e:7f": {Name: "Netgear Inc.", Category: "network_gear"},
	"44:94:fc": {Name: "Netgear Inc.", Category: "network_gear"},
	"84:1b:5e": {Name: "Netgear Inc.", Category: "network_gear"},
	"9c:3d:cf": {Name: "Netgear Inc.", Category: "network_gear"},
	"c0:3f:0e": {Name: "Netgear Inc.", Category: "network_gear"},

	// Ubiquiti Networks
	"00:15:6d": {Name: "Ubiquiti Inc.", Category: "network_gear"},
	"00:27:22": {Name: "Ubiquiti Inc.", Category: "network_gear"},
	"04:18:d6": {Name: "Ubiquiti Inc.", Category: "network_gear"},
	"18:e8:29": {Name: "Ubiquiti Inc.", Category: "network_gear"},
	"24:a4:3c": {Name: "Ubiquiti Inc.", Category: "network_gear"},
	"44:d9:e7": {Name: "Ubiquiti Inc.", Category: "network_gear"},
	"68:72:51": {Name: "Ubiquiti Inc.", Category: "network_gear"},
	"70:a7:41": {Name: "Ubiquiti Inc.", Category: "network_gear"},
	"74:83:c2": {Name: "Ubiquiti Inc.", Category: "network_gear"},
	"78:8a:20": {Name: "Ubiquiti Inc.", Category: "network_gear"},
	"b4:fb:e4": {Name: "Ubiquiti Inc.", Category: "network_gear"},
	"dc:9f:db": {Name: "Ubiquiti Inc.", Category: "network_gear"},
	"e0:63:da": {Name: "Ubiquiti Inc.", Category: "network_gear"},

	// Huawei Technologies
	"00:18:82": {Name: "Huawei Technologies", Category: "network_gear"},
	"00:1e:10": {Name: "Huawei Technologies", Category: "network_gear"},
	"00:25:68": {Name: "Huawei Technologies", Category: "network_gear"},
	"04:25:c5": {Name: "Huawei Technologies", Category: "network_gear"},
	"10:47:80": {Name: "Huawei Technologies", Category: "network_gear"},
	"20:0b:c7": {Name: "Huawei Technologies", Category: "network_gear"},
	"48:46:fb": {Name: "Huawei Technologies", Category: "network_gear"},
	"70:72:3c": {Name: "Huawei Technologies", Category: "network_gear"},
	"ac:85:3d": {Name: "Huawei Technologies", Category: "network_gear"},
	"cc:96:e5": {Name: "Huawei Technologies", Category: "network_gear"},

	// Arista Networks
	"00:1c:73": {Name: "Arista Networks", Category: "network_gear"},
	"28:99:3a": {Name: "Arista Networks", Category: "network_gear"},
	"44:4c:a8": {Name: "Arista Networks", Category: "network_gear"},
	"74:83:ef": {Name: "Arista Networks", Category: "network_gear"},

	// Amazon Technologies
	"00:fc:8b": {Name: "Amazon Technologies", Category: "mobile_iot"},
	"0c:47:c9": {Name: "Amazon Technologies", Category: "mobile_iot"},
	"18:74:2e": {Name: "Amazon Technologies", Category: "mobile_iot"},
	"34:d2:70": {Name: "Amazon Technologies", Category: "mobile_iot"},
	"40:b4:cd": {Name: "Amazon Technologies", Category: "mobile_iot"},
	"50:dc:e7": {Name: "Amazon Technologies", Category: "mobile_iot"},
	"68:54:fd": {Name: "Amazon Technologies", Category: "mobile_iot"},
	"74:75:48": {Name: "Amazon Technologies", Category: "mobile_iot"},
	"ac:63:be": {Name: "Amazon Technologies", Category: "mobile_iot"},
	"fc:65:de": {Name: "Amazon Technologies", Category: "mobile_iot"},
}

// LookupVendor extracts the 24-bit OUI prefix from a HardwareAddr and returns the identified vendor and category.
func LookupVendor(mac net.HardwareAddr) (string, string) {
	if len(mac) < 3 {
		return "Unknown Vendor", "unknown"
	}

	// Layer 2 Broadcast MAC
	if mac.String() == "ff:ff:ff:ff:ff:ff" {
		return "Broadcast / Layer 2 Flooding", "network_gear"
	}

	// Multicast prefix checks
	if mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x5e {
		return "IPv4 Multicast Group", "network_gear"
	}
	if mac[0] == 0x33 && mac[1] == 0x33 {
		return "IPv6 Multicast Group", "network_gear"
	}

	// Format OUI prefix as aa:bb:cc (lowercase)
	prefix := fmt.Sprintf("%02x:%02x:%02x", mac[0], mac[1], mac[2])

	// Safe read from database
	ouiMutex.RLock()
	vendor, found := ouiDatabase[strings.ToLower(prefix)]
	ouiMutex.RUnlock()

	if found {
		return vendor.Name, vendor.Category
	}

	// Check if this is a locally administered / randomized address (bit 1 of 1st byte set: x2, x6, xA, xE)
	if (mac[0] & 0x02) != 0 {
		return "Randomized / Locally Administered MAC", "workstation"
	}

	return "Unknown Vendor (Unregistered OUI)", "unknown"
}

// LookupVendorByString allows lookup using a raw string MAC address.
func LookupVendorByString(macStr string) (string, string, error) {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return "Invalid MAC Address", "unknown", err
	}
	vendor, category := LookupVendor(mac)
	return vendor, category, nil
}

// AddVendor dynamically registers or overrides an OUI in the database during runtime.
func AddVendor(ouiPrefix string, name string, category string) {
	formatted := strings.ToLower(strings.ReplaceAll(ouiPrefix, "-", ":"))
	if len(formatted) > 8 {
		formatted = formatted[:8]
	}

	ouiMutex.Lock()
	ouiDatabase[formatted] = OUIVendor{
		Name:     name,
		Category: category,
	}
	ouiMutex.Unlock()
}

// PredictOSByTTL guesses system type based on Time To Live (TTL) values.
func PredictOSByTTL(ttl int) string {
	switch {
	case ttl <= 0:
		return "Unknown"
	case ttl <= 64:
		return "Linux / Android / iOS / MacOS"
	case ttl <= 128:
		return "Windows OS"
	case ttl <= 255:
		return "Cisco / Network Router / Unix"
	default:
		return "Custom Embedded / Unknown"
	}
}

// AnalyzeDevice evaluates MAC, IP, TTL, and Category to detect suspicious behavior.
func AnalyzeDevice(ipStr, macStr string, ttl int) DeviceInfo {
	vendor, category, err := LookupVendorByString(macStr)
	if err != nil {
		return DeviceInfo{
			IP:           ipStr,
			MAC:          macStr,
			Vendor:       "Invalid MAC",
			Category:     "unknown",
			TTL:          ttl,
			OSGuess:      "Unknown",
			IsSuspicious: true,
			Reason:       "Malformed or invalid MAC format",
		}
	}

	osGuess := PredictOSByTTL(ttl)
	isSuspicious := false
	reasons := []string{}

	// Suspicious Check 1: Spoofed or Randomized MAC Address
	if strings.Contains(vendor, "Randomized") {
		isSuspicious = true
		reasons = append(reasons, "Randomized/Locally-Administered MAC (Possible MAC Spoofing)")
	}

	// Suspicious Check 2: Unregistered / Unknown Vendor
	if strings.Contains(vendor, "Unknown Vendor") {
		isSuspicious = true
		reasons = append(reasons, "Unregistered OUI Vendor Prefix")
	}

	// Suspicious Check 3: TTL Mismatch (e.g. Windows vendor with Linux TTL)
	if strings.Contains(vendor, "Microsoft") && ttl <= 64 {
		isSuspicious = true
		reasons = append(reasons, "TTL Mismatch: Microsoft OUI with Linux/Unix TTL Signature")
	}

	return DeviceInfo{
		IP:           ipStr,
		MAC:          macStr,
		Vendor:       vendor,
		Category:     category,
		TTL:          ttl,
		OSGuess:      osGuess,
		IsSuspicious: isSuspicious,
		Reason:       strings.Join(reasons, " | "),
	}
}

// PrintDeviceTable outputs device details into a clean CLI dashboard.
func PrintDeviceTable(devices []DeviceInfo) {
	fmt.Println("\n=========================================================================================================")
	fmt.Printf("%-15s | %-17s | %-24s | %-12s | %-4s | %-10s\n", "IP Address", "MAC Address", "Vendor / Manufacturer", "Category", "TTL", "Status")
	fmt.Println("---------------------------------------------------------------------------------------------------------")

	for _, d := range devices {
		status := "🟢 OK"
		if d.IsSuspicious {
			status = "⚠️ [SUSPICIOUS]"
		}
		fmt.Printf("%-15s | %-17s | %-24s | %-12s | %-4d | %-10s\n", d.IP, d.MAC, truncate(d.Vendor, 24), d.Category, d.TTL, status)
		if d.IsSuspicious {
			fmt.Printf("   └── 🚩 Reason: %s\n", d.Reason)
		}
	}
	fmt.Println("=========================================================================================================\n")
}

func truncate(str string, maxLen int) string {
	if len(str) > maxLen {
		return str[:maxLen-3] + "..."
	}
	return str
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	// Sample network dataset to simulate discovery
	sampleNetwork := []DeviceInfo{
		AnalyzeDevice("192.168.1.1", "00:00:0c:11:22:33", 255),  // Cisco Router
		AnalyzeDevice("192.168.1.10", "00:03:93:aa:bb:cc", 64),   // Apple Mac
		AnalyzeDevice("192.168.1.15", "00:15:5d:01:02:03", 128),  // Hyper-V VM
		AnalyzeDevice("192.168.1.50", "02:11:22:33:44:55", 64),   // Randomized MAC (Suspicious)
		AnalyzeDevice("192.168.1.99", "00:0d:3a:44:55:66", 64),   // Microsoft OUI with Linux TTL (Suspicious Mismatch)
		AnalyzeDevice("192.168.1.100", "e4:5f:01:aa:bb:cc", 64),  // Raspberry Pi
	}

	for {
		fmt.Println("==============================================")
		fmt.Println("    NETWORK DEVICE ANALYZER & OUI SCANNER    ")
		fmt.Println("==============================================")
		fmt.Println("1. Show Sample Network Scan (IP, MAC, TTL, Threat Check)")
		fmt.Println("2. Analyze Single MAC Address")
		fmt.Println("3. Analyze Manual Network Device (IP + MAC + TTL)")
		fmt.Println("4. Add New Vendor to OUI Database")
		fmt.Println("5. Export Sample Scan to JSON")
		fmt.Println("0. Exit (إغلاق / خروج)")
		fmt.Println("==============================================")
		fmt.Print("Choose an option: ")

		if !scanner.Scan() {
			break
		}
		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			PrintDeviceTable(sampleNetwork)

		case "2":
			fmt.Print("Enter MAC Address (e.g. 00:11:22:33:44:55): ")
			scanner.Scan()
			macInput := strings.TrimSpace(scanner.Text())
			vendor, category, err := LookupVendorByString(macInput)
			if err != nil {
				fmt.Printf("Error: %v\n\n", err)
			} else {
				fmt.Printf("\nResult: Vendor = %s | Category = %s\n\n", vendor, category)
			}

		case "3":
			fmt.Print("Enter IP Address: ")
			scanner.Scan()
			ip := strings.TrimSpace(scanner.Text())

			fmt.Print("Enter MAC Address: ")
			scanner.Scan()
			mac := strings.TrimSpace(scanner.Text())

			fmt.Print("Enter TTL Value (e.g. 64, 128, 255): ")
			scanner.Scan()
			var ttl int
			fmt.Sscanf(scanner.Text(), "%d", &ttl)

			dev := AnalyzeDevice(ip, mac, ttl)
			PrintDeviceTable([]DeviceInfo{dev})

		case "4":
			fmt.Print("Enter OUI Prefix (e.g. AA:BB:CC): ")
			scanner.Scan()
			oui := strings.TrimSpace(scanner.Text())

			fmt.Print("Enter Vendor Name: ")
			scanner.Scan()
			vName := strings.TrimSpace(scanner.Text())

			fmt.Print("Enter Category (workstation/server/network_gear/mobile_iot/virtual_machine): ")
			scanner.Scan()
			cat := strings.TrimSpace(scanner.Text())

			AddVendor(oui, vName, cat)
			fmt.Println("Successfully added vendor to OUI database!\n")

		case "5":
			jsonData, err := json.MarshalIndent(sampleNetwork, "", "  ")
			if err != nil {
				fmt.Printf("Failed to export: %v\n", err)
			} else {
				fmt.Println("\n--- JSON EXPORT ---")
				fmt.Println(string(jsonData))
				fmt.Println("-------------------\n")
			}

		case "0", "q", "exit", "خروج":
			fmt.Println("\nExiting application... Goodbye!")
			os.Exit(0)

		default:
			fmt.Println("\nInvalid option! Please try again.\n")
		}
	}
}
