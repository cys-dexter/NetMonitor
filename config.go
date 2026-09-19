package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	AppVersion   = "1.0"
	AppDeveloper = "Ahmad"
	AppGitHub    = "cys-dexter"
	AppBranding  = "NetMonitor — Developed by Ahmad | GitHub: cys-dexter"

	AppBanner = `
  _   _      _   __  __             _ _             
 | \ | | ___| |_|  \/  | ___  _ __ (_) |_ ___  _ __ 
 |  \| |/ _ \ __| |\/| |/ _ \| '_ \| | __/ _ \| '__|
 | |\  |  __/ |_| |  | | (_) | | | | | || (_) | |   
 |_| \_|\___|\__|_|  |_|\___/|_| |_|_|\__\___/|_|   
 Defensive Network Monitoring & Protocol Diagnostics
 NetMonitor — Developed by Ahmad | GitHub: cys-dexter
`
)

// AppConfig contains runtime parameters for packet capture, filtering, logging, and UI.
type AppConfig struct {
	InterfaceName   string        `json:"interface_name"`
	BPFFilter       string        `json:"bpf_filter"`
	Promiscuous     bool          `json:"promiscuous"`
	SnapLen         int32         `json:"snap_len"`
	Timeout         time.Duration `json:"timeout"`
	MaxEvents       int           `json:"max_events"`
	MaxFlows        int           `json:"max_flows"`
	FlowTimeout     time.Duration `json:"flow_timeout"`
	RefreshInterval time.Duration `json:"refresh_interval"`
	LogFile         string        `json:"log_file"`
	LogLevel        string        `json:"log_level"`
	ListInterfaces  bool          `json:"list_interfaces"`
	ShowVersion     bool          `json:"show_version"`
}

// DefaultConfig returns an AppConfig populated with sensible production defaults.
func DefaultConfig() AppConfig {
	return AppConfig{
		InterfaceName:   "",
		BPFFilter:       "",
		Promiscuous:     true,
		SnapLen:         65535,
		Timeout:         100 * time.Millisecond,
		MaxEvents:       2000,
		MaxFlows:        5000,
		FlowTimeout:     30 * time.Second,
		RefreshInterval: 200 * time.Millisecond,
		LogFile:         "netmonitor.log",
		LogLevel:        "INFO",
	}
}

// ParseCLI parses command-line flags and returns an AppConfig or an error.
func ParseCLI(args []string) (AppConfig, error) {
	cfg := DefaultConfig()

	fs := flag.NewFlagSet("netmonitor", flag.ContinueOnError)

	fs.StringVar(&cfg.InterfaceName, "i", cfg.InterfaceName, "Network interface to monitor (e.g., eth0, wlan0)")
	fs.StringVar(&cfg.BPFFilter, "f", cfg.BPFFilter, "Berkeley Packet Filter string (e.g., 'tcp or udp')")
	var noPromisc bool
	fs.BoolVar(&noPromisc, "p", false, "Disable promiscuous capture mode")
	fs.BoolVar(&cfg.ListInterfaces, "l", false, "List discovered network interfaces and exit")
	fs.BoolVar(&cfg.ShowVersion, "v", false, "Display NetMonitor version and developer information")
	fs.StringVar(&cfg.LogFile, "log-file", cfg.LogFile, "Path to write structured audit logs")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level: DEBUG, INFO, WARN, ERROR")
	fs.IntVar(&cfg.MaxFlows, "max-flows", cfg.MaxFlows, "Maximum active network flows to track concurrently")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\nVersion: %s\nDeveloper: %s (GitHub: %s)\n\nUsage:\n",
			AppBanner, AppVersion, AppDeveloper, AppGitHub)
		fmt.Fprintf(os.Stderr, "  sudo ./netmonitor [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  sudo ./netmonitor -i eth0\n")
		fmt.Fprintf(os.Stderr, "  sudo ./netmonitor -i wlan0 -f \"not port 22\"\n")
		fmt.Fprintf(os.Stderr, "  sudo ./netmonitor -i eth0 --log-level DEBUG --log-file /var/log/netmonitor.log\n")
		fmt.Fprintf(os.Stderr, "  ./netmonitor -l\n\n")
	}

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	cfg.Promiscuous = !noPromisc

	return cfg, nil
}

// Validate ensures that the supplied configuration parameters are sane and consistent.
func (c *AppConfig) Validate() error {
	if c.ShowVersion || c.ListInterfaces {
		return nil
	}

	if c.SnapLen <= 0 {
		return errors.New("snap_len must be greater than 0")
	}

	if c.MaxEvents <= 0 {
		return errors.New("max_events must be greater than 0")
	}

	if c.MaxFlows <= 0 {
		return errors.New("max_flows must be greater than 0")
	}

	validLogLevels := map[string]bool{
		"DEBUG": true,
		"INFO":  true,
		"WARN":  true,
		"ERROR": true,
	}
	if !validLogLevels[strings.ToUpper(c.LogLevel)] {
		return fmt.Errorf("invalid log_level '%s': must be DEBUG, INFO, WARN, or ERROR", c.LogLevel)
	}

	return nil
}
