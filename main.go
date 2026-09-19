package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	cfg, err := ParseCLI(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Configuration error: %v\n", err)
		os.Exit(1)
	}

	if cfg.ShowVersion {
		fmt.Printf("NetMonitor v%s — Developed by %s (GitHub: %s)\n", AppVersion, AppDeveloper, AppGitHub)
		fmt.Println("Defensive Network Monitoring & Protocol Diagnostics Tool")
		os.Exit(0)
	}

	// Interface listing mode
	if cfg.ListInterfaces {
		summaries, err := GetInterfaceSummaries()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error discovering network interfaces: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("%s\nVersion: %s\nDeveloper: %s (GitHub: %s)\n\n", AppBanner, AppVersion, AppDeveloper, AppGitHub)
		fmt.Println("Available Network Interfaces:")
		fmt.Println("------------------------------------------------------------")
		for _, dev := range summaries {
			ipList := "No IPv4"
			if len(dev.IPv4Addrs) > 0 {
				ipList = strings.Join(dev.IPv4Addrs, ", ")
			}
			loopbackStr := ""
			if dev.IsLoopback {
				loopbackStr = " [Loopback]"
			}
			fmt.Printf("  • %-15s [%s]%s - %s\n", dev.Name, ipList, loopbackStr, dev.Description)
		}
		os.Exit(0)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// Check privileges
	if !CheckRawPrivileges() {
		fmt.Fprintf(os.Stderr, "\033[33m[!] Notice: NetMonitor requires root/SUDO privileges or CAP_NET_RAW capabilities for promiscuous packet capture.\033[0m\n")
		fmt.Fprintf(os.Stderr, "    Please run with: \033[1;37msudo ./netmonitor -i <interface>\033[0m\n\n")
	}

	// Initialize structured logger
	_, logCleanup, err := InitLogger(cfg.LogFile, cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Warning: Failed to initialize file logger: %v\n", err)
	} else {
		defer logCleanup()
	}

	slog.Info("NetMonitor initializing",
		"version", AppVersion,
		"developer", AppDeveloper,
		"github", AppGitHub,
	)

	// Determine interface
	if cfg.InterfaceName == "" {
		detected, err := FindDefaultInterface()
		if err != nil {
			slog.Error("Failed to automatically determine default network interface", "error", err)
			fmt.Fprintf(os.Stderr, "[-] Error: Failed to automatically determine active network interface: %v\n", err)
			fmt.Fprintf(os.Stderr, "    Please specify an interface explicitly using -i <interface> (see -l to list)\n")
			os.Exit(1)
		}
		cfg.InterfaceName = detected
		slog.Info("Auto-detected default network interface", "interface", cfg.InterfaceName)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS termination signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Initialize subsystems
	conntrack := NewConnectionTracker(cfg.MaxFlows, cfg.FlowTimeout)
	state := NewNetworkState(cfg.MaxEvents, conntrack)
	capture := NewCaptureEngine(cfg, state, conntrack)

	if err := capture.Start(ctx); err != nil {
		slog.Error("Packet capture failed to start", "interface", cfg.InterfaceName, "error", err)
		fmt.Fprintf(os.Stderr, "[-] Error starting packet capture on interface '%s': %v\n", cfg.InterfaceName, err)
		fmt.Fprintf(os.Stderr, "    Ensure you have sudo/root privileges and that interface '%s' exists.\n", cfg.InterfaceName)
		os.Exit(1)
	}
	defer capture.Stop()

	// Initialize and run TUI
	ui := NewUI(cfg, state, conntrack)

	go func() {
		sig := <-sigChan
		slog.Info("Shutdown signal received, initiating graceful exit", "signal", sig.String())
		cancel()
		ui.Stop()
	}()

	if err := ui.Run(ctx); err != nil {
		slog.Error("TUI execution encountered an error", "error", err)
		fmt.Fprintf(os.Stderr, "[-] TUI execution error: %v\n", err)
		os.Exit(1)
	}

	slog.Info("NetMonitor exited cleanly")
	fmt.Println("[+] NetMonitor exited cleanly.")
}
