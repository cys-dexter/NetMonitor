package main

import (
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Promiscuous {
		t.Errorf("expected DefaultConfig promiscuous to be true, got false")
	}
	if cfg.SnapLen != 65535 {
		t.Errorf("expected snap_len 65535, got %d", cfg.SnapLen)
	}
	if cfg.MaxEvents != 2000 {
		t.Errorf("expected max_events 2000, got %d", cfg.MaxEvents)
	}
	if cfg.MaxFlows != 5000 {
		t.Errorf("expected max_flows 5000, got %d", cfg.MaxFlows)
	}
	if cfg.LogLevel != "INFO" {
		t.Errorf("expected default log_level INFO, got %s", cfg.LogLevel)
	}
}

func TestDeveloperIdentity(t *testing.T) {
	if AppDeveloper != "Ahmad" {
		t.Errorf("expected AppDeveloper to be 'Ahmad', got '%s'", AppDeveloper)
	}
	if AppGitHub != "Dexter-cys" {
		t.Errorf("expected AppGitHub to be 'Dexter-cys', got '%s'", AppGitHub)
	}
	if !strings.Contains(AppBranding, "Ahmad") || !strings.Contains(AppBranding, "Dexter-cys") {
		t.Errorf("expected AppBranding to contain developer and GitHub, got '%s'", AppBranding)
	}
}

func TestParseCLI(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedIf  string
		expectedBPF string
		noPromisc   bool
		logLevel    string
		showVer     bool
	}{
		{
			name:        "Custom interface and filter",
			args:        []string{"-i", "eth1", "-f", "tcp and port 80", "-log-level", "DEBUG"},
			expectedIf:  "eth1",
			expectedBPF: "tcp and port 80",
			noPromisc:   false,
			logLevel:    "DEBUG",
		},
		{
			name:       "Non-promiscuous flag",
			args:       []string{"-i", "wlan0", "-p"},
			expectedIf: "wlan0",
			noPromisc:  true,
			logLevel:   "INFO",
		},
		{
			name:    "Version flag",
			args:    []string{"-v"},
			showVer: true,
			logLevel: "INFO",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseCLI(tt.args)
			if err != nil {
				t.Fatalf("unexpected error parsing CLI args: %v", err)
			}
			if tt.showVer && !cfg.ShowVersion {
				t.Errorf("expected ShowVersion=true")
			}
			if tt.expectedIf != "" && cfg.InterfaceName != tt.expectedIf {
				t.Errorf("expected interface %s, got %s", tt.expectedIf, cfg.InterfaceName)
			}
			if tt.expectedBPF != "" && cfg.BPFFilter != tt.expectedBPF {
				t.Errorf("expected BPF %s, got %s", tt.expectedBPF, cfg.BPFFilter)
			}
			if tt.noPromisc && cfg.Promiscuous {
				t.Errorf("expected promiscuous false, got true")
			}
			if cfg.LogLevel != tt.logLevel {
				t.Errorf("expected log level %s, got %s", tt.logLevel, cfg.LogLevel)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config failed validation: %v", err)
	}

	// Negative SnapLen
	invalidCfg := cfg
	invalidCfg.SnapLen = 0
	if err := invalidCfg.Validate(); err == nil {
		t.Errorf("expected error for snap_len <= 0, got nil")
	}

	// Negative MaxEvents
	invalidCfg = cfg
	invalidCfg.MaxEvents = -10
	if err := invalidCfg.Validate(); err == nil {
		t.Errorf("expected error for max_events <= 0, got nil")
	}

	// Negative MaxFlows
	invalidCfg = cfg
	invalidCfg.MaxFlows = 0
	if err := invalidCfg.Validate(); err == nil {
		t.Errorf("expected error for max_flows <= 0, got nil")
	}

	// Invalid LogLevel
	invalidCfg = cfg
	invalidCfg.LogLevel = "VERBOSE_UNKNOWN"
	if err := invalidCfg.Validate(); err == nil {
		t.Errorf("expected error for invalid log level, got nil")
	}
}
