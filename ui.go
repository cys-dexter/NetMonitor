package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// BottomViewMode toggles between the host inventory and live connection flows.
type BottomViewMode int

const (
	ViewModeHosts BottomViewMode = iota
	ViewModeFlows
)

// UI manages the terminal user interface, dynamic panes, and periodic redraw cycles.
type UI struct {
	app                 *tview.Application
	state               *NetworkState
	conntrack           *ConnectionTracker
	cfg                 AppConfig
	headerView          *tview.TextView
	eventLogView        *tview.TextView
	bottomTableView     *tview.Table
	footerView          *tview.TextView
	mainFlex            *tview.Flex
	pages               *tview.Pages
	viewMode            BottomViewMode
	lastRenderedEventID int64
	mu                  sync.Mutex
	stopChan            chan struct{}
}

// NewUI initializes the split-screen TUI with tabbed views and developer identity.
func NewUI(cfg AppConfig, state *NetworkState, conntrack *ConnectionTracker) *UI {
	app := tview.NewApplication()
	pages := tview.NewPages()

	ui := &UI{
		app:       app,
		pages:     pages,
		state:     state,
		conntrack: conntrack,
		cfg:       cfg,
		viewMode:  ViewModeHosts,
		stopChan:  make(chan struct{}),
	}

	ui.initViews()
	return ui
}

// initViews constructs and arranges the UI components.
func (ui *UI) initViews() {
	// 1. Header Banner
	ui.headerView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	ui.headerView.SetBorder(false)

	// 2. Security Events & Compliance Log Panel
	ui.eventLogView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWordWrap(true)
	ui.eventLogView.SetBorder(true).
		SetTitle(" [white]🛡️  [bold#00ffff]SECURITY EVENTS & COMPLIANCE LOGS[-] ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(tcell.ColorDarkCyan)

	// 3. Bottom Dual-Mode Table
	ui.bottomTableView = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0)
	ui.bottomTableView.SetBorder(true).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(tcell.ColorDarkCyan)

	ui.renderTableHeaders()

	// 4. Footer View (with clean, professional developer attribution)
	ui.footerView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	ui.footerView.SetText(fmt.Sprintf(
		" [yellow][q][white] Quit | [yellow][t][white] Toggle View | [yellow][c][white] Clear Logs | [yellow][?][white] About | [gray]%s[-]",
		AppBranding,
	))

	// Split-Screen Layout
	ui.mainFlex = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(ui.headerView, 2, 0, false).
		AddItem(ui.eventLogView, 0, 1, false).
		AddItem(ui.bottomTableView, 0, 1, true).
		AddItem(ui.footerView, 1, 0, false)

	ui.pages.AddPage("main", ui.mainFlex, true, true)

	// Global Keybindings
	ui.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		// If modal is active, let it handle keys
		if ui.pages.HasPage("about") {
			if event.Key() == tcell.KeyEscape || event.Rune() == 'q' || event.Key() == tcell.KeyEnter {
				ui.pages.RemovePage("about")
				ui.app.SetFocus(ui.bottomTableView)
				return nil
			}
			return event
		}

		switch event.Key() {
		case tcell.KeyCtrlC:
			ui.app.Stop()
			return nil
		case tcell.KeyTab:
			if ui.app.GetFocus() == ui.bottomTableView {
				ui.app.SetFocus(ui.eventLogView)
			} else {
				ui.app.SetFocus(ui.bottomTableView)
			}
			return nil
		}

		switch event.Rune() {
		case 'q', 'Q':
			ui.app.Stop()
			return nil
		case 't', 'T':
			ui.mu.Lock()
			if ui.viewMode == ViewModeHosts {
				ui.viewMode = ViewModeFlows
			} else {
				ui.viewMode = ViewModeHosts
			}
			ui.mu.Unlock()
			ui.bottomTableView.Clear()
			ui.renderTableHeaders()
			return nil
		case 'c', 'C':
			ui.state.ClearEvents()
			ui.eventLogView.Clear()
			ui.mu.Lock()
			ui.lastRenderedEventID = 0
			ui.mu.Unlock()
			return nil
		case '?', 'h', 'H':
			ui.showAboutModal()
			return nil
		}

		return event
	})

	ui.app.SetRoot(ui.pages, true).SetFocus(ui.bottomTableView)
}

// showAboutModal displays the application information, developer attribution, and heuristic disclaimers.
func (ui *UI) showAboutModal() {
	aboutText := fmt.Sprintf(`[bold#00ffff]NetMonitor v%s[-]
[yellow]Developed by %s (GitHub: %s)[-]

[bold#ffffff]Defensive Network Monitoring & Protocol Diagnostics Tool[-]

[white]Heuristic & Analytical Disclaimer:[-]
• OS detection is a passive heuristic derived from standard default TTLs.
• Single-hop decrements (TTL 63/127) indicate intermediate routing hops or NAT tethering.
• Hardware OUI lookups map MAC prefixes to IEEE-registered manufacturers.
  Modern devices frequently randomize MAC addresses (RFC 7844).
• Heuristics serve as investigative indicators, not definitive proof of compromise.

[bold#ffffff]Keybindings:[-]
  [yellow]t[-]      Toggle between Active Hosts and Live Connections
  [yellow]c[-]      Clear Security Events Log
  [yellow]Tab[-]    Switch focus between panels
  [yellow]↑/↓[-]    Navigate table rows or scroll logs
  [yellow]q[-]      Quit NetMonitor

[gray]Press Enter or Esc to dismiss this dialog[-]`,
		AppVersion, AppDeveloper, AppGitHub,
	)

	modal := tview.NewModal().
		SetText(aboutText).
		AddButtons([]string{"Close"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			ui.pages.RemovePage("about")
			ui.app.SetFocus(ui.bottomTableView)
		})

	ui.pages.AddPage("about", modal, true, true)
}

// renderTableHeaders sets up column headers based on active view mode.
func (ui *UI) renderTableHeaders() {
	if ui.viewMode == ViewModeHosts {
		ui.bottomTableView.SetTitle(" [white]🛰️  [bold#00ffff]ACTIVE HOST INVENTORY [gray](Press 't' to view Live Flows | '?' for About)[-] ")
		headers := []struct {
			title string
			exp   int
		}{
			{"IP Address", 0},
			{"MAC Address", 0},
			{"Hardware Vendor (OUI)", 0},
			{"TTL", 0},
			{"Inferred OS Profile (Heuristic)", 0},
			{"Security Status", 0},
			{"Active Indicators & Compliance Alerts", 1},
		}

		for col, h := range headers {
			cell := tview.NewTableCell(fmt.Sprintf(" [bold#000000]%s[-] ", h.title)).
				SetBackgroundColor(tcell.ColorDarkCyan).
				SetTextColor(tcell.ColorWhite).
				SetAlign(tview.AlignLeft).
				SetSelectable(false)
			if h.exp > 0 {
				cell.SetExpansion(h.exp)
			}
			ui.bottomTableView.SetCell(0, col, cell)
		}
	} else {
		ui.bottomTableView.SetTitle(" [white]🔄  [bold#00ffff]LIVE CONNECTION TRACKER [gray](Press 't' to view Hosts | '?' for About)[-] ")
		headers := []struct {
			title string
			exp   int
		}{
			{"Endpoint A", 0},
			{"Endpoint B", 0},
			{"Proto", 0},
			{"State", 0},
			{"Packets", 0},
			{"Volume", 0},
			{"Duration", 1},
		}

		for col, h := range headers {
			cell := tview.NewTableCell(fmt.Sprintf(" [bold#000000]%s[-] ", h.title)).
				SetBackgroundColor(tcell.ColorDarkCyan).
				SetTextColor(tcell.ColorWhite).
				SetAlign(tview.AlignLeft).
				SetSelectable(false)
			if h.exp > 0 {
				cell.SetExpansion(h.exp)
			}
			ui.bottomTableView.SetCell(0, col, cell)
		}
	}
}

// Run starts UI rendering and periodic background polling.
func (ui *UI) Run(ctx context.Context) error {
	go ui.refreshLoop(ctx)
	return ui.app.Run()
}

// refreshLoop schedules periodic safe updates on the main UI thread.
func (ui *UI) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(ui.cfg.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			ui.app.Stop()
			return
		case <-ui.stopChan:
			ui.app.Stop()
			return
		case <-ticker.C:
			ui.app.QueueUpdateDraw(func() {
				ui.updateHeader()
				ui.updateLogs()
				if ui.viewMode == ViewModeHosts {
					ui.updateHostsTable()
				} else {
					ui.updateFlowsTable()
				}
			})
		}
	}
}

// updateHeader updates counters and reliability metrics in the top banner.
func (ui *UI) updateHeader() {
	stats := ui.state.GetStats()

	banner := fmt.Sprintf(
		" [bold#ffffff][ NetMonitor ][-] [yellow]Interface:[-] [cyan]%s[-] | "+
			"[yellow]Hosts:[-] [green]%d[-] | "+
			"[yellow]Flows:[-] [cyan]%d[-] | "+
			"[yellow]Packets:[-] [white]%d[-] | "+
			"[yellow]Drops:[-] [white]Pcap:%d/Queue:%d[-] | "+
			"[yellow]Alerts:[-] [red]%d[-] | "+
			"[yellow]Suspicious:[-] [yellow]%d[-] | "+
			"[yellow]Cleartext:[-] [red]%d[-] | "+
			"[yellow]DNS:[-] [green]%d[-] | "+
			"[yellow]Uptime:[-] [gray]%s[-]",
		ui.cfg.InterfaceName,
		stats.ActiveHostsCount,
		stats.ActiveFlowsCount,
		stats.TotalPackets,
		stats.PcapDropped,
		stats.QueueDropped,
		stats.AlertCount,
		stats.SuspiciousCount,
		stats.UnencryptedDetections,
		stats.DNSQueriesCount,
		formatDuration(stats.Uptime),
	)

	ui.headerView.SetText(banner)
}

// updateLogs appends newly recorded security events to the log pane.
func (ui *UI) updateLogs() {
	events := ui.state.GetEventsSnapshot(200)
	if len(events) == 0 {
		return
	}

	ui.mu.Lock()
	defer ui.mu.Unlock()

	for _, evt := range events {
		if evt.ID <= ui.lastRenderedEventID {
			continue
		}
		ui.lastRenderedEventID = evt.ID

		timeStr := evt.Timestamp.Format("15:04:05")

		var prefix string
		switch evt.Severity {
		case SeverityAlert:
			prefix = "[bold#ff5555][ALERT 🚨][-]"
		case SeveritySuspicious:
			prefix = "[bold#ffb86c][SUSPICIOUS ⚠️][-]"
		default:
			prefix = "[bold#50fa7b][INFO ℹ️][-]"
		}

		var line string
		if evt.DestIP != nil {
			line = fmt.Sprintf(" %s [gray]%s[-] %s [cyan]%s:%d -> %s:%d[-] [bold#ffffff]%s[-] [gray]%s[-]\n",
				prefix, timeStr, evt.Protocol, evt.SourceIP, evt.SrcPort, evt.DestIP, evt.DstPort, evt.Message, evt.Details)
		} else {
			line = fmt.Sprintf(" %s [gray]%s[-] %s [cyan]%s[-] [bold#ffffff]%s[-] [gray]%s[-]\n",
				prefix, timeStr, evt.Protocol, evt.SourceIP, evt.Message, evt.Details)
		}

		fmt.Fprint(ui.eventLogView, line)
	}

	ui.eventLogView.ScrollToEnd()
}

// updateHostsTable synchronizes the active host inventory table.
func (ui *UI) updateHostsTable() {
	hosts := ui.state.GetHostsSnapshot()

	rowIdx := 1
	for _, h := range hosts {
		ipCell := tview.NewTableCell(fmt.Sprintf(" %s", h.IP.String())).
			SetTextColor(tcell.ColorWhite).
			SetAlign(tview.AlignLeft)

		macStr := "-"
		if len(h.MAC) > 0 {
			macStr = h.MAC.String()
		}
		macCell := tview.NewTableCell(fmt.Sprintf(" %s", macStr)).
			SetTextColor(tcell.ColorDarkGray).
			SetAlign(tview.AlignLeft)

		vendorCell := tview.NewTableCell(fmt.Sprintf(" %s", truncateString(h.Vendor, 22))).
			SetTextColor(tcell.ColorLightCyan).
			SetAlign(tview.AlignLeft)

		ttlCell := tview.NewTableCell(fmt.Sprintf(" %d", h.LastSeenTTL)).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignRight)

		osCell := tview.NewTableCell(fmt.Sprintf(" %s", truncateString(h.InferredOS, 34))).
			SetTextColor(tcell.ColorGreen).
			SetAlign(tview.AlignLeft)

		statusCell := tview.NewTableCell("")
		switch h.SecurityStatus {
		case StatusAlert:
			statusCell.SetText(" [bold#ff5555][ALERT 🚨][-]").
				SetTextColor(tcell.ColorRed)
		case StatusSuspicious:
			statusCell.SetText(" [bold#ffb86c][SUSPICIOUS ⚠️][-]").
				SetTextColor(tcell.ColorYellow)
		default:
			statusCell.SetText(" [bold#50fa7b][SAFE ✓][-]").
				SetTextColor(tcell.ColorGreen)
		}
		statusCell.SetAlign(tview.AlignCenter)

		anomaliesText := "-"
		if len(h.ActiveAnomalies) > 0 {
			anomaliesText = strings.Join(h.ActiveAnomalies, " | ")
		}
		anomCell := tview.NewTableCell(fmt.Sprintf(" %s", anomaliesText)).
			SetExpansion(1).
			SetAlign(tview.AlignLeft)

		if h.SecurityStatus == StatusAlert {
			anomCell.SetTextColor(tcell.ColorRed)
		} else if h.SecurityStatus == StatusSuspicious {
			anomCell.SetTextColor(tcell.ColorYellow)
		} else {
			anomCell.SetTextColor(tcell.ColorGray)
		}

		ui.bottomTableView.SetCell(rowIdx, 0, ipCell)
		ui.bottomTableView.SetCell(rowIdx, 1, macCell)
		ui.bottomTableView.SetCell(rowIdx, 2, vendorCell)
		ui.bottomTableView.SetCell(rowIdx, 3, ttlCell)
		ui.bottomTableView.SetCell(rowIdx, 4, osCell)
		ui.bottomTableView.SetCell(rowIdx, 5, statusCell)
		ui.bottomTableView.SetCell(rowIdx, 6, anomCell)

		rowIdx++
	}

	totalRows := ui.bottomTableView.GetRowCount()
	for r := totalRows - 1; r >= rowIdx; r-- {
		ui.bottomTableView.RemoveRow(r)
	}
}

// updateFlowsTable synchronizes the active connection flows table.
func (ui *UI) updateFlowsTable() {
	if ui.conntrack == nil {
		return
	}

	flows := ui.conntrack.GetActiveFlows(100)

	rowIdx := 1
	for _, f := range flows {
		epACell := tview.NewTableCell(fmt.Sprintf(" %s:%d", f.Key.EndpointA, f.Key.PortA)).
			SetTextColor(tcell.ColorWhite).
			SetAlign(tview.AlignLeft)

		epBCell := tview.NewTableCell(fmt.Sprintf(" %s:%d", f.Key.EndpointB, f.Key.PortB)).
			SetTextColor(tcell.ColorWhite).
			SetAlign(tview.AlignLeft)

		protoCell := tview.NewTableCell(fmt.Sprintf(" %s", f.Key.Protocol)).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter)

		stateColor := tcell.ColorLightGreen
		if f.State == "RESET" || f.State == "FIN_WAIT" {
			stateColor = tcell.ColorDarkGray
		} else if f.State == "SYN_SENT" || f.State == "SYN_RECV" {
			stateColor = tcell.ColorOrange
		}

		stateCell := tview.NewTableCell(fmt.Sprintf(" %s", f.State)).
			SetTextColor(stateColor).
			SetAlign(tview.AlignCenter)

		pktsCell := tview.NewTableCell(fmt.Sprintf(" %d", f.Packets)).
			SetTextColor(tcell.ColorLightCyan).
			SetAlign(tview.AlignRight)

		bytesCell := tview.NewTableCell(fmt.Sprintf(" %s", formatBytes(f.Bytes))).
			SetTextColor(tcell.ColorLightCyan).
			SetAlign(tview.AlignRight)

		durCell := tview.NewTableCell(fmt.Sprintf(" %s", formatDuration(f.Duration()))).
			SetTextColor(tcell.ColorGray).
			SetExpansion(1).
			SetAlign(tview.AlignLeft)

		ui.bottomTableView.SetCell(rowIdx, 0, epACell)
		ui.bottomTableView.SetCell(rowIdx, 1, epBCell)
		ui.bottomTableView.SetCell(rowIdx, 2, protoCell)
		ui.bottomTableView.SetCell(rowIdx, 3, stateCell)
		ui.bottomTableView.SetCell(rowIdx, 4, pktsCell)
		ui.bottomTableView.SetCell(rowIdx, 5, bytesCell)
		ui.bottomTableView.SetCell(rowIdx, 6, durCell)

		rowIdx++
	}

	totalRows := ui.bottomTableView.GetRowCount()
	for r := totalRows - 1; r >= rowIdx; r-- {
		ui.bottomTableView.RemoveRow(r)
	}
}

// Stop safely signals the UI loop to terminate.
func (ui *UI) Stop() {
	select {
	case <-ui.stopChan:
		return
	default:
		close(ui.stopChan)
	}
	ui.app.Stop()
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
