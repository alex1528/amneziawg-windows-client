/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/lxn/walk"

	"github.com/alex1528/amneziawg-windows-client/auth"
	"github.com/alex1528/amneziawg-windows-client/l18n"
	"github.com/alex1528/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// OIDCPage is the OIDC authentication tab page.
// Design: one-click "Sign in" button (works out of the box with defaults),
// status display, and "Advanced Settings" link at the bottom for custom config.
type OIDCPage struct {
	*walk.TabPage

	statusLabel    *walk.Label
	configLabel    *walk.Label
	connectButton  *walk.PushButton
	logoutButton   *walk.PushButton
	settingsButton *walk.PushButton
	ticker         *time.Ticker
}

func NewOIDCPage() (*OIDCPage, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	p := &OIDCPage{}
	if p.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(p)

	p.SetTitle(l18n.Sprintf("OIDC"))
	vlayout := walk.NewVBoxLayout()
	vlayout.SetMargins(walk.Margins{18, 18, 18, 18})
	vlayout.SetSpacing(10)
	p.SetLayout(vlayout)

	// --- Title ---
	titleLabel, _ := walk.NewLabel(p)
	titleLabel.SetText(l18n.Sprintf("VPN Connection"))
	titleFont, _ := walk.NewFont("Segoe UI", 12, walk.FontBold)
	titleLabel.SetFont(titleFont)
	titleLabel.SetAlignment(walk.AlignHCenterVCenter)

	// --- Status ---
	walk.NewVSpacer(p)
	p.statusLabel, _ = walk.NewLabel(p)
	p.statusLabel.SetAlignment(walk.AlignHCenterVCenter)
	statusFont, _ := walk.NewFont("Segoe UI", 10, 0)
	p.statusLabel.SetFont(statusFont)

	// --- Config indicator (default vs custom) ---
	p.configLabel, _ = walk.NewLabel(p)
	p.configLabel.SetAlignment(walk.AlignHCenterVCenter)

	// --- Spacer ---
	walk.NewVSpacer(p)

	// --- Main buttons: Connect + Logout (centered) ---
	buttonRow, _ := walk.NewComposite(p)
	buttonRow.SetLayout(walk.NewHBoxLayout())
	walk.NewHSpacer(buttonRow)

	p.connectButton, _ = walk.NewPushButton(buttonRow)
	p.connectButton.SetText(l18n.Sprintf("Sign in"))
	p.connectButton.SetMinMaxSize(walk.Size{160, 36}, walk.Size{200, 44})
	p.connectButton.Clicked().Attach(p.onConnect)

	p.logoutButton, _ = walk.NewPushButton(buttonRow)
	p.logoutButton.SetText(l18n.Sprintf("Logout"))
	p.logoutButton.SetMinMaxSize(walk.Size{90, 36}, walk.Size{120, 44})
	p.logoutButton.Clicked().Attach(p.onLogout)

	walk.NewHSpacer(buttonRow)

	// --- Spacer ---
	walk.NewVSpacer(p)

	// --- Bottom: "Advanced Settings" link ---
	bottomRow, _ := walk.NewComposite(p)
	bottomRow.SetLayout(walk.NewHBoxLayout())
	walk.NewHSpacer(bottomRow)

	p.settingsButton, _ = walk.NewPushButton(bottomRow)
	p.settingsButton.SetText(l18n.Sprintf("Advanced Settings"))
	p.settingsButton.SetMinMaxSize(walk.Size{140, 28}, walk.Size{180, 32})
	p.settingsButton.Clicked().Attach(p.onAdvancedSettings)

	walk.NewHSpacer(bottomRow)

	// --- Initial status + start ticker ---
	p.updateStatus()

	p.ticker = time.NewTicker(1 * time.Second)
	go func() {
		for range p.ticker.C {
			p.Synchronize(func() {
				p.updateStatus()
			})
		}
	}()
	p.Disposing().Attach(func() {
		p.ticker.Stop()
	})

	disposables.Spare()
	return p, nil
}

// onConnect: one-click does everything (login → provision → import → activate)
func (p *OIDCPage) onConnect() {
	cfg := auth.LoadConfigFromRegistry()
	if !auth.IsConfigured(cfg) {
		walk.MsgBox(p.Form(), l18n.Sprintf("Error"),
			l18n.Sprintf("OIDC not configured. Please check Advanced Settings."),
			walk.MsgBoxIconWarning)
		return
	}

	p.connectButton.SetEnabled(false)
	p.statusLabel.SetText(l18n.Sprintf("Connecting..."))

	go func() {
		provisioner := NewOIDCProvisioner(p.Form())
		tunnelName, configData, err := provisioner.Run()

		if err != nil {
			p.Synchronize(func() {
				p.connectButton.SetEnabled(true)
				p.statusLabel.SetText(l18n.Sprintf("Connection failed"))
				walk.MsgBox(p.Form(), l18n.Sprintf("Error"),
					fmt.Sprintf("%v", err), walk.MsgBoxIconError)
				p.updateStatus()
			})
			return
		}

		wgConf, parseErr := conf.FromWgQuick(configData, tunnelName)
		if parseErr != nil {
			p.Synchronize(func() {
				p.connectButton.SetEnabled(true)
				p.statusLabel.SetText(l18n.Sprintf("Config error"))
				walk.MsgBox(p.Form(), l18n.Sprintf("Error"),
					fmt.Sprintf("Failed to parse config: %v", parseErr),
					walk.MsgBoxIconError)
			})
			return
		}

		tunnel, createErr := manager.IPCClientNewTunnel(wgConf)
		if createErr != nil && !strings.Contains(createErr.Error(), "already exists") {
			p.Synchronize(func() {
				p.connectButton.SetEnabled(true)
				walk.MsgBox(p.Form(), l18n.Sprintf("Error"),
					fmt.Sprintf("Failed to import tunnel: %v", createErr),
					walk.MsgBoxIconError)
			})
			return
		}
		if createErr == nil {
			tunnel.Start()
		}

		p.Synchronize(func() {
			p.connectButton.SetEnabled(true)
			p.updateStatus()
		})
	}()
}

// onLogout: clear token + disconnect
func (p *OIDCPage) onLogout() {
	StopMonitor()
	auth.ClearToken()
	p.updateStatus()
	p.connectButton.SetEnabled(false)
	p.statusLabel.SetText("Disconnecting...")
	go func() {
		DisconnectAllTunnels()
		p.Synchronize(func() {
			p.connectButton.SetEnabled(true)
			p.updateStatus()
		})
	}()
}

// onAdvancedSettings: open settings dialog
func (p *OIDCPage) onAdvancedSettings() {
	if RunOIDCSettingsDialog(p.Form()) {
		// Settings saved — refresh status
		p.updateStatus()
	}
}

// updateStatus shows current state + config source indicator
func (p *OIDCPage) updateStatus() {
	cfg := auth.LoadConfigFromRegistry()

	// Config source indicator
	if auth.IsUsingDefaults(cfg) {
		p.configLabel.SetText(l18n.Sprintf("Using default server"))
	} else {
		p.configLabel.SetText(l18n.Sprintf("Using custom server: %s", cfg.IssuerURL))
	}

	token, _ := auth.LoadToken()
	if token == nil {
		p.statusLabel.SetText(l18n.Sprintf("Not connected"))
		if p.connectButton != nil {
			p.connectButton.SetText(l18n.Sprintf("Sign in"))
		}
		return
	}

	if token.ExpiresAt.Before(time.Now()) {
		if IsRenewing() {
			p.statusLabel.SetText(l18n.Sprintf("%s (renewing session...)", token.Email))
		} else {
			p.statusLabel.SetText(l18n.Sprintf("Session expired — click Sign in to renew"))
		}
		if p.connectButton != nil {
			p.connectButton.SetText(l18n.Sprintf("Reconnect"))
		}
		return
	}

	totalSec := int(time.Until(token.ExpiresAt).Seconds())
	if totalSec < 0 {
		totalSec = 0
	}
	var countdown string
	if totalSec >= 3600 {
		countdown = fmt.Sprintf("%dh%dm%ds", totalSec/3600, (totalSec%3600)/60, totalSec%60)
	} else if totalSec >= 60 {
		countdown = fmt.Sprintf("%dm%ds", totalSec/60, totalSec%60)
	} else {
		countdown = fmt.Sprintf("%ds", totalSec)
	}
	p.statusLabel.SetText(fmt.Sprintf("%s (valid for %s)", token.Email, countdown))
	if p.connectButton != nil {
		p.connectButton.SetText(l18n.Sprintf("Reconnect"))
	}
}
