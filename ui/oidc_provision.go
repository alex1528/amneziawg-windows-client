/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */

package ui

import (
	"log"
	"strings"
	"fmt"

	"github.com/lxn/walk"

	"github.com/alex1528/amneziawg-windows-client/auth"
	"github.com/alex1528/amneziawg-windows-client/l18n"
	"github.com/alex1528/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// TryOIDCProvision attempts to auto-provision a tunnel via OIDC login.
// Called from RunUI after the manage window is created.
func TryOIDCProvision(mtw *ManageTunnelsWindow) bool {
	// Recover from any panic to prevent crashing the entire application.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("OIDC: panic recovered: %v", r)
			showErrorCustom(mtw,
				"OIDC Error",
				fmt.Sprintf("An unexpected error occurred during OIDC provisioning: %v", r))
		}
	}()

	provisioner := NewOIDCProvisioner(mtw)

	if !provisioner.IsConfigured() {
		log.Println("OIDC: not configured, skipping auto-provision")
		// Show settings dialog for first-time configuration
		if !RunOIDCSettingsDialog(mtw) {
			return false
		}
		// Reload config after user saves settings
		provisioner.cfg = auth.LoadConfigFromRegistry()
		if !provisioner.IsConfigured() {
			return false
		}
	}

	tunnels, err := manager.IPCClientTunnels()
	if err == nil && len(tunnels) > 0 {
		log.Println("OIDC: tunnels already exist, skipping auto-provision")
		return false
	}

	log.Println("OIDC: starting auto-provision flow...")

	tunnelName, configData, err := provisioner.Run()
	if err != nil {
		log.Printf("OIDC: provision failed: %v", err)
		showErrorCustom(mtw,
			l18n.Sprintf("OIDC Provision Failed"),
			l18n.Sprintf("Failed to automatically configure VPN: %v", err))
		return false
	}

	wgConf, err := conf.FromWgQuick(configData, tunnelName)
	if err != nil {
		log.Printf("OIDC: failed to parse config: %v", err)
		showErrorCustom(mtw,
			l18n.Sprintf("Configuration Error"),
			l18n.Sprintf("Failed to parse WireGuard configuration: %v", err))
		return false
	}

	tunnel, err := manager.IPCClientNewTunnel(wgConf)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			log.Printf("OIDC: tunnel '%s' already exists", tunnelName)
			return true
		}
		log.Printf("OIDC: failed to create tunnel: %v", err)
		showErrorCustom(mtw,
			l18n.Sprintf("Import Error"),
			l18n.Sprintf("Failed to import tunnel: %v", err))
		return false
	}

	if err := tunnel.Start(); err != nil {
		log.Printf("OIDC: tunnel imported but failed to start: %v", err)
	}

	log.Printf("OIDC: successfully provisioned tunnel '%s'", tunnelName)

	return true
}

// LogoutOIDC clears the stored OIDC token.
func LogoutOIDC(owner walk.Form) {
	if err := auth.ClearToken(); err != nil {
		showErrorCustom(owner,
			l18n.Sprintf("Logout Error"),
			l18n.Sprintf("Failed to clear OIDC token: %v", err))
		return
	}
	walk.MsgBox(owner,
		l18n.Sprintf("Logged Out"),
		l18n.Sprintf("OIDC token has been cleared. You will need to log in again next time."),
		walk.MsgBoxIconInformation)
}
