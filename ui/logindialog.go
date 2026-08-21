/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */

package ui

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/lxn/walk"

	"github.com/alex1528/amneziawg-windows-client/auth"
	"github.com/alex1528/amneziawg-windows-client/l18n"
	"github.com/alex1528/amneziawg-windows-client/wgeasy"
)

// OIDCProvisioner handles the OIDC login and automatic config provisioning flow.
type OIDCProvisioner struct {
	cfg    auth.OIDCConfig
	parent walk.Form
}

// NewOIDCProvisioner creates a new provisioner with the given config.
func NewOIDCProvisioner(parent walk.Form) *OIDCProvisioner {
	return &OIDCProvisioner{
		cfg:    auth.LoadConfigFromRegistry(),
		parent: parent,
	}
}

// IsConfigured returns true if the OIDC configuration has required fields.
func (p *OIDCProvisioner) IsConfigured() bool {
	return p.cfg.IssuerURL != "" && p.cfg.ClientID != "" && p.cfg.WGEasyURL != ""
}

// Run executes the full provisioning flow:
// 1. Check for existing valid token
// 2. If expired/missing, trigger OIDC login
// 3. Fetch WireGuard config from wg-easy
// 4. Return the config string for import
func (p *OIDCProvisioner) Run() (configName string, configData string, err error) {
	if !p.IsConfigured() {
		return "", "", fmt.Errorf("OIDC not configured (check registry HKLM\\SOFTWARE\\AmneziaWG\\OIDC)")
	}

	// Step 1: Try to load existing token
	token, err := auth.LoadToken()
	if err == nil && token != nil && token.ExpiresAt.After(time.Now()) {
		configName, configData, err = p.fetchConfig(token)
		if err == nil {
			return configName, configData, nil
		}
		log.Printf("OIDC: cached token failed (%v), attempting refresh", err)
	}

	// Step 2: Try to refresh if we have a refresh token
	if token != nil && token.RefreshToken != "" {
		newToken, refreshErr := auth.RefreshToken(context.Background(), p.cfg, token.RefreshToken)
		if refreshErr == nil {
			auth.SaveToken(newToken)
			configName, configData, err = p.fetchConfig(newToken)
			if err == nil {
				return configName, configData, nil
			}
		}
		log.Printf("OIDC: refresh failed, requiring interactive login")
	}

	// Step 3: Interactive login required
	token, err = p.interactiveLogin()
	if err != nil {
		return "", "", fmt.Errorf("OIDC login failed: %w", err)
	}

	if saveErr := auth.SaveToken(token); saveErr != nil {
		log.Printf("OIDC: warning - failed to save token: %v", saveErr)
	}

	// Step 4: Fetch config with new token
	configName, configData, err = p.fetchConfig(token)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch config after login: %w", err)
	}

	return configName, configData, nil
}

func (p *OIDCProvisioner) interactiveLogin() (*auth.AuthResult, error) {
	walk.MsgBox(p.parent,
		l18n.Sprintf("OIDC Login"),
		l18n.Sprintf("Your browser will open for authentication.\nPlease log in and return to this application."),
		walk.MsgBoxIconInformation)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	return auth.Login(ctx, p.cfg)
}

func (p *OIDCProvisioner) fetchConfig(token *auth.AuthResult) (string, string, error) {
	client := wgeasy.NewClient(p.cfg.WGEasyURL, token.AccessToken)

	clients, err := client.ListClients()
	if err != nil {
		return "", "", fmt.Errorf("list clients: %w", err)
	}

	var targetClient *wgeasy.WGClient

	if len(clients) == 0 {
		name := token.Email
		if idx := indexOfByte(name, '@'); idx > 0 {
			name = name[:idx]
		}
		created, err := client.CreateClient(name)
		if err != nil {
			return "", "", fmt.Errorf("create client: %w", err)
		}
		targetClient = created
	} else {
		for i := range clients {
			if clients[i].Enabled {
				targetClient = &clients[i]
				break
			}
		}
		if targetClient == nil {
			targetClient = &clients[0]
		}
	}

	conf, err := client.GetConfiguration(targetClient.ID)
	if err != nil {
		return "", "", fmt.Errorf("get configuration: %w", err)
	}

	tunnelName := targetClient.Name
	if tunnelName == "" {
		tunnelName = "wg-easy"
	}

	return tunnelName, conf, nil
}

func indexOfByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
