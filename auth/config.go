/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */
package auth

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// Compile-time defaults — change these to match your deployment.
// If no custom config is saved in registry, these are used out of the box.
const (
	DefaultIssuerURL = "https://sso.gslb.vip/application/o/wg-easy-desktop/"
	DefaultClientID  = "wg-easy-desktop"
	DefaultWGEasyURL = "https://wg-easy.verycloud.cn"
)

// OIDCConfig holds the configuration for the OIDC authentication flow.
type OIDCConfig struct {
	// IssuerURL is the OIDC provider's issuer URL (e.g. https://accounts.google.com).
	IssuerURL string

	// ClientID is the OAuth2 client identifier registered with the provider.
	ClientID string

	// RedirectPort is the local port for the callback server. 0 means pick a random available port.
	RedirectPort int

	// Scopes is the list of OAuth2 scopes to request. Defaults to ["openid", "email", "profile"].
	Scopes []string

	// WGEasyURL is the base URL of the wg-easy API server for peer management.
	WGEasyURL string
}

// DefaultConfig provides compile-time default configuration.
var DefaultConfig = OIDCConfig{
	IssuerURL: DefaultIssuerURL,
	ClientID:  DefaultClientID,
	WGEasyURL: DefaultWGEasyURL,
	Scopes:    []string{"openid", "email", "profile", "offline_access"},
}

// IsConfigured returns true if we have a valid configuration
// (either defaults or custom from registry).
func IsConfigured(cfg OIDCConfig) bool {
	return cfg.IssuerURL != "" && cfg.ClientID != "" && cfg.WGEasyURL != ""
}

// IsUsingDefaults returns true if all config values match compile-time defaults.
func IsUsingDefaults(cfg OIDCConfig) bool {
	return cfg.IssuerURL == DefaultIssuerURL &&
		cfg.ClientID == DefaultClientID &&
		cfg.WGEasyURL == DefaultWGEasyURL
}

// LoadConfigFromRegistry reads OIDC configuration from the Windows registry
// at HKLM\SOFTWARE\AmneziaWG\OIDC. If the registry key or values are not
// found, it returns DefaultConfig (compile-time defaults).
func LoadConfigFromRegistry() OIDCConfig {
	cfg := DefaultConfig

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\AmneziaWG\OIDC`, registry.QUERY_VALUE)
	if err != nil {
		return cfg
	}
	defer k.Close()

	if v, _, err := k.GetStringValue("IssuerURL"); err == nil && v != "" {
		cfg.IssuerURL = v
	}
	if v, _, err := k.GetStringValue("ClientID"); err == nil && v != "" {
		cfg.ClientID = v
	}
	if v, _, err := k.GetStringValue("WGEasyURL"); err == nil && v != "" {
		cfg.WGEasyURL = v
	}

	return cfg
}

// SaveConfigToRegistry writes OIDC configuration to the Windows registry
// at HKLM\SOFTWARE\AmneziaWG\OIDC.
func SaveConfigToRegistry(cfg OIDCConfig) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\AmneziaWG\OIDC`, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to create registry key: %w", err)
	}
	defer k.Close()

	if err := k.SetStringValue("IssuerURL", cfg.IssuerURL); err != nil {
		return fmt.Errorf("failed to set IssuerURL: %w", err)
	}
	if err := k.SetStringValue("ClientID", cfg.ClientID); err != nil {
		return fmt.Errorf("failed to set ClientID: %w", err)
	}
	if err := k.SetStringValue("WGEasyURL", cfg.WGEasyURL); err != nil {
		return fmt.Errorf("failed to set WGEasyURL: %w", err)
	}

	return nil
}

// ResetToDefaults clears custom config from registry,
// so the app falls back to compile-time defaults.
func ResetToDefaults() error {
	return SaveConfigToRegistry(OIDCConfig{
		IssuerURL: DefaultIssuerURL,
		ClientID:  DefaultClientID,
		WGEasyURL: DefaultWGEasyURL,
	})
}
