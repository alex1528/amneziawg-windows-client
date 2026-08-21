/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */
package auth

import (
	"golang.org/x/sys/windows/registry"
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

// DefaultConfig provides a zero-value configuration with standard scopes.
var DefaultConfig = OIDCConfig{
	Scopes: []string{"openid", "email", "profile"},
}

// LoadConfigFromRegistry reads OIDC configuration from the Windows registry
// at HKLM\SOFTWARE\AmneziaWG\OIDC. If the registry key or values are not
// found, it returns DefaultConfig.
func LoadConfigFromRegistry() OIDCConfig {
	cfg := DefaultConfig

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\AmneziaWG\OIDC`, registry.QUERY_VALUE)
	if err != nil {
		return cfg
	}
	defer k.Close()

	if v, _, err := k.GetStringValue("IssuerURL"); err == nil {
		cfg.IssuerURL = v
	}
	if v, _, err := k.GetStringValue("ClientID"); err == nil {
		cfg.ClientID = v
	}
	if v, _, err := k.GetStringValue("WGEasyURL"); err == nil {
		cfg.WGEasyURL = v
	}

	return cfg
}
