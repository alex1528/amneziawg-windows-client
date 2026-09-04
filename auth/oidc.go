/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Login performs the full OIDC Authorization Code + PKCE flow.
// It opens the system browser for user authentication and waits for the
// callback with the authorization code.
func Login(ctx context.Context, cfg OIDCConfig) (*AuthResult, error) {
	// Ensure issuer URL has trailing slash — Authentik returns issuer with
	// trailing slash, and go-oidc does strict string comparison.
	issuerURL := ensureTrailingSlash(cfg.IssuerURL)
	// Inject HTTP client with direct DNS resolution into context.
	// This bypasses system DNS (which may point to 127.0.0.1 when tunnel is active)
	// and ensures OIDC discovery can always resolve the IDP hostname.
	ctx = oidc.ClientContext(ctx, directDNSHTTPClient())

	// Discover OIDC provider.
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}

	// Generate PKCE code verifier (32 random bytes, base64url-encoded).
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Derive code challenge (SHA-256 of verifier, base64url-encoded).
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Generate random state parameter (16 random bytes, base64url-encoded).
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Start the local callback server.
	srv := NewCallbackServer(cfg.RedirectPort)
	if err := srv.Start(); err != nil {
		return nil, fmt.Errorf("failed to start callback server: %w", err)
	}
	defer srv.Stop()

	// Determine scopes.
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile", "offline_access"}
	}

	// Build oauth2 config (public client, no secret).
	oauth2Cfg := &oauth2.Config{
		ClientID:    cfg.ClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: srv.RedirectURL(),
		Scopes:      scopes,
	}

	// Build the authorization URL with PKCE parameters.
	authURL := oauth2Cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", state),
	)

	// Open the browser for user login.
	// Use rundll32 to avoid cmd.exe interpreting '&' in the URL as command separator.
	if err := exec.Command("rundll32", "url.dll,FileProtocolHandler", authURL).Start(); err != nil {
		return nil, fmt.Errorf("failed to open browser: %w", err)
	}

	// Wait for the authorization code from the callback.
	code, err := srv.WaitForCode(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("failed to receive authorization code: %w", err)
	}

	// Exchange authorization code for tokens, supplying the code verifier.
	token, err := oauth2Cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	// Try to extract refresh_token from Extra fields if not in standard field
	// (some OIDC providers return it as an extra rather than the standard field)
	refreshToken := token.RefreshToken
	if refreshToken == "" {
		if rt, ok := token.Extra("refresh_token").(string); ok && rt != "" {
			refreshToken = rt
		}
	}

	// Extract and verify the ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}

	// Extract email claim from the ID token.
	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %w", err)
	}

	return &AuthResult{
		AccessToken:  token.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: refreshToken,
		Email:        claims.Email,
		ExpiresAt:    token.Expiry,
	}, nil
}

// RefreshToken uses a stored refresh token to obtain a new set of tokens
// without requiring user interaction.
func RefreshToken(ctx context.Context, cfg OIDCConfig, refreshToken string) (*AuthResult, error) {
	issuerURL := ensureTrailingSlash(cfg.IssuerURL)
	// Use direct DNS resolution (same as Login) to avoid system DNS issues
	ctx = oidc.ClientContext(ctx, directDNSHTTPClient())

	// Discover OIDC provider.
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}

	// Determine scopes.
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile", "offline_access"}
	}

	// Build oauth2 config.
	oauth2Cfg := &oauth2.Config{
		ClientID: cfg.ClientID,
		Endpoint: provider.Endpoint(),
		Scopes:   scopes,
	}

	// Create a token source from the refresh token.
	oldToken := &oauth2.Token{
		RefreshToken: refreshToken,
	}
	ts := oauth2Cfg.TokenSource(ctx, oldToken)

	// Obtain the new token.
	token, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	// Extract and verify the ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in refreshed token response")
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("refreshed id_token verification failed: %w", err)
	}

	// Extract email claim.
	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse refreshed id_token claims: %w", err)
	}

	return &AuthResult{
		AccessToken:  token.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		Email:        claims.Email,
		ExpiresAt:    token.Expiry,
	}, nil
}

// directDNSHTTPClient creates an HTTP client that can resolve DNS even when
// the system DNS is broken (e.g. pointing to 127.0.0.1 with proxy not running,
// or routing through a VPN that can't reach the DNS server).
//
// Strategy: Use Go's built-in resolver with multiple DNS servers and short timeout.
// The resolver tries 8.8.8.8 first (globally reachable through any VPN exit),
// with a 3-second timeout per attempt. Go's resolver automatically retries,
// so within the 30s HTTP timeout it will try multiple times.
//
// If UDP DNS completely fails, the function also configures a custom DialContext
// that attempts to resolve via DNS-over-HTTPS (8.8.8.8) as ultimate fallback.
func directDNSHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// Use 8.8.8.8 — universally reachable (works through VPN tunnels
				// since VPN servers typically have internet access)
				d := net.Dialer{Timeout: 3 * time.Second}
				conn, err := d.DialContext(ctx, "udp", "8.8.8.8:53")
				if err != nil {
					// Fallback to 1.1.1.1
					conn, err = d.DialContext(ctx, "udp", "1.1.1.1:53")
				}
				if err != nil {
					// Last resort: 223.5.5.5 (works in China without VPN)
					conn, err = d.DialContext(ctx, "udp", "223.5.5.5:53")
				}
				return conn, err
			},
		},
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			// Disable HTTP/2 to avoid potential issues with some OIDC servers
			ForceAttemptHTTP2: false,
		},
	}
}

// ensureTrailingSlash appends a "/" to the URL if it doesn't already end with one.
// Authentik's OIDC discovery document returns the issuer with a trailing slash,
// and go-oidc does a strict string comparison. Without this normalization,
// users who omit the trailing slash in settings get a cryptic mismatch error.
func ensureTrailingSlash(u string) string {
	if !strings.HasSuffix(u, "/") {
		return u + "/"
	}
	return u
}
