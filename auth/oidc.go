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
	"os/exec"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Login performs the full OIDC Authorization Code + PKCE flow.
// It opens the system browser for user authentication and waits for the
// callback with the authorization code.
func Login(ctx context.Context, cfg OIDCConfig) (*AuthResult, error) {
	// Discover OIDC provider.
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
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
		scopes = []string{"openid", "email", "profile"}
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
	)

	// Open the browser for user login.
	if err := exec.Command("cmd", "/c", "start", authURL).Start(); err != nil {
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
		RefreshToken: token.RefreshToken,
		Email:        claims.Email,
		ExpiresAt:    token.Expiry,
	}, nil
}

// RefreshToken uses a stored refresh token to obtain a new set of tokens
// without requiring user interaction.
func RefreshToken(ctx context.Context, cfg OIDCConfig, refreshToken string) (*AuthResult, error) {
	// Discover OIDC provider.
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}

	// Determine scopes.
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
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
