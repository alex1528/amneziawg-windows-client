/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */

package ui

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lxn/walk"

	"github.com/alex1528/amneziawg-windows-client/auth"
	"github.com/alex1528/amneziawg-windows-client/l18n"
	"github.com/alex1528/amneziawg-windows-client/manager"
)

// OIDCGate manages OIDC-tunnel lifecycle.
//
// Renewal strategy for Public Client (no refresh_token):
//   - Token expiry T, renewal starts at T - renewBefore (2 min before)
//   - Renewal = call Login() which opens browser
//     If Authentik session alive → browser auto-completes → new token → tunnel unaffected
//     If Authentik session expired → user inputs password → new token → tunnel unaffected
//   - Tunnel STAYS CONNECTED until: token expired + gracePeriod exhausted + renewal not completed
//   - Only Logout causes immediate disconnect
type OIDCGate struct {
	enabled    bool
	mu         sync.Mutex
	monitoring bool
	stopCh     chan struct{}
	renewing   atomic.Bool
}

const (
	// Start renewal this long before token expires.
	// For short-lived tokens (5min), this means renewal starts at 50% lifetime.
	// For long-lived tokens (8h), this gives plenty of time.
	renewBefore = 5 * time.Minute
	// After token expires, keep tunnel alive waiting for renewal to complete.
	gracePeriod = 5 * time.Minute
)

var globalGate = &OIDCGate{}

func InitOIDCGate() {
	cfg := auth.LoadConfigFromRegistry()
	globalGate.enabled = auth.IsConfigured(cfg)
	if globalGate.enabled {
		if auth.IsUsingDefaults(cfg) {
			log.Println("oidcgate: enabled (default server)")
		} else {
			log.Printf("oidcgate: enabled (custom: %s)", cfg.IssuerURL)
		}
	}
}

func IsGateEnabled() bool {
	return globalGate.enabled
}

func IsRenewing() bool {
	return globalGate.renewing.Load()
}

// CheckTunnelAllowed blocks new tunnel activation if not authenticated.
// NEVER disconnects running tunnels — that's MonitorTokenExpiry's job.
func CheckTunnelAllowed(owner walk.Form) bool {
	if !globalGate.enabled {
		return true
	}
	token, _ := auth.LoadToken()
	if token == nil {
		if owner != nil {
			walk.MsgBox(owner, l18n.Sprintf("Authentication Required"),
				l18n.Sprintf("Please login via OIDC tab before connecting VPN."),
				walk.MsgBoxIconWarning)
		}
		return false
	}
	// Allow if: token valid, OR within grace period, OR renewal in progress
	deadline := token.ExpiresAt.Add(gracePeriod)
	if time.Now().After(deadline) && !IsRenewing() {
		if owner != nil {
			walk.MsgBox(owner, l18n.Sprintf("Session Expired"),
				l18n.Sprintf("Session expired. Click Connect to renew."),
				walk.MsgBoxIconWarning)
		}
		return false
	}
	return true
}

// DisconnectAllTunnels — ONLY called on explicit user Logout.
func DisconnectAllTunnels() {
	tunnels, err := manager.IPCClientTunnels()
	if err != nil {
		return
	}
	for _, t := range tunnels {
		state, _ := t.State()
		if state == manager.TunnelStarted || state == manager.TunnelStarting {
			log.Printf("oidcgate: stopping tunnel '%s' (logout)", t.Name)
			t.Stop()
		}
	}
}

// MonitorTokenExpiry: single background goroutine managing renewal + disconnect.
func MonitorTokenExpiry() {
	if !globalGate.enabled {
		return
	}
	globalGate.mu.Lock()
	if globalGate.monitoring {
		globalGate.mu.Unlock()
		return
	}
	globalGate.monitoring = true
	globalGate.stopCh = make(chan struct{})
	globalGate.mu.Unlock()

	go monitorLoop(globalGate.stopCh)
}

func StopMonitor() {
	globalGate.mu.Lock()
	defer globalGate.mu.Unlock()
	if globalGate.monitoring {
		close(globalGate.stopCh)
		globalGate.monitoring = false
	}
}

func monitorLoop(stopCh chan struct{}) {
	log.Println("oidcgate: monitor started")
	defer log.Println("oidcgate: monitor stopped")

	renewalAttempted := false

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		token, _ := auth.LoadToken()
		if token == nil {
			renewalAttempted = false
			sleepOrStop(10*time.Second, stopCh)
			continue
		}

		remaining := time.Until(token.ExpiresAt)

		// For short-lived tokens (e.g. 5min), start renewal at 50% lifetime.
		// For long-lived tokens (e.g. 8h), use fixed 5min before expiry.
		effectiveRenewBefore := renewBefore
		if remaining < renewBefore && !renewalAttempted {
			// Token lifetime is shorter than renewBefore — renew at 50% remaining
			effectiveRenewBefore = remaining / 2
			if effectiveRenewBefore < 30*time.Second {
				effectiveRenewBefore = 30 * time.Second
			}
		}

		if remaining > effectiveRenewBefore {
			// Token still fresh — sleep until renewal window
			renewalAttempted = false
			wait := remaining - effectiveRenewBefore
			if wait > 30*time.Second {
				wait = 30 * time.Second
			}
			sleepOrStop(wait, stopCh)
			continue
		}

		if remaining > 0 && !renewalAttempted {
			// Within renewal window, token NOT yet expired — attempt renewal NOW
			// This gives us `renewBefore` time to complete before expiry
			log.Printf("oidcgate: token expires in %s, starting renewal", remaining.Round(time.Second))
			renewalAttempted = true
			go attemptRenewal(stopCh)
			sleepOrStop(10*time.Second, stopCh)
			continue
		}

		if remaining > 0 {
			// Renewal already attempted, waiting for it to complete before expiry
			sleepOrStop(5*time.Second, stopCh)
			continue
		}

		// Token expired — check if renewal succeeded (token might have been updated)
		freshToken, _ := auth.LoadToken()
		if freshToken != nil && freshToken.ExpiresAt.After(time.Now()) {
			// Renewal succeeded! New token is valid. Reset state.
			log.Println("oidcgate: renewal succeeded, new token valid")
			renewalAttempted = false
			continue
		}

		// Token expired, renewal not successful yet — grace period
		expiredFor := time.Since(token.ExpiresAt)
		if expiredFor < gracePeriod {
			// Still within grace period — tunnel stays connected
			if !IsRenewing() && !renewalAttempted {
				// Try renewal again
				renewalAttempted = true
				go attemptRenewal(stopCh)
			}
			sleepOrStop(10*time.Second, stopCh)
			continue
		}

		// Grace period exhausted — disconnect
		log.Println("oidcgate: token expired + grace period exhausted — disconnecting tunnels")
		disconnectOnExpiry()
		renewalAttempted = false
		sleepOrStop(60*time.Second, stopCh)
	}
}

// attemptRenewal tries to get a new token. For Public Client: calls Login() (browser).
// For Confidential Client with refresh_token: silent refresh first.
func attemptRenewal(stopCh chan struct{}) {
	globalGate.renewing.Store(true)
	defer globalGate.renewing.Store(false)

	cfg := auth.LoadConfigFromRegistry()
	if cfg.IssuerURL == "" || cfg.ClientID == "" {
		return
	}

	token, _ := auth.LoadToken()

	// Try refresh_token first (completely silent, no browser)
	if token != nil && token.RefreshToken != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		newToken, err := auth.RefreshToken(ctx, cfg, token.RefreshToken)
		cancel()
		if err == nil && newToken != nil {
			auth.SaveToken(newToken)
			log.Printf("oidcgate: renewed via refresh_token (expires %s)", newToken.ExpiresAt.Format("15:04:05"))
			return
		}
		log.Printf("oidcgate: refresh_token failed: %v, trying browser login", err)
	}

	// No refresh_token or refresh failed — use Login() (browser-based)
	// If Authentik session cookie is still valid, browser auto-completes (user sees brief flash)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	select {
	case <-stopCh:
		return
	default:
	}

	log.Println("oidcgate: attempting browser-based renewal")
	newToken, err := auth.Login(ctx, cfg)
	if err != nil {
		log.Printf("oidcgate: browser renewal failed: %v", err)
		return
	}

	auth.SaveToken(newToken)
	log.Printf("oidcgate: renewed via browser login (expires %s)", newToken.ExpiresAt.Format("15:04:05"))
}

func disconnectOnExpiry() {
	tunnels, err := manager.IPCClientTunnels()
	if err != nil {
		return
	}
	for _, t := range tunnels {
		state, _ := t.State()
		if state == manager.TunnelStarted || state == manager.TunnelStarting {
			log.Printf("oidcgate: stopping tunnel '%s' (session expired)", t.Name)
			t.Stop()
		}
	}
}

func sleepOrStop(d time.Duration, stopCh chan struct{}) {
	select {
	case <-time.After(d):
	case <-stopCh:
	}
}
