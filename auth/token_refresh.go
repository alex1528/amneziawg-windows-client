/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */
package auth

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// TokenRefresher manages automatic background token refresh.
//
// Design principles:
//   - Proactive: refreshes at 75% of token lifetime (before expiry)
//   - Resilient: retries with exponential backoff on failure
//   - Non-blocking: runs in background goroutine, never blocks UI
//   - Observable: provides status and callbacks for UI notification
//   - Safe: mutex-protected, handles concurrent start/stop gracefully
type TokenRefresher struct {
	cfg        OIDCConfig
	mu         sync.Mutex
	running    bool
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	onRefresh  func(token *AuthResult)   // called after successful refresh
	onExpired  func(err error)           // called when token expires and refresh fails
	lastError  error
	lastRefresh time.Time
}

// RefresherStatus represents the current state of the token refresher.
type RefresherStatus struct {
	Running       bool
	LastRefresh   time.Time
	LastError     error
	NextRefreshIn time.Duration
	TokenEmail    string
	TokenExpiry   time.Time
}

// NewTokenRefresher creates a new background token refresher.
func NewTokenRefresher(cfg OIDCConfig) *TokenRefresher {
	return &TokenRefresher{cfg: cfg}
}

// SetCallbacks sets the notification callbacks.
//   onRefresh: called on successful token refresh (can be nil)
//   onExpired: called when token cannot be refreshed (can be nil)
func (r *TokenRefresher) SetCallbacks(onRefresh func(*AuthResult), onExpired func(error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onRefresh = onRefresh
	r.onExpired = onExpired
}

// Start begins the background refresh loop.
// Safe to call multiple times (idempotent).
func (r *TokenRefresher) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.running = true

	r.wg.Add(1)
	go r.refreshLoop(ctx)
	log.Println("auth: token refresher started")
}

// Stop halts the background refresh loop.
func (r *TokenRefresher) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return
	}

	r.cancel()
	r.wg.Wait()
	r.running = false
	log.Println("auth: token refresher stopped")
}

// IsRunning returns whether the refresher is active.
func (r *TokenRefresher) IsRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

// Status returns the current refresher status.
func (r *TokenRefresher) Status() RefresherStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	status := RefresherStatus{
		Running:     r.running,
		LastRefresh: r.lastRefresh,
		LastError:   r.lastError,
	}

	token, _ := LoadToken()
	if token != nil {
		status.TokenEmail = token.Email
		status.TokenExpiry = token.ExpiresAt
		status.NextRefreshIn = r.calcNextRefreshDelay(token)
	}

	return status
}

// ForceRefresh triggers an immediate token refresh attempt.
// Returns the new token or error.
func (r *TokenRefresher) ForceRefresh() (*AuthResult, error) {
	token, err := LoadToken()
	if err != nil || token == nil {
		// No token at all — cannot refresh
		return nil, fmt.Errorf("no token available, login required")
	}
	return r.doRefresh(token)
}

// refreshLoop is the main background loop.
func (r *TokenRefresher) refreshLoop(ctx context.Context) {
	defer r.wg.Done()

	// Initial check delay (let the app settle)
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}

	for {
		token, _ := LoadToken()
		if token == nil {
			// No token at all — wait for login
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
				continue
			}
		}

		// Calculate when to refresh (at 75% of token lifetime)
		delay := r.calcNextRefreshDelay(token)

		if delay <= 0 {
			// Token already expired or about to expire — refresh now
			r.attemptRefresh(ctx, token)
		} else {
			// Wait until refresh time
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
				// Time to refresh
				currentToken, _ := LoadToken()
				if currentToken != nil && currentToken.RefreshToken != "" {
					r.attemptRefresh(ctx, currentToken)
				}
			}
		}

		// Brief pause between cycles
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

// calcNextRefreshDelay calculates how long to wait before next refresh.
// Strategy: refresh at 75% of token lifetime (e.g., 1h token → refresh at 45min).
// Minimum: if less than 5 minutes remain, refresh immediately.
func (r *TokenRefresher) calcNextRefreshDelay(token *AuthResult) time.Duration {
	now := time.Now()

	if token.ExpiresAt.IsZero() {
		// No expiry info — refresh every 30 minutes as fallback
		if r.lastRefresh.IsZero() {
			return 0 // refresh immediately on first run
		}
		return 30*time.Minute - time.Since(r.lastRefresh)
	}

	remaining := token.ExpiresAt.Sub(now)

	if remaining <= 5*time.Minute {
		return 0 // urgent: less than 5 min left
	}

	// Refresh at 75% of lifetime elapsed
	// If token was issued now and expires in 1h, refresh at 45min mark
	refreshAt := remaining / 4 // wait 75% of remaining time
	if refreshAt < 2*time.Minute {
		refreshAt = 2 * time.Minute
	}

	// But cap at 30 minutes (don't sleep too long even for long-lived tokens)
	if refreshAt > 30*time.Minute {
		refreshAt = 30 * time.Minute
	}

	return remaining - refreshAt
}

// attemptRefresh tries to refresh the token with exponential backoff.
func (r *TokenRefresher) attemptRefresh(ctx context.Context, token *AuthResult) {
	maxRetries := 3
	backoff := 5 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		newToken, err := r.doRefresh(token)
		if err == nil && newToken != nil {
			// Success
			r.mu.Lock()
			r.lastRefresh = time.Now()
			r.lastError = nil
			r.mu.Unlock()

			log.Printf("auth: token refreshed successfully (expires %s)",
				newToken.ExpiresAt.Format("2006-01-02 15:04"))

			if r.onRefresh != nil {
				r.onRefresh(newToken)
			}
			return
		}

		log.Printf("auth: refresh attempt %d/%d failed: %v", attempt, maxRetries, err)

		r.mu.Lock()
		r.lastError = err
		r.mu.Unlock()

		// Exponential backoff
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
	}

	// All retries exhausted
	log.Println("auth: token refresh failed after all retries")
	if r.onExpired != nil {
		r.mu.Lock()
		err := r.lastError
		r.mu.Unlock()
		r.onExpired(err)
	}
}

// doRefresh performs the actual token refresh.
// Strategy:
//   1. If refresh_token exists → use standard refresh flow
//   2. If no refresh_token (Public Client) → re-login silently
//      Authentik session cookie is long-lived, so browser auto-completes
//      without user interaction (no password prompt)
func (r *TokenRefresher) doRefresh(token *AuthResult) (*AuthResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var newToken *AuthResult
	var err error

	if token.RefreshToken != "" {
		// Standard refresh_token flow
		newToken, err = RefreshToken(ctx, r.cfg, token.RefreshToken)
	} else {
		// No refresh_token (Authentik Public Client) → silent re-login
		// Browser session cookie allows automatic re-authentication
		newToken, err = Login(ctx, r.cfg)
	}

	if err != nil {
		return nil, err
	}
	// Persist the new token
	SaveToken(newToken)
	return newToken, nil
}

// --- Global refresher singleton ---

var (
	globalRefresher     *TokenRefresher
	globalRefresherOnce sync.Once
	globalRefresherMu   sync.Mutex
)

// StartAutoRefresh starts the global background token refresher.
// Safe to call from UI — non-blocking.
func StartAutoRefresh(cfg OIDCConfig) {
	globalRefresherMu.Lock()
	defer globalRefresherMu.Unlock()

	if globalRefresher != nil {
		globalRefresher.Stop()
	}
	globalRefresher = NewTokenRefresher(cfg)
	globalRefresher.Start()
}

// StopAutoRefresh stops the global background token refresher.
func StopAutoRefresh() {
	globalRefresherMu.Lock()
	defer globalRefresherMu.Unlock()

	if globalRefresher != nil {
		globalRefresher.Stop()
		globalRefresher = nil
	}
}

// SetAutoRefreshCallbacks sets callbacks on the global refresher.
func SetAutoRefreshCallbacks(onRefresh func(*AuthResult), onExpired func(error)) {
	globalRefresherMu.Lock()
	defer globalRefresherMu.Unlock()

	if globalRefresher != nil {
		globalRefresher.SetCallbacks(onRefresh, onExpired)
	}
}

// GetAutoRefreshStatus returns the global refresher status.
func GetAutoRefreshStatus() *RefresherStatus {
	globalRefresherMu.Lock()
	defer globalRefresherMu.Unlock()

	if globalRefresher == nil {
		return nil
	}
	status := globalRefresher.Status()
	return &status
}

// ForceAutoRefresh triggers an immediate refresh on the global refresher.
func ForceAutoRefresh() (*AuthResult, error) {
	globalRefresherMu.Lock()
	r := globalRefresher
	globalRefresherMu.Unlock()

	if r == nil {
		return nil, nil
	}
	return r.ForceRefresh()
}
