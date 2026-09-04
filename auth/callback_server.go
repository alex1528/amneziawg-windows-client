/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */
package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

const callbackTimeout = 5 * time.Minute

// callbackResult holds the state and code received from the OIDC provider callback.
type callbackResult struct {
	State string
	Code  string
}

// CallbackServer is a lightweight HTTP server that listens for the OAuth2
// redirect callback on localhost.
type CallbackServer struct {
	port     int
	listener net.Listener
	server   *http.Server
	resultCh chan callbackResult
}

// NewCallbackServer creates a new CallbackServer. If port is 0, a random
// available port will be chosen when Start is called.
func NewCallbackServer(port int) *CallbackServer {
	return &CallbackServer{
		port:     port,
		resultCh: make(chan callbackResult, 1),
	}
}

// Start begins listening for HTTP requests on the configured port.
func (s *CallbackServer) Start() error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("callback server listen: %w", err)
	}
	s.listener = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", s.handleCallback)

	s.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go s.server.Serve(ln) //nolint:errcheck
	return nil
}

// RedirectURL returns the full OAuth2 redirect URI pointing to this server.
func (s *CallbackServer) RedirectURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/callback", s.listener.Addr().(*net.TCPAddr).Port)
}

// WaitForCode blocks until the authorization code is received or the context
// is cancelled. It validates that the returned state matches expectedState.
func (s *CallbackServer) WaitForCode(ctx context.Context, expectedState string) (string, error) {
	timer := time.NewTimer(callbackTimeout)
	defer timer.Stop()

	select {
	case result := <-s.resultCh:
		if result.State != expectedState {
			return "", fmt.Errorf("state mismatch: expected %q, got %q", expectedState, result.State)
		}
		return result.Code, nil
	case <-ctx.Done():
		return "", ctx.Err()
	case <-timer.C:
		return "", fmt.Errorf("timed out waiting for authorization callback (%v)", callbackTimeout)
	}
}

// Stop gracefully shuts down the callback server.
func (s *CallbackServer) Stop() {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.server.Shutdown(ctx) //nolint:errcheck
	}
}

// handleCallback processes the OAuth2 redirect request, extracts the code and
// state parameters, and displays a success page to the user.
func (s *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		errMsg := r.URL.Query().Get("error")
		errDesc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("Authorization failed: %s - %s", errMsg, errDesc), http.StatusBadRequest)
		return
	}

	// Send the result to the waiting goroutine.
	s.resultCh <- callbackResult{State: state, Code: code}

	// Render a friendly success page.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>AmneziaWG - Authentication Successful</title></head>
<body style="font-family:sans-serif;text-align:center;padding-top:80px;">
<h1>&#10004; Authentication Successful</h1>
<p>You may close this browser tab and return to AmneziaWG.</p>
</body>
</html>`)
}
