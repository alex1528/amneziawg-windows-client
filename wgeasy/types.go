/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */

package wgeasy

import (
	"encoding/json"
	"fmt"
)

// WGClient represents a WireGuard client entry from wg-easy API.
type WGClient struct {
	ID        json.Number `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Address   string `json:"address"`
	PublicKey string `json:"publicKey"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// ErrorResponse represents an API error.
type ErrorResponse struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"statusMessage"`
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("wg-easy API error %d: %s", e.StatusCode, e.Message)
}

// ProvisionResult represents the response from the provision endpoint.
// The server finds or creates a WireGuard client for the authenticated user
// and returns the full configuration in a single call.
type ProvisionResult struct {
	ClientID      int    `json:"clientId"`
	Name          string `json:"name"`
	Configuration string `json:"configuration"`
	Created       bool   `json:"created"`
}
