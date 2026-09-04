/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */

package wgeasy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client is the wg-easy HTTP API client.
type Client struct {
	BaseURL     string
	AccessToken string
	httpClient  *http.Client
}

// NewClient creates a new wg-easy API client.
func NewClient(baseURL, accessToken string) *Client {
	return &Client{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		AccessToken: accessToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: 10 * time.Second,
					Resolver: &net.Resolver{
						PreferGo: true,
						Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
							// Multi-server fallback: 8.8.8.8 works through VPN tunnels,
							// 223.5.5.5 works in China without VPN
							d := net.Dialer{Timeout: 3 * time.Second}
							conn, err := d.DialContext(ctx, "udp", "8.8.8.8:53")
							if err != nil {
								conn, err = d.DialContext(ctx, "udp", "1.1.1.1:53")
							}
							if err != nil {
								conn, err = d.DialContext(ctx, "udp", "223.5.5.5:53")
							}
							return conn, err
						},
					},
				}).DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
	}
}

// do executes an HTTP request with the Authorization header attached.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	return c.httpClient.Do(req)
}

// checkError inspects the response status code and decodes an ErrorResponse
// for non-2xx replies.
func (c *Client) checkError(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	defer resp.Body.Close()
	var apiErr ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
		return fmt.Errorf("wg-easy API: unexpected status %d", resp.StatusCode)
	}
	if apiErr.StatusCode == 0 {
		apiErr.StatusCode = resp.StatusCode
	}
	return &apiErr
}

// ListClients retrieves all WireGuard clients sorted ascending.
func (c *Client) ListClients() ([]WGClient, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/api/client?sort=asc", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := c.checkError(resp); err != nil {
		return nil, err
	}

	var clients []WGClient
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return nil, err
	}
	return clients, nil
}

// GetConfiguration downloads the raw WireGuard configuration for a client.
func (c *Client) GetConfiguration(clientID string) (string, error) {
	url := fmt.Sprintf("%s/api/client/%s/configuration", c.BaseURL, clientID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if err := c.checkError(resp); err != nil {
		return "", err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// CreateClient creates a new WireGuard client with the given name.
func (c *Client) CreateClient(name string) (*WGClient, error) {
	payload, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/api/client", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := c.checkError(resp); err != nil {
		return nil, err
	}

	var client WGClient
	if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
		return nil, err
	}
	return &client, nil
}

// Provision requests the server to find or create a WireGuard client for
// the currently authenticated user. This is an idempotent operation —
// calling it multiple times returns the same client.
//
// If the user has no existing client, the server automatically creates one
// bound to the user's account and returns the full .conf configuration.
func (c *Client) Provision() (*ProvisionResult, error) {
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/api/client/provision", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := c.checkError(resp); err != nil {
		return nil, err
	}

	var result ProvisionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
