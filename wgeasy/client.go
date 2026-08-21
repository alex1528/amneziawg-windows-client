/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */

package wgeasy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
		httpClient:  &http.Client{},
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
