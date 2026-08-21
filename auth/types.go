/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */
package auth

import "time"

// AuthResult holds the tokens and user info obtained from OIDC login.
type AuthResult struct {
	AccessToken  string    `json:"access_token"`
	IDToken      string    `json:"id_token"`
	RefreshToken string    `json:"refresh_token"`
	Email        string    `json:"email"`
	ExpiresAt    time.Time `json:"expires_at"`
}
