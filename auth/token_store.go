/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */
package auth

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const credTargetName = "AmneziaWG-OIDC-Token"

// In-memory token cache — eliminates dependency on Credential Manager for
// session-level reads. Credential Manager is used only for persistence
// across process restarts.
var (
	cachedToken *AuthResult
	tokenMu     sync.RWMutex
)

// CREDENTIAL structure matching Windows CREDENTIALW.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
)

var (
	modAdvapi32     = windows.NewLazySystemDLL("advapi32.dll")
	procCredWriteW  = modAdvapi32.NewProc("CredWriteW")
	procCredReadW   = modAdvapi32.NewProc("CredReadW")
	procCredDeleteW = modAdvapi32.NewProc("CredDeleteW")
	procCredFree    = modAdvapi32.NewProc("CredFree")
)

// SaveToken persists the AuthResult both in memory and to Windows Credential Manager.
// Even if Credential Manager write fails, the in-memory cache is always updated.
func SaveToken(result *AuthResult) error {
	// Always update in-memory cache (this never fails)
	tokenMu.Lock()
	cachedToken = result
	tokenMu.Unlock()

	// Attempt to persist to Credential Manager (best-effort)
	if err := writeToCredentialManager(result); err != nil {
		log.Printf("auth: credential manager write failed (token cached in memory): %v", err)
		return err
	}
	return nil
}

// LoadToken retrieves the stored AuthResult.
// Priority: in-memory cache → Windows Credential Manager.
// This ensures the token is always available after Login even if
// Credential Manager has permission issues.
func LoadToken() (*AuthResult, error) {
	// Check in-memory cache first (fast, always reliable)
	tokenMu.RLock()
	cached := cachedToken
	tokenMu.RUnlock()

	if cached != nil {
		return cached, nil
	}

	// Fallback: try Credential Manager (for tokens from previous sessions)
	result, err := readFromCredentialManager()
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}

	// Update in-memory cache with what we found
	tokenMu.Lock()
	cachedToken = result
	tokenMu.Unlock()

	return result, nil
}

// ClearToken removes the token from both memory and Credential Manager.
func ClearToken() error {
	// Clear in-memory cache
	tokenMu.Lock()
	cachedToken = nil
	tokenMu.Unlock()

	// Clear from Credential Manager
	return deleteFromCredentialManager()
}

// --- Credential Manager operations (best-effort persistence) ---

func writeToCredentialManager(result *AuthResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}

	targetName, err := windows.UTF16PtrFromString(credTargetName)
	if err != nil {
		return err
	}

	userName, err := windows.UTF16PtrFromString(result.Email)
	if err != nil {
		return err
	}

	cred := credential{
		Type:               credTypeGeneric,
		TargetName:         targetName,
		CredentialBlobSize: uint32(len(data)),
		CredentialBlob:     &data[0],
		Persist:            credPersistLocalMachine,
		UserName:           userName,
	}

	ret, _, sysErr := procCredWriteW.Call(
		uintptr(unsafe.Pointer(&cred)),
		0,
	)
	if ret == 0 {
		return fmt.Errorf("CredWriteW: %w", sysErr)
	}
	return nil
}

func readFromCredentialManager() (*AuthResult, error) {
	targetName, err := windows.UTF16PtrFromString(credTargetName)
	if err != nil {
		return nil, err
	}

	var pcred *credential
	ret, _, sysErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(targetName)),
		uintptr(credTypeGeneric),
		0,
		uintptr(unsafe.Pointer(&pcred)),
	)
	if ret == 0 {
		// ERROR_NOT_FOUND (1168) means no credential stored
		if errno, ok := sysErr.(windows.Errno); ok && errno == 1168 {
			return nil, nil
		}
		return nil, fmt.Errorf("CredReadW: %w", sysErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(pcred)))

	// Copy blob data before freeing
	blob := unsafe.Slice(pcred.CredentialBlob, pcred.CredentialBlobSize)
	data := make([]byte, len(blob))
	copy(data, blob)

	var result AuthResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("unmarshal stored token: %w", err)
	}
	return &result, nil
}

func deleteFromCredentialManager() error {
	targetName, err := windows.UTF16PtrFromString(credTargetName)
	if err != nil {
		return err
	}

	ret, _, sysErr := procCredDeleteW.Call(
		uintptr(unsafe.Pointer(targetName)),
		uintptr(credTypeGeneric),
		0,
	)
	if ret == 0 {
		// Ignore ERROR_NOT_FOUND
		if errno, ok := sysErr.(windows.Errno); ok && errno == 1168 {
			return nil
		}
		return fmt.Errorf("CredDeleteW: %w", sysErr)
	}
	return nil
}
