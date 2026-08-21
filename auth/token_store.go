/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */
package auth

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const credTargetName = "AmneziaWG-OIDC-Token"

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
	credTypeGeneric          = 1
	credPersistLocalMachine  = 2
)

var (
	modAdvapi32     = windows.NewLazySystemDLL("advapi32.dll")
	procCredWriteW  = modAdvapi32.NewProc("CredWriteW")
	procCredReadW   = modAdvapi32.NewProc("CredReadW")
	procCredDeleteW = modAdvapi32.NewProc("CredDeleteW")
	procCredFree    = modAdvapi32.NewProc("CredFree")
)

// SaveToken persists the AuthResult to the Windows Credential Manager as JSON.
func SaveToken(result *AuthResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
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

	ret, _, err := procCredWriteW.Call(
		uintptr(unsafe.Pointer(&cred)),
		0, // Flags
		0, // Reserved
	)
	if ret == 0 {
		return fmt.Errorf("CredWriteW failed: %w", err)
	}
	return nil
}

// LoadToken retrieves the stored AuthResult from the Windows Credential Manager.
// Returns nil and no error if no credential is found.
func LoadToken() (*AuthResult, error) {
	targetName, err := windows.UTF16PtrFromString(credTargetName)
	if err != nil {
		return nil, err
	}

	var pcred *credential
	ret, _, err := procCredReadW.Call(
		uintptr(unsafe.Pointer(targetName)),
		uintptr(credTypeGeneric),
		0, // Flags
		uintptr(unsafe.Pointer(&pcred)),
	)
	if ret == 0 {
		// ERROR_NOT_FOUND (1168) means no credential stored.
		if errno, ok := err.(windows.Errno); ok && errno == 1168 {
			return nil, nil
		}
		return nil, fmt.Errorf("CredReadW failed: %w", err)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(pcred)))

	// Copy the credential blob bytes.
	blob := unsafe.Slice(pcred.CredentialBlob, pcred.CredentialBlobSize)
	data := make([]byte, len(blob))
	copy(data, blob)

	var result AuthResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal stored token: %w", err)
	}
	return &result, nil
}

// ClearToken removes the stored credential from the Windows Credential Manager.
func ClearToken() error {
	targetName, err := windows.UTF16PtrFromString(credTargetName)
	if err != nil {
		return err
	}

	ret, _, err := procCredDeleteW.Call(
		uintptr(unsafe.Pointer(targetName)),
		uintptr(credTypeGeneric),
		0, // Flags
	)
	if ret == 0 {
		// Ignore if not found.
		if errno, ok := err.(windows.Errno); ok && errno == 1168 {
			return nil
		}
		return fmt.Errorf("CredDeleteW failed: %w", err)
	}
	return nil
}
