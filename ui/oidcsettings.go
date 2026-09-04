/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 alex1528. All Rights Reserved.
 */

package ui

import (
	"log"

	"github.com/lxn/walk"

	"github.com/alex1528/amneziawg-windows-client/auth"
	"github.com/alex1528/amneziawg-windows-client/l18n"
)

// OIDCSettingsDialog provides advanced OIDC configuration.
// Users can customize server URLs or reset to compile-time defaults.
type OIDCSettingsDialog struct {
	*walk.Dialog

	issuerEdit   *walk.LineEdit
	clientEdit   *walk.LineEdit
	wgeasyEdit   *walk.LineEdit
	statusLabel  *walk.Label
	saveButton   *walk.PushButton
	resetButton  *walk.PushButton
	cancelButton *walk.PushButton
}

// RunOIDCSettingsDialog shows the OIDC configuration dialog.
// Returns true if the user saved settings.
func RunOIDCSettingsDialog(owner walk.Form) bool {
	dlg := new(OIDCSettingsDialog)

	var err error
	if dlg.Dialog, err = walk.NewDialog(owner); err != nil {
		log.Printf("OIDC settings: failed to create dialog: %v", err)
		return false
	}
	defer dlg.Dispose()

	dlg.SetTitle(l18n.Sprintf("OIDC Advanced Settings"))
	dlg.SetMinMaxSize(walk.Size{480, 300}, walk.Size{650, 380})
	dlg.SetSize(walk.Size{520, 320})

	vlayout := walk.NewVBoxLayout()
	vlayout.SetMargins(walk.Margins{12, 12, 12, 12})
	vlayout.SetSpacing(8)
	dlg.SetLayout(vlayout)

	// Load current config
	cfg := auth.LoadConfigFromRegistry()

	// --- Status indicator ---
	dlg.statusLabel, _ = walk.NewLabel(dlg)
	dlg.statusLabel.SetAlignment(walk.AlignHCenterVCenter)
	dlg.updateStatusLabel(cfg)

	walk.NewVSeparator(dlg)

	// --- Issuer URL ---
	issuerRow, _ := walk.NewComposite(dlg)
	hbl1 := walk.NewHBoxLayout()
	hbl1.SetMargins(walk.Margins{})
	issuerRow.SetLayout(hbl1)
	lblIssuer, _ := walk.NewLabel(issuerRow)
	lblIssuer.SetText(l18n.Sprintf("Issuer URL:"))
	lblIssuer.SetMinMaxSize(walk.Size{90, 0}, walk.Size{90, 0})
	dlg.issuerEdit, _ = walk.NewLineEdit(issuerRow)
	dlg.issuerEdit.SetText(cfg.IssuerURL)
	dlg.issuerEdit.SetCueBanner(auth.DefaultIssuerURL)

	// --- Client ID ---
	clientRow, _ := walk.NewComposite(dlg)
	hbl2 := walk.NewHBoxLayout()
	hbl2.SetMargins(walk.Margins{})
	clientRow.SetLayout(hbl2)
	lblClient, _ := walk.NewLabel(clientRow)
	lblClient.SetText(l18n.Sprintf("Client ID:"))
	lblClient.SetMinMaxSize(walk.Size{90, 0}, walk.Size{90, 0})
	dlg.clientEdit, _ = walk.NewLineEdit(clientRow)
	dlg.clientEdit.SetText(cfg.ClientID)
	dlg.clientEdit.SetCueBanner(auth.DefaultClientID)

	// --- WG-Easy URL ---
	wgeasyRow, _ := walk.NewComposite(dlg)
	hbl3 := walk.NewHBoxLayout()
	hbl3.SetMargins(walk.Margins{})
	wgeasyRow.SetLayout(hbl3)
	lblWgeasy, _ := walk.NewLabel(wgeasyRow)
	lblWgeasy.SetText(l18n.Sprintf("WG-Easy URL:"))
	lblWgeasy.SetMinMaxSize(walk.Size{90, 0}, walk.Size{90, 0})
	dlg.wgeasyEdit, _ = walk.NewLineEdit(wgeasyRow)
	dlg.wgeasyEdit.SetText(cfg.WGEasyURL)
	dlg.wgeasyEdit.SetCueBanner(auth.DefaultWGEasyURL)

	// --- Button row ---
	walk.NewVSpacer(dlg)
	buttonRow, _ := walk.NewComposite(dlg)
	hbl4 := walk.NewHBoxLayout()
	hbl4.SetMargins(walk.Margins{0, 6, 0, 0})
	buttonRow.SetLayout(hbl4)

	// Reset to defaults (left side)
	dlg.resetButton, _ = walk.NewPushButton(buttonRow)
	dlg.resetButton.SetText(l18n.Sprintf("Reset to defaults"))
	dlg.resetButton.Clicked().Attach(func() {
		dlg.issuerEdit.SetText(auth.DefaultIssuerURL)
		dlg.clientEdit.SetText(auth.DefaultClientID)
		dlg.wgeasyEdit.SetText(auth.DefaultWGEasyURL)
		dlg.updateStatusLabel(auth.DefaultConfig)
	})

	walk.NewHSpacer(buttonRow)

	// Save (right side)
	dlg.saveButton, _ = walk.NewPushButton(buttonRow)
	dlg.saveButton.SetText(l18n.Sprintf("Save"))
	dlg.saveButton.Clicked().Attach(func() {
		issuer := dlg.issuerEdit.Text()
		clientID := dlg.clientEdit.Text()
		wgeasyURL := dlg.wgeasyEdit.Text()

		if issuer == "" || clientID == "" || wgeasyURL == "" {
			walk.MsgBox(dlg, l18n.Sprintf("Validation Error"),
				l18n.Sprintf("All fields are required."),
				walk.MsgBoxIconWarning)
			return
		}

		newCfg := auth.OIDCConfig{
			IssuerURL: issuer,
			ClientID:  clientID,
			WGEasyURL: wgeasyURL,
		}

		if err := auth.SaveConfigToRegistry(newCfg); err != nil {
			walk.MsgBox(dlg, l18n.Sprintf("Save Error"),
				l18n.Sprintf("Failed to save OIDC settings: %v", err),
				walk.MsgBoxIconError)
			return
		}

		dlg.Accept()
	})

	// Cancel
	dlg.cancelButton, _ = walk.NewPushButton(buttonRow)
	dlg.cancelButton.SetText(l18n.Sprintf("Cancel"))
	dlg.cancelButton.Clicked().Attach(func() {
		dlg.Cancel()
	})

	dlg.SetDefaultButton(dlg.saveButton)
	dlg.SetCancelButton(dlg.cancelButton)

	return dlg.Run() == walk.DlgCmdOK
}

func (dlg *OIDCSettingsDialog) updateStatusLabel(cfg auth.OIDCConfig) {
	if auth.IsUsingDefaults(cfg) {
		dlg.statusLabel.SetText(l18n.Sprintf("Using default server configuration"))
	} else {
		dlg.statusLabel.SetText(l18n.Sprintf("Using custom server configuration"))
	}
}
