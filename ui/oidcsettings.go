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

// OIDCSettingsDialog provides a UI for configuring OIDC parameters.
type OIDCSettingsDialog struct {
	*walk.Dialog

	issuerEdit   *walk.LineEdit
	clientEdit   *walk.LineEdit
	wgeasyEdit   *walk.LineEdit
	saveButton   *walk.PushButton
	cancelButton *walk.PushButton
}

// RunOIDCSettingsDialog shows the OIDC configuration dialog.
// Returns true if the user saved valid settings.
func RunOIDCSettingsDialog(owner walk.Form) bool {
	dlg := new(OIDCSettingsDialog)
	layout := walk.NewGridLayout()
	layout.SetColumns(2)
	layout.SetMargins(walk.Margins{10, 10, 10, 10})
	layout.SetSpacing(6)

	var err error
	if dlg.Dialog, err = walk.NewDialog(owner); err != nil {
		log.Printf("OIDC settings: failed to create dialog: %v", err)
		return false
	}
	defer dlg.Dispose()

	dlg.SetTitle(l18n.Sprintf("OIDC Settings"))
	dlg.SetLayout(layout)
	dlg.SetMinMaxSize(walk.Size{450, 0}, walk.Size{600, 0})

	// Load current config
	cfg := auth.LoadConfigFromRegistry()

	// IssuerURL
	lblIssuer, _ := walk.NewLabel(dlg)
	lblIssuer.SetText(l18n.Sprintf("Issuer URL:"))
	dlg.issuerEdit, _ = walk.NewLineEdit(dlg)
	dlg.issuerEdit.SetText(cfg.IssuerURL)
	dlg.issuerEdit.SetCueBanner("https://sso.example.com/application/o/app-slug/")

	// ClientID
	lblClient, _ := walk.NewLabel(dlg)
	lblClient.SetText(l18n.Sprintf("Client ID:"))
	dlg.clientEdit, _ = walk.NewLineEdit(dlg)
	dlg.clientEdit.SetText(cfg.ClientID)
	dlg.clientEdit.SetCueBanner("wg-easy-desktop")

	// WGEasyURL
	lblWgeasy, _ := walk.NewLabel(dlg)
	lblWgeasy.SetText(l18n.Sprintf("WG-Easy URL:"))
	dlg.wgeasyEdit, _ = walk.NewLineEdit(dlg)
	dlg.wgeasyEdit.SetText(cfg.WGEasyURL)
	dlg.wgeasyEdit.SetCueBanner("https://wg-easy.example.com")

	// Spacer
	spacer, _ := walk.NewComposite(dlg)
	spacer.SetMinMaxSize(walk.Size{0, 10}, walk.Size{0, 10})

	// Buttons
	buttonContainer, _ := walk.NewComposite(dlg)
	hLayout := walk.NewHBoxLayout()
	hLayout.SetMargins(walk.Margins{})
	buttonContainer.SetLayout(hLayout)
	layout.SetRange(buttonContainer, walk.Rectangle{0, 4, 2, 1})

	walk.NewHSpacer(buttonContainer)

	dlg.saveButton, _ = walk.NewPushButton(buttonContainer)
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

		walk.MsgBox(dlg, l18n.Sprintf("Settings Saved"),
			l18n.Sprintf("OIDC settings have been saved successfully."),
			walk.MsgBoxIconInformation)
		dlg.Accept()
	})

	dlg.cancelButton, _ = walk.NewPushButton(buttonContainer)
	dlg.cancelButton.SetText(l18n.Sprintf("Cancel"))
	dlg.cancelButton.Clicked().Attach(func() {
		dlg.Cancel()
	})

	dlg.SetDefaultButton(dlg.saveButton)
	dlg.SetCancelButton(dlg.cancelButton)

	return dlg.Run() == walk.DlgCmdOK
}
