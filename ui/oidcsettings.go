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

	var err error
	if dlg.Dialog, err = walk.NewDialog(owner); err != nil {
		log.Printf("OIDC settings: failed to create dialog: %v", err)
		return false
	}
	defer dlg.Dispose()

	dlg.SetTitle(l18n.Sprintf("OIDC Settings"))
	dlg.SetMinMaxSize(walk.Size{450, 220}, walk.Size{600, 300})
	dlg.SetSize(walk.Size{480, 250})

	vlayout := walk.NewVBoxLayout()
	vlayout.SetMargins(walk.Margins{10, 10, 10, 10})
	vlayout.SetSpacing(8)
	dlg.SetLayout(vlayout)

	// Load current config
	cfg := auth.LoadConfigFromRegistry()

	// IssuerURL row
	issuerRow, _ := walk.NewComposite(dlg)
	hbl1 := walk.NewHBoxLayout()
	hbl1.SetMargins(walk.Margins{})
	issuerRow.SetLayout(hbl1)
	lblIssuer, _ := walk.NewLabel(issuerRow)
	lblIssuer.SetText(l18n.Sprintf("Issuer URL:"))
	lblIssuer.SetMinMaxSize(walk.Size{90, 0}, walk.Size{90, 0})
	dlg.issuerEdit, _ = walk.NewLineEdit(issuerRow)
	dlg.issuerEdit.SetText(cfg.IssuerURL)
	dlg.issuerEdit.SetCueBanner("https://sso.example.com/application/o/app-slug/")

	// ClientID row
	clientRow, _ := walk.NewComposite(dlg)
	hbl2 := walk.NewHBoxLayout()
	hbl2.SetMargins(walk.Margins{})
	clientRow.SetLayout(hbl2)
	lblClient, _ := walk.NewLabel(clientRow)
	lblClient.SetText(l18n.Sprintf("Client ID:"))
	lblClient.SetMinMaxSize(walk.Size{90, 0}, walk.Size{90, 0})
	dlg.clientEdit, _ = walk.NewLineEdit(clientRow)
	dlg.clientEdit.SetText(cfg.ClientID)
	dlg.clientEdit.SetCueBanner("wg-easy-desktop")

	// WGEasyURL row
	wgeasyRow, _ := walk.NewComposite(dlg)
	hbl3 := walk.NewHBoxLayout()
	hbl3.SetMargins(walk.Margins{})
	wgeasyRow.SetLayout(hbl3)
	lblWgeasy, _ := walk.NewLabel(wgeasyRow)
	lblWgeasy.SetText(l18n.Sprintf("WG-Easy URL:"))
	lblWgeasy.SetMinMaxSize(walk.Size{90, 0}, walk.Size{90, 0})
	dlg.wgeasyEdit, _ = walk.NewLineEdit(wgeasyRow)
	dlg.wgeasyEdit.SetText(cfg.WGEasyURL)
	dlg.wgeasyEdit.SetCueBanner("https://wg-easy.example.com")

	// Button row
	buttonRow, _ := walk.NewComposite(dlg)
	hbl4 := walk.NewHBoxLayout()
	hbl4.SetMargins(walk.Margins{0, 10, 0, 0})
	buttonRow.SetLayout(hbl4)

	walk.NewHSpacer(buttonRow)

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

		walk.MsgBox(dlg, l18n.Sprintf("Settings Saved"),
			l18n.Sprintf("OIDC settings have been saved successfully."),
			walk.MsgBoxIconInformation)
		dlg.Accept()
	})

	dlg.cancelButton, _ = walk.NewPushButton(buttonRow)
	dlg.cancelButton.SetText(l18n.Sprintf("Cancel"))
	dlg.cancelButton.Clicked().Attach(func() {
		dlg.Cancel()
	})

	dlg.SetDefaultButton(dlg.saveButton)
	dlg.SetCancelButton(dlg.cancelButton)

	return dlg.Run() == walk.DlgCmdOK
}
