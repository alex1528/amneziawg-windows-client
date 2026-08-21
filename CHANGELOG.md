# Changelog

All notable changes to this project will be documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- OIDC authentication module (`auth/` package) with PKCE support
- wg-easy REST API client (`wgeasy/` package) for automatic configuration provisioning
- Login dialog in UI with browser-based OIDC flow
- Token storage via Windows Credential Manager
- [REDACTED_TOKEN] authentication support in wg-easy server API
- Documentation: `docs/oidc.md`

### Changed
- Module path migrated to `github.com/alex1528/amneziawg-windows-client`
- Version number aligned with git tag format (no `v` prefix)

## [2.0.2] - 2026-08-20

### Notes
- Baseline release forked from amnezia-vpn/amneziawg-windows-client
- Git tag format changed from `vX.Y.Z` to `X.Y.Z`
