# Registry Keys for Admins

These are advanced configuration knobs that admins can set to do unusual things
that are not recommended. There is no UI to enable these, and no such thing is
planned. These registry keys may also be removed at some point in the future.
The uninstaller will clean up the entirety of `HKLM\Software\AmneziaWG`. Use
at your own risk, and please make sure you know what you're doing.

#### `HKLM\Software\AmneziaWG\LimitedOperatorUI`

When this key is set to `DWORD(1)`, the UI will be launched on desktops of
users belonging to the Network Configuration Operators builtin group
(S-1-5-32-556), with the following limitations for members of that group:

  - Configurations are stripped of all public, private, and pre-shared keys;
  - No version update popup notifications are shown, and updates are not permitted, though a tab still indicates the availability;
  - Adding, removing, editing, importing, or exporting configurations is forbidden; and
  - Quitting the manager is forbidden.

However, basic functionality such as starting and stopping tunnels remains intact.

```
> reg add HKLM\Software\AmneziaWG /v LimitedOperatorUI /t REG_DWORD /d 1 /f
```

#### `HKLM\Software\AmneziaWG\DangerousScriptExecution`

When this key is set to `DWORD(1)`, the tunnel service will execute the commands
specified in the `PreUp`, `PostUp`, `PreDown`, and `PostDown` options of a
tunnel configuration. Note that this execution is done as the Local System user,
which runs with the highest permissions on the operating system, and is therefore
a real target of malware. Therefore, you should enable this option only with the
utmost trepidation. Rather than use `%i`, AmneziaWG for Windows instead sets the
environment variable `AMNEZIAWG_TUNNEL_NAME` to the name of the tunnel when
executing these scripts.

```
> reg add HKLM\Software\AmneziaWG /v DangerousScriptExecution /t REG_DWORD /d 1 /f
```

#### `HKLM\Software\AmneziaWG\OIDC`

These keys configure the OIDC automatic login and provisioning feature. When all
three values are empty or absent, compile-time defaults are used (see
[`oidc.md`](oidc.md) for details).

| Value | Type | Description | Default |
|-------|------|-------------|---------|
| `IssuerURL` | REG_SZ | Authentik OIDC discovery URL | `https://sso.gslb.vip/application/o/wg-easy-desktop/` |
| `ClientID` | REG_SZ | OAuth2 Public Client ID | `wg-easy-desktop` |
| `WGEasyURL` | REG_SZ | wg-easy server base URL | `https://wg-easy.verycloud.cn` |

To pre-configure OIDC for all users on a machine:

```
> reg add HKLM\Software\AmneziaWG\OIDC /v IssuerURL /t REG_SZ /d "https://sso.example.com/application/o/wg-easy/" /f
> reg add HKLM\Software\AmneziaWG\OIDC /v ClientID /t REG_SZ /d "wg-easy-desktop" /f
> reg add HKLM\Software\AmneziaWG\OIDC /v WGEasyURL /t REG_SZ /d "https://wg-easy.example.com" /f
```

To reset to compile-time defaults, delete the `OIDC` subkey or use the
"Reset to Defaults" button in the OIDC Settings dialog.
