# OIDC 自动登录与配置下发

## 功能概述
客户端启动时通过 OIDC（OpenID Connect）协议登录 Authentik，获取 access_token 后自动从 wg-easy 服务端拉取 WireGuard 配置，解析 .conf 并导入隧道，实现一键登录即连接。

客户端内置编译时默认配置，首次使用无需手动填写任何 URL，点击 Sign in 即可完成全部流程。

## 架构图
```
用户启动客户端
    │
    ├─ 1. 检查本地 Token（Windows Credential Manager）
    │      ├─ 有效 → 直接拉取配置（步骤6）
    │      ├─ 过期 → 尝试 refresh_token 续期
    │      │    ├─ 续期成功 → 步骤6
    │      │    └─ 续期失败 → 步骤2（交互式登录）
    │      └─ 无 → 步骤2
    │
    ├─ 2. 启动本地 HTTP 回调监听（127.0.0.1:随机端口）
    ├─ 3. 打开系统浏览器 → Authentik 授权页（PKCE S256）
    ├─ 4. 用户在浏览器中登录
    ├─ 5. Authentik 回调 code → 本地服务器
    ├─ 6. 客户端用 code + PKCE verifier 换取 token
    ├─ 7. 用 access_token 调用 wg-easy POST /api/client/provision
    ├─ 8. 解析返回的 .conf 并导入 WireGuard 隧道
    └─ 9. 自动激活隧道连接
```

## 编译时默认配置

客户端内置以下默认值，用户无需配置即可使用：

| 参数 | 默认值 |
|------|--------|
| Issuer URL | `https://sso.gslb.vip/application/o/wg-easy-desktop/` |
| Client ID | `wg-easy-desktop` |
| WG-Easy URL | `https://wg-easy.verycloud.cn` |

如需连接其他服务端，可通过托盘右键 → "OIDC Settings…" 修改，或点击 OIDC 页面底部 "Advanced Settings" 按钮。

## 配置说明

### Authentik 侧
- 创建 Application（slug: wg-easy-desktop）
- Provider: OAuth2/OIDC, Client type: **Public**
- Client ID: wg-easy-desktop
- Redirect URI: `^http://127\.0\.0\.1:[0-9]+/callback$`（regex 模式）
- Scopes: openid, email, profile, offline_access
- Authentication flow: default-authentication-flow
- Authorization flow: default-provider-authorization-implicit-consent

### 客户端侧

#### OIDC 配置
注册表路径: `HKLM\SOFTWARE\AmneziaWG\OIDC`
| 值名 | 类型 | 说明 | 默认值 |
|------|------|------|--------|
| IssuerURL | REG_SZ | Authentik OIDC discovery URL | `https://sso.gslb.vip/application/o/wg-easy-desktop/` |
| ClientID | REG_SZ | Public Client ID | `wg-easy-desktop` |
| WGEasyURL | REG_SZ | wg-easy 服务地址 | `https://wg-easy.verycloud.cn` |

注册表为空时自动使用编译时默认值。可通过 "OIDC Settings" 对话框中的 "Reset to Defaults" 恢复默认。

### wg-easy 服务端
需支持 `Authorization: Bearer <token>` 头认证，通过调用 Authentik userinfo endpoint 验证 token 并匹配用户。

Provision 端点: `POST /api/client/provision`
- 查找用户已有的 WireGuard 客户端，如有则返回其配置
- 如无则自动创建新客户端并返回配置
- 返回格式: `{ "clientId": int, "name": string, "configuration": string, "created": bool }`

## Token 生命周期管理

### 自动刷新（TokenRefresher）
- 在 token 生命周期的 **75%** 时主动刷新（如 1h token → 第 45min 时刷新）
- 短期 token（< 5min）在 50% 时刷新
- 失败后指数退避重试（5s → 10s → 20s → ...）
- 成功后自动保存新 token 到 Credential Manager

### OIDC Gate（隧道生命周期守卫）
- **续期窗口**: token 过期前 5 分钟开始续期
- **宽限期**: token 过期后仍保持隧道连接 5 分钟，等待续期完成
- **续期策略**: 先尝试 refresh_token 静默续期 → 失败后打开浏览器交互式续期
- **断开条件**: token 过期 + 宽限期耗尽 + 续期未完成 → 自动断开所有隧道
- **即时断开**: 用户主动 Logout 立即断开

### 启动时自动 Provision
- 客户端启动后自动检查：配置是否完整 → 是否有已存在的隧道 → 无则自动执行 OIDC 登录 + Provision 流程
- 通过 `TryOIDCProvision()` 实现，内含 `defer recover()` 保护，OIDC 异常不影响客户端主进程

## UI 入口

| 入口 | 位置 | 功能 |
|------|------|------|
| OIDC Tab | 主窗口标签页 | 一键 Sign in、状态倒计时、Logout |
| OIDC Settings… | 托盘右键菜单 | 打开高级设置对话框 |
| Advanced Settings | OIDC Tab 底部 | 打开高级设置对话框 |

### OIDC Tab 界面
- **Sign in 按钮**: 执行完整流程（登录 → Provision → 导入 → 激活）
- **状态显示**: `email (valid for Xh Ym)` / `Session expired` / `Not connected`
- **配置指示**: `Using default server` / `Using custom server: xxx`
- **Logout 按钮**: 清除 token + 断开隧道

### OIDC Settings 对话框
- 3 个输入框：Issuer URL、Client ID、WG-Easy URL
- CueBanner 显示当前默认值
- "Reset to Defaults" 按钮恢复编译时默认值
- 状态指示：默认/自定义配置

## 新增模块

| 包 | 职责 |
|----|------|
| auth/ | OIDC 登录流程（PKCE）、Token 安全存储、Token 自动刷新、注册表配置读写 |
| wgeasy/ | wg-easy REST API 客户端（Provision、DNS-aware dialer） |

## 安全设计
- **PKCE S256**: 桌面 Public Client 无 client_secret，依赖 PKCE 防中间人
- **Token 存储**: Windows Credential Manager（OS 级加密）+ 进程内存缓存
- **Token 自动刷新**: 过期前使用 refresh_token 续期，后台静默完成
- **回调监听**: 仅绑定 127.0.0.1 随机端口（RFC 8252 §7.3），外部不可达
- **浏览器打开**: 使用 `rundll32 url.dll,FileProtocolHandler` 避免 cmd.exe 截断 URL 中的 `&`
- **Panic 保护**: `TryOIDCProvision` 内含 `defer recover()`，异常不影响客户端主进程

## 依赖
- `github.com/coreos/go-oidc/v3` — OIDC Discovery + ID Token 验证
- `golang.org/x/oauth2` — OAuth2 授权码流程
- `golang.org/x/sys/windows` — Credential Manager + 注册表 API
- `github.com/go-jose/go-jose/v4` — JOSE/JWK 签名验证（go-oidc 间接依赖）
