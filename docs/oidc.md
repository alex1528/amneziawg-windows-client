# OIDC 自动登录与配置下发

## 功能概述
客户端启动时通过 OIDC（OpenID Connect）协议登录 Authentik，获取 access_token 后自动从 wg-easy 服务端拉取 WireGuard 配置并导入，实现一键登录即连接。

## 架构图
```
用户启动客户端
    │
    ├─ 1. 检查本地 Token（Windows Credential Manager）
    │      ├─ 有效 → 直接拉取配置（步骤7）
    │      └─ 无/过期 → 继续
    │
    ├─ 2. 启动本地 HTTP 回调监听（127.0.0.1:随机端口）
    ├─ 3. 打开系统浏览器 → Authentik 授权页
    ├─ 4. 用户在浏览器中登录
    ├─ 5. Authentik 回调 code → 本地服务器
    ├─ 6. 客户端用 code + PKCE verifier 换取 token
    ├─ 7. 用 access_token 调用 wg-easy API 获取配置
    ├─ 8. 解析 .conf 并导入 WireGuard 隧道
    └─ 9. 自动激活隧道连接
```

## 配置说明

### Authentik 侧
- 创建 Application（slug: wg-easy-desktop）
- Provider: OAuth2/OIDC, Client type: **Public**
- Client ID: wg-easy-desktop
- Redirect URI: `^http://127\.0\.0\.1:[0-9]+/callback$`（regex 模式）
- Scopes: openid, email, profile

### 客户端侧
注册表路径: `HKLM\SOFTWARE\AmneziaWG\OIDC`
| 值名 | 类型 | 说明 |
|------|------|------|
| IssuerURL | REG_SZ | Authentik OIDC discovery URL |
| ClientID | REG_SZ | Public Client ID |
| WGEasyURL | REG_SZ | wg-easy 服务地址 |

### wg-easy 服务端
需支持 Authorization: Bearer <token> 头认证，通过调用 Authentik userinfo endpoint 验证 token 并匹配用户。

## 新增模块

| 包 | 职责 |
|----|------|
| auth/ | OIDC 登录流程（PKCE）、Token 安全存储、Token 刷新 |
| wgeasy/ | wg-easy REST API 客户端（列出客户端、下载配置、创建客户端） |

## 安全设计
- PKCE S256：桌面 Public Client 无 client_secret，依赖 PKCE 防中间人
- Token 存储：Windows Credential Manager（OS 级加密）
- Token 自动刷新：过期前使用 refresh_token 续期
- 回调监听：仅绑定 127.0.0.1，外部不可达

## 依赖
- github.com/coreos/go-oidc/v3
- golang.org/x/oauth2
- golang.org/x/sys/windows（Credential Manager API）
