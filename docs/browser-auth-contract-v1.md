# Browser Auth Contract v1

本文冻结 `@neko/auth-client` 首个浏览器 OAuth 契约，以及 Plugin Market 迁移时必须保持的兼容行为。它是回归测试和跨仓库 provenance 校验的依据，不是部署配置来源。

契约标识：`browser-auth-v1`

## 1. 协议请求

### Authorization

- 路径：`<authorizationServerUrl>/oauth2/auth`
- 方法：浏览器导航。
- 固定参数：
  - `response_type=code`
  - `code_challenge_method=S256`
- 配置参数：
  - `client_id`
  - `redirect_uri`
  - `scope`
- 每次事务生成：
  - `state`
  - `code_verifier`
  - `code_challenge=BASE64URL(SHA256(code_verifier))`
- UI 参数：`screen=login|registration`。
- 同一 client 实例上并发开始授权时，只导航一次，并向调用者返回同一个 Promise 结果。

不允许降级为 PKCE `plain`。当浏览器没有 `SubtleCrypto` 时，仍使用本地 SHA-256 实现生成 S256 challenge。

### Authorization code exchange

- 路径：`<authorizationServerUrl>/oauth2/token`
- 方法：`POST`
- Content-Type：`application/x-www-form-urlencoded`
- 请求字段：
  - `grant_type=authorization_code`
  - `code`
  - `redirect_uri`
  - `code_verifier`
  - `client_id`

交换前必须验证：

- callback 含有 code。
- callback 含有 state。
- state 能命中对应事务，或与兼容 state key 精确相等。
- 能取得对应 code verifier。

交换成功后才保存 token、清理对应事务并触发一次 session change callback。失败时不写入 token。

### Refresh token exchange

- 路径：`<authorizationServerUrl>/oauth2/token`
- 方法：`POST`
- Content-Type：`application/x-www-form-urlencoded`
- 请求字段：
  - `grant_type=refresh_token`
  - `refresh_token`
  - `client_id`

行为：

- 没有 refresh token 时返回 `null`，不发送请求。
- 同一实例上的并发 refresh 合并为一次网络请求。
- 成功响应必须包含 access token。
- 响应包含新 refresh token 时替换旧值。
- 响应没有新 refresh token 时保留旧值。
- refresh 返回非 2xx、畸形 JSON 或缺少 access token 时清理 session。
- 请求在收到 Hydra 响应前发生网络异常时向调用者抛出异常，不由 SDK 清理 session。

### Token revocation

- 路径：`<authorizationServerUrl>/oauth2/revoke`
- 方法：`POST`
- Content-Type：`application/x-www-form-urlencoded`
- 对现有 access token 和 refresh token 分别发送：
  - `token`
  - `token_type_hint=access_token|refresh_token`
  - `client_id`

撤销请求通过 `Promise.allSettled` 汇合。无论单个撤销请求成功或失败，最后都清理本站 session 和授权事务，并触发一次 session change callback。

## 2. 授权事务

SDK 默认 transaction keys：

```text
state         nekoAuthState
verifier      nekoAuthCodeVerifier
continuation  nekoAuthContinuation
prefix        nekoAuthTx:
```

消费者可以为兼容历史数据覆盖全部 keys。每个 state-bound transaction 保存：

```json
{
  "verifier": "<PKCE verifier>",
  "next": "<consumer continuation>",
  "createdAt": 0
}
```

`next` 是 v1 内部持久化字段名；公共 API 使用 `continuation`。这个差异用于兼容 Market 历史事务格式，不代表 SDK 负责 return-path 安全策略。

事务 TTL 为 30 分钟。v1 保持已有行为：开始下一次授权时清理过期或畸形事务；callback 本身不新增 TTL 拒绝逻辑。改变这个行为需要新的契约版本和消费者回归验证。

## 3. SDK 与消费者边界

SDK 负责：

- PKCE、state 和事务。
- authorization URL。
- code exchange、refresh 和 revoke。
- 并发授权/refresh 去重。
- 调用注入的 session store 和 session change callback。

消费者负责：

- token 实际存储策略。
- continuation 的同源校验。
- callback 页面和路由。
- account URL、logout return URL 和页面文案。
- API 401 后是否重试。
- 后端 introspection、client、scope、audience 和业务权限。

## 4. Plugin Market 兼容契约

Market facade 必须继续保留：

### 默认公开配置

```text
Hydra public URL  http://127.0.0.1:4444
Auth Web URL      http://127.0.0.1:4455
client_id         neko-plugin-market-web-dev
redirect_uri      <window.origin>/oauth/callback
scopes            openid email profile offline
```

以上默认值只用于本地开发。生产 Docker 构建必须显式提供全部公开 Auth 配置并通过 fail-closed 校验。

### localStorage

```text
token
refreshToken
currentUser
oryAuthSessionSource=ory-hydra-pkce
```

### sessionStorage

```text
oryOAuthState
oryOAuthCodeVerifier
oryOAuthNext
oryOAuthTx:<state>
```

### 浏览器事件

登录完成、明确的 session 清理和本站撤销完成后发送：

```text
auth:changed
```

### Market 专属策略

以下内容不得移入 SDK：

- `authRoute`
- `currentMarketPath`
- `sanitizeAuthNext`
- `marketLogoutCompleteUrl`
- `intent=market_account`
- HashRouter callback 兼容

## 5. 变更规则

- 修复内部实现但不改变上述可观察行为时，契约仍为 `browser-auth-v1`。
- 改变请求参数、storage 格式、错误语义、清理时机或回调行为时，必须先更新契约并完成 Market 与第二消费者验证。
- SDK 包内容变化后必须升级 package version，禁止覆盖已交付的 tarball。
- 消费者必须记录 Auth Git commit、package version、contract version 和 tarball SHA-256。
- CI 必须从固定 Auth commit 重新打包，并与消费者提交的 tarball 做字节级校验。
