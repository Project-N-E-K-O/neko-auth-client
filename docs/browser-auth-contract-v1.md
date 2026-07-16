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

authorization server 返回 error callback 时，也必须先按相同规则验证 state，验证
通过后才可取消并清理对应事务。伪造或无关的 error/state 不得清理真实事务。

交换成功后才保存 token、清理对应事务并触发一次 session change callback。失败时不写入 token。
保存 token 时，SDK 以可选的第二参数传递
`{ grantType: "authorization_code" }`。旧 session store 可忽略该参数；需要隔离
账号 token family 的消费者可据此确保新授权响应未返回 refresh token 时不会沿用
上一账号的 refresh token。

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
- 默认情况下，refresh 返回非 2xx、畸形 JSON 或缺少 access token 时清理 session。
- 请求在收到 Hydra 响应前发生网络异常时向调用者抛出异常，不由 SDK 清理 session。
- 消费者可显式设置 `preserveSessionOnServerError=true`：Hydra 返回 5xx 或
  429 时向调用者抛出暂时不可用错误并保留 session；确定性的其他 4xx
  （包括 `invalid_grant`）仍清理 session。该选项默认关闭以保持 v1 行为。
- refresh 发出前记录 refresh token 快照；响应到达时若当前 refresh token
  已变化或清空，旧响应不得写入 token，也不得清理新的 session。
- 消费者可显式设置 `preserveSessionOnRefreshError=true`：只有响应 body 中明确
  返回 `invalid_grant`、`invalid_client` 或 `unauthorized_client` 时清理匹配的
  session；408、其他临时或不明确的 4xx、429、5xx、网络故障、畸形 JSON 和
  缺少 access token 的成功响应都向调用者抛错并保留 session。该选项默认关闭，
  不改变 browser-auth-v1 的默认错误语义。
- 成功保存 refresh 响应时，SDK 以可选第二参数传递
  `{ grantType: "refresh_token" }`，使消费者可以在服务端未轮换 refresh token
  时保留当前 token family。
- 消费者可注入 `refreshCoordinator.runExclusive()` 作为跨实例/跨 Tab 互斥。
  SDK 进入临界区后再次比较 refresh token 快照；若另一实例已经轮换 token，当前
  调用直接复用新 access token，不得再次提交旧 refresh token。该配置默认缺省，
  不改变 browser-auth-v1 单实例去重行为。
- 消费者可显式设置 `oauthRequestTimeoutMs`，为 token exchange、refresh 和 revoke
  HTTP 请求设置硬上限。超时会中止支持 AbortSignal 的 fetch，并且即使 fetch adapter
  忽略中止，SDK 也必须按时 reject，使 `refreshCoordinator` 退出临界区。该配置默认
  缺省，因此不改变 browser-auth-v1 原有的无界请求行为。

### Token revocation

- 路径：`<authorizationServerUrl>/oauth2/revoke`
- 方法：`POST`
- Content-Type：`application/x-www-form-urlencoded`
- 对现有 access token 和 refresh token 分别发送：
  - `token`
  - `token_type_hint=access_token|refresh_token`
  - `client_id`

撤销请求通过 `Promise.allSettled` 汇合。无论单个撤销请求成功或失败，最后都清理本站 session 和授权事务，并触发一次 session change callback。

消费者可显式设置 `localFirstRevoke=true`，先清理本站 session 和授权事务，再做
有界的 best-effort 撤销。等待上限由 `revokeTimeoutMs` 设置，默认 3000ms；超时
会中止支持 AbortSignal 的请求并返回，即使底层 fetch 忽略中止也不得继续阻塞。
因为清理只发生在请求之前，旧账号的迟到撤销结果不会清理随后建立的新 session。
该选项默认关闭，因此 browser-auth-v1 默认的“撤销汇合后清理”时机保持不变。

`revokeTokens({ accessToken, refreshToken })` 对调用方已捕获并从当前 session 脱离的 token
快照执行同样有界的 best-effort 撤销。该方法不得读取、清理或触发当前 session 的 change
callback，适用于消费者先在自己的共享存储锁内完成本地退出，再延迟初始化 SDK/config 并
撤销旧 token；旧账号撤销的迟到结果不得影响随后建立的新账号。

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

默认清理 TTL 为 30 分钟。v1 默认保持已有行为：开始下一次授权时清理过期
或畸形事务，callback 本身不按年龄拒绝。消费者可设置正的有限值
`transactionMaxAgeMs`，显式要求 callback 必须命中带有效 `createdAt` 的
state-bound transaction，且时间戳不得来自未来、年龄不得超过该值。该选项
默认未设置，因此旧消费者和兼容 transaction key 的行为不变。

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

`0.1.0-rc.4` 是第一个提供 `transactionMaxAgeMs`、
`preserveSessionOnServerError` 和 refresh session 快照保护的版本；包的契约标识
仍为 `browser-auth-v1`，两个新配置均为 opt-in。

`0.1.0-rc.5` 增加 token grant context、error callback state 校验、
`preserveSessionOnRefreshError`、`refreshCoordinator`、`localFirstRevoke` 和
`revokeTimeoutMs`、`oauthRequestTimeoutMs`，以及不触碰当前 session 的 detached
`revokeTokens()`。新错误
与清理时序均需消费者显式 opt-in，因此 SDK 的 browser-auth-v1 默认行为保持不变。

`0.1.0-rc.6` 是 N.E.K.O.Servers 第二消费者接入所冻结的当前制品版本，包含上述
opt-in 防护及其跨实例 refresh、换号竞态、请求与响应体超时、detached revoke
回归测试。契约标识仍为 `browser-auth-v1`；消费者必须同时固定平台 commit、制品
SHA-256 与 npm integrity，不能仅依赖版本字符串。
