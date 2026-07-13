# N.E.K.O Browser Auth Client

这是 `@neko/auth-client` 的公开源码镜像，供 N.E.K.O 家族网站通过 Git 仓库获取统一的浏览器 OAuth 2.0 Authorization Code + PKCE 客户端。

仓库只包含浏览器 SDK 和公开契约，不包含 Auth 服务端源码、部署配置、密钥或用户数据。

## 获取与验证

```bash
git clone https://github.com/Project-N-E-K-O/neko-auth-client.git
cd neko-auth-client/packages/auth-client
npm ci --include=dev
npm test
npm run lint
npm run build
npm pack
```

当前镜像版本、契约、来源提交和 tarball 校验值记录在 [`SOURCE.json`](SOURCE.json)。消费者应固定公开仓库 commit 和 tarball SHA-256，不要跟随浮动分支部署。

浏览器端接入要求见 [`docs/browser-auth-contract-v1.md`](docs/browser-auth-contract-v1.md)，SDK API 见 [`packages/auth-client/README.md`](packages/auth-client/README.md)。

## 目录

- `packages/auth-client/`：可构建、测试和打包的 SDK 源码
- `docs/browser-auth-contract-v1.md`：跨网站冻结契约
- `SOURCE.json`：本次公开镜像的不可变来源记录
