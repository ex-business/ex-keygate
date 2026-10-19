# 本机模拟 SSO

用户确认目前没有现有 SSO，使用本机模拟服务推进开发联调。未来可替换为真实 OIDC/SSO，不新增 ExKeyGate 密码账号系统。

## 启动

```sh
go run ./cmd/mock-sso
```

默认只监听 `https://127.0.0.1:19443`。`-port 0` 可分配随机本机端口，`-redirect` 可指定另一个精确匹配的本机 HTTPS 回调地址。

首次启动生成测试 CA 和连接配置，默认路径：

- `data/mock-sso/ca.pem`：公开的测试 CA 证书。
- `data/mock-sso/connection.json`：issuer、JWKS、clientId、回调地址及测试身份。

目录受 Git 忽略，私钥只保存在进程内，不写入文件。重启后重新生成密钥和证书，旧授权码失效，客户端需重新加载 CA；不要把测试 CA 安装为系统全局信任。

```sh
curl --cacert data/mock-sso/ca.pem \
  https://127.0.0.1:19443/.well-known/openid-configuration
```

## 接口与配置

| 项目 | 默认值 |
| --- | --- |
| issuer | https://127.0.0.1:19443 |
| discovery | /.well-known/openid-configuration |
| JWKS | /jwks |
| 授权码入口 | /authorize |
| Token 交换 | /token |
| clientId | keygate-console-dev |
| 回调 | https://127.0.0.1:18761/auth/callback |
| 测试 ACR | urn:keygate:dev:simulated-mfa |

仅支持授权码与 PKCE S256。state、nonce 和原始 verifier 使用 32 字节随机数据的规范 base64url 编码。授权码一分钟内有效，单次消费；ID Token 使用 ES256 签名，四分钟有效。

授权页提供三个身份：`demo-requester`、`demo-approver-1`、`demo-approver-2`。这些名称不自动赋予本地权限，真实申请/审批角色仍需 KeyGate 的受控策略绑定。

## 安全边界

这是故意不要求真实身份凭据的测试工具。页面明确标记模拟身份，不实施真实密码、MFA、硬件认证或用户撤权，也不能用于安全等级验收。

- 仅允许 development/test 和本机 HTTPS 地址；production 启动直接失败。
- 使用 TLS 1.3，自建测试 CA 和 ES256 临时签名密钥。
- 回调地址精确匹配，拒绝外部回调与 Host 替换；授权提交要求同源 Origin。
- 授权码内存受限，并发兑换只允许一次；错误 PKCE 不换发 Token。
- 返回的 access_token 没有资源服务器，不授予任何 KeyGate 管理权限。
- OIDC 适配器默认拒绝 `urn:keygate:dev:` ACR；只有显式 DevelopmentMode 才能使用，CA 通过专属信任池加载，不关闭证书校验。

当前管理端完整登录回调、PKCE/state 存储及会话尚未实现，因此默认回调地址是后续接入约定，不代表已经有可登录管理页面。完整模拟链路可通过 `go test -race ./internal/mocksso` 验证，无需真实 SSO 或密码。

## 已验证

Discovery/JWKS → 授权码 → PKCE 兑换 → OIDC 适配器验证三种独立身份；拒绝错误 nonce、错误 PKCE、重放、过期、外部回调、错误客户端和外部 Origin；16 个并发兑换只有一个成功。测试没有把模拟 ACR 当作真实 MFA 结论。
