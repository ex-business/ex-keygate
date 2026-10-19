# H5 认证与 SDK

目录：
- [适用范围与前提](#scope)
- [登录流程](#login)
- [接口与状态](#api)
- [SDK 接入](#sdk)
- [撤销与恢复](#revoke)
- [安全与验收](#security)

<a id="scope"></a>
## 适用范围与前提

本期只交付同源 H5 的联合身份会话执行器、TypeScript/ESM SDK 与 `/h5` 演示页面。移动端、桌面端、硬件和 KMS/HSM 继续延后；既有后端 HMAC 执行器保持独立。

1. 由管理员在 `/manage` 登记客户端，选择 browser Profile，经两名独立审批人批准并执行创建。执行器只接受 enabled 的 browser/federated_session/none/oidc 组合，不根据请求自报类型降级。
2. 用户必须是当前安全域内已登记且 enabled 的人员，并通过服务端固定 OIDC 的 PKCE、nonce、签名、受众、近期认证与 ACR 核验。已有管理角色不是 H5 登录前提，H5 登录也不创建人员或授予管理角色。
3. 应用与 ExKeyGate 浏览器入口使用相同 HTTPS origin。端口或子域不同均属于不同 origin；本期不开放 CORS 凭据、第三方 iframe 或跨域 BFF。
4. 同源脚本属于相同信任边界，不能用不同 clientId 隔离恶意同源应用。正式管理面与不受信 H5 应用必须分离 origin/部署信任边界，本机共同演示不构成生产隔离验收。

<a id="login"></a>
## 登录流程

```text
H5 login button -> /h5/login/{client}
                         |
               Freeze client revision
                         |
            OIDC + state + browser binding + PKCE
                         |
                 Fixed /auth/callback
                         |
             Verify nonce / issuer / audience / ACR
                         |
          Recheck client + registered enabled person
                         |
          Commit identity + H5 session + audit atomically
                         |
             Secure HttpOnly SameSite=Strict Cookies
                         |
            Click fixed first-party continuation link
                         |
           SDK session -> authenticate -> logout
```

H5 登录上下文持久化在一次性登录事务内，固定安全域、客户端及修订；另一节点可使用同一权威库处理回调，但必须装配相同身份配置和登录保护根。登录中发生停用或修订变化，回调失败且不留下新的父身份／H5 会话，也不下发有效身份 Cookie。授权码与登录事务不能重复消费；失败后重新发起登录。

回调使用明确的第一方继续链接，避免跨站重定向链影响 Strict Cookie。默认链接为 `/h5?client=CLIENT`。可信服务构造配置 `BrowserReturnPaths: map[string]string{"my-h5":"/app"}` 可为客户端登记固定同源路径；只接受受限绝对路径，不接受协议、域名、查询、片段或客户端临时 returnUrl。更改返回配置会改变身份配置摘要，节点须一致，旧配置会话不能沿用。

<a id="api"></a>
## 接口与状态

| 方法与路径 | 条件／结果 |
| --- | --- |
| GET /h5/login/{client} | 客户端已获批且为 H5；303 到固定 SSO，不接受查询参数 |
| POST /api/browser/{client}/session | 已有同源身份 Cookie、身份 CSRF、精确 Origin 与空 JSON `{}`；201 并设置独立 H5 Cookie，轮换同父身份的旧客户端会话 |
| GET /api/browser/{client}/session | H5 Cookie；200 返回当前身份、到期时间、CSRF，不改变期限 |
| POST /api/browser/{client}/authenticate | H5 Cookie、H5 CSRF、精确 Origin 与 `{}`；200 说明当前请求已认证，不返回可转移 Bearer |
| POST /api/browser/{client}/logout | 同上；原子撤销本客户端凭据及审计，204 后清除对应 Cookie |

查询和建立响应：

```json
{
  "clientId": "my-h5",
  "principalId": "oidc-<主体摘要>",
  "authenticatedAt": "2026-10-19T12:00:00Z",
  "expiresAt": "2026-10-19T12:05:00Z",
  "csrfToken": "<当前客户端用途绑定值>"
}
```

认证响应只有 authenticated、clientId、principalId、expiresAt。所有接口禁止将 H5 Cookie 或 ID Token 作为管理 Bearer；业务资源权限由实际业务继续判定。本服务的认证结果只作用于当前直接请求，不是外部业务可以直接信任的客户端自报授权。

| 状态 | 应对 |
| --- | --- |
| 401 | Cookie、父身份、人员或客户端状态已无效；停止使用旧会话，由用户重新登录 |
| 403 | Origin／CSRF、已登录身份的客户端资格或允许的 Profile 不符合要求；检查配置，不自动降级 |
| 400 | 非空／未知 JSON、无效参数、非法路由等协议错误 |
| 503／超时 | 数据库、租约、审计或身份设施不可用；拒绝认证，不能凭本地缓存放行 |

Cookie 名按安全域和客户端摘要区分，均为 `__Host-`、Secure、HttpOnly、Path=/、SameSite=Strict、无 Domain。SDK 无法读取 Cookie。CSRF 用不同的 H5 用途、域、客户端及身份配置绑定，不能与父身份 CSRF 混用。应用不得把 CSRF 或会话响应写入日志。

<a id="sdk"></a>
## SDK 接入

源码及可安装目录为 `sdk/browser`。项目内安装或静态模块方式：

```js
import {KeygateBrowserClient} from '/sdk/browser.js';
const client = new KeygateBrowserClient({clientId: 'my-h5'});
loginButton.onclick = () => client.login();

// 从回调继续进入应用后调用。
const session = await client.session();
const identity = await client.authenticate();
await client.logout();
```

TypeScript 项目可本地安装 `sdk/browser`，从 `@ex-keygate/browser` 导入同名类与类型，未自动发布 npm。`connect()` 用于显式兑换已有 SSO 身份，认证期限保持原值；GET 查询、authenticate 和 connect 均不能滑动续期，最长不超过原身份认证之后五分钟。

所有请求只指向固定同源路径，使用 credentials=same-origin、cache=no-store、redirect=error，五秒超时。会话变更不自动重发，401/403 清除 SDK 内临时 CSRF；超时或提交不明交由用户重新核对会话。logout 失败不会声称服务端已撤销；即使清掉内存中的 CSRF，Cookie 仍以服务端成功响应或自然过期为准。

演示页 `/h5` 使用相同 SDK，不把 CSRF、Cookie 或密钥展示到处理结果。客户端 ID 可手工选择或从默认继续链接带入，它只选择已登记作用域，不构成授权证据。

<a id="revoke"></a>
## 撤销与恢复

每次读取／认证均在共享权威事务里核验父会话撤销及到期、人员 enabled/修订、客户端 enabled/修订、当前 Profile 及节点资格。客户端停用、人员撤权或父身份退出后，其他节点立即拒绝；客户端修订变化后旧会话不恢复。H5 logout 只退出当前客户端，不隐式退出企业 SSO 或其他客户端。

审计失败回滚建立、轮换或撤销，不能返回伪成功。恢复隔离会撤销 H5 会话，检查点包含 browser_sessions；迁移 11 的表清单变化要求停服升级后重新建立安全校验点，不能用旧清单验证新版本。

<a id="security"></a>
## 安全与验收

`python3 scripts/security-acceptance.py` 新增 SDK 类型检查、源／产物一致性、Node 协议测试、npm 漏洞检查和 H5 页面语法检查；原有 PostgreSQL 全量 race、节点故障、Go 漏洞检查等继续执行。

覆盖：真实 TLS 模拟 OIDC 回调、Cookie 属性、代码／state 重复消费、登录途中停用、父身份退出、跨客户端／管理凭据隔离、CSRF/Origin、权限不提升、跨 Store 实时撤销、到期、审计回滚和回调失败无半成品。SDK 另验证固定同源、禁止 Bearer／凭据存储、失败不重发、响应错配、并发会话变更及产物漂移。

另以一次性 Chromium 上下文完成真实浏览器验证：SSO 表单、PKCE 回调、固定继续链接、Strict/HttpOnly/Secure Cookie、查询、认证和退出后 401。只对本机自签名测试证书开启上下文级例外，未修改系统信任；Go TLS 集成仍校验固定 CA。当前未覆盖 Safari、移动 WebView 或生产入口。

模拟 SSO 的登录页采用 origin 级 Referrer-Policy，避免表单 Origin 变为 null；CSP 的 form-action 只额外允许已配置的精确回调地址，以通过 Chromium 的重定向校验。其他响应保留 no-referrer，空／null／外站 Origin 仍拒绝。

设计参考 [OWASP CSRF 防护](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) 和 [Cookie 属性说明](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)。CSRF 与 HttpOnly 不代替 XSS 防护、同源脚本治理及业务授权；真实身份平台、真实 MFA 和生产信任隔离仍需单独验收。
