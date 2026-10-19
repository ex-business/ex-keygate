# 客户端管理到停用的开发 HTTP 流程

目录：
- [适用范围](#scope)
- [身份与前提](#identity)
- [客户端和审批](#requests)
- [交付和启用](#delivery)
- [认证与停用](#authentication)
- [状态与重试](#states)

<a id="scope"></a>
## 适用范围

本功能在 `cmd/keygate-dev -enable-key-flow` 显式开启，仅限本机开发/测试。没有该参数时仍只有原登录功能，不自动给模拟身份添加业务权限。主服务 `cmd/keygate` 不开放这些接口。重启演示进程会创建新临时安全域和根；旧模拟域、会话与软件密钥不作为恢复方案继续使用。

原生和浏览器类型可以单独登记 Profile；本条共享密钥认证链路仅针对后端 HMAC 客户端。生产身份治理、强认证、KMS/HSM 和业务网关仍待接入。

<a id="identity"></a>
## 身份与前提

通过原 `/auth/login`、回调和短会话登录，`/auth/session` 返回会话绑定的 csrfToken。演示账号 demo-requester 发起与执行，demo-approver-1 和 demo-approver-2 分别审批；三个模拟账号不证明三个独立自然人或真实 MFA。管理页面为 `/manage`。

所有接口走开发控制台的直接 TLS 地址（默认 `https://localhost:18761`），不信任转发头。管理接口使用 Secure/HttpOnly 会话 Cookie；写操作要求固定 Origin、X-CSRF-Token 和 application/json。发起申请额外要求 X-Idempotency-Key。不接受请求自报账号、角色或 Bearer 作为管理身份。

GET `/api/config` 返回当前 environment、rootId、固定认证 audience 和独立 profiles，且标记 developmentOnly / simulatedApprovals。配置读取需要全域 viewer。

<a id="requests"></a>
## 客户端和审批

| 调用 | 条件与下一步 |
| --- | --- |
| GET `/api/clients` | 当前 viewer 范围过滤，最多 100 条；单条通过 GET `/api/clients/{client}` 读取 |
| POST `/api/requests` | requester 提交 ControlOperation，返回 id、digest、manifest、decision、executed；参数被冻结 |
| GET `/api/requests` | 最近 100 条候选中筛选当前可读申请；单条通过 GET `/api/requests/{id}` 读取 |
| POST `/api/requests/{id}/votes` | 当前合格 approver 提交 `{ "digest": "已审阅摘要", "accept": true }`；任意拒绝终止申请 |
| POST `/api/requests/{id}/execute` | 原申请人提交 `{ "digest": "获批摘要" }`，内部执行器重新检查资格与修订；未批准或非申请人拒绝 |

创建客户端的请求体示例：

```json
{"kind":"client_create","clientId":"backend-one","expectedRevision":"0","name":"后端客户端","profileId":"backend","profileVersion":"1"}
```

创建申请通过两人批准并执行后才出现客户端。backend、desktop、mobile、browser 各有独立 Profile；非后端类型不走共享 HMAC 密钥签发。每次后续操作先重新读取客户端 revision，版本字段使用十进制字符串，不能把旧 revision 自动替换后继承旧票。

<a id="delivery"></a>
## 交付和启用

密钥签发仍通过申请接口，kind 为 key_issue。必要字段：clientId、expectedRevision、keyVersion、rootId、notAfter、recipientPublicKey/recipientFingerprint、recipientSigningKey/recipientSigningFingerprint；name/profileId 为空，profileVersion 为字符串 0。公钥是公开配置，私钥不提交。notAfter 使用固定三位毫秒 UTC 格式，最大 24 小时；初始版本为字符串 1。

- RSA 公钥仅加密，独立 Ed25519 公钥用于领取签名；两者都冻结到审批清单。
- 签发执行后为 pending；GET `/api/deliveries/{issueId}/challenge` 返回需签名的 input（二进制 JSON 字段采用标准 base64）。领取不使用管理会话授权。
- POST `/api/deliveries/{issueId}/claim` 接收 `{ "signature": "Ed25519 签名的标准 base64" }`，一次性返回加密交付包、OAEP 标签和持有证明输入。接收方私钥在本机解密，管理员页面不领取明文。
- POST `/api/deliveries/{issueId}/confirm` 接收 `{ "mac": "对持有证明输入计算的 HMAC-SHA256 标准 base64" }`，成功 204 后为 staged。挑战最长五分钟，领取响应丢失不重新发送。
- 再读取最新客户端 revision，提交新的 key_activate 申请，指定 keyVersion，其他签发字段留空。两人批准并由申请人执行后为 active。

GET `/api/clients/{client}/keys/{version}` 返回当前范围内的密钥元信息，不返回秘密。首次启用的 retireAt 留空；轮换须明确旧版本退役截止时间（最多十五分钟），且只能存在一个有效 retiring 版本。

<a id="authentication"></a>
## 认证与停用

后端对 POST `/api/auth/probe` 的实际请求做固定 RFC 9421 HMAC 签名，受众固定为 keygate-probe；规范和固定跨语言向量见[请求签名认证](请求签名认证.md)。探测正文不超过 1 MiB，不能带查询参数。该接口不接受管理员 Cookie 替代客户端签名，也不将认证结果变成外部业务的访问令牌。

启用后认证成功返回 200 和 authenticated=true；未交付、未启用、错误正文/签名、超时、重放及停用后均返回 401。正常停用提交 key_disable 申请，两人审批、执行后立即影响后续认证。应急角色也可 POST `/api/clients/{client}/emergency-disable`、正文 `{}`，立即停用整个客户端；它不能恢复或扩大权限。

```text
requester -> client_create request -> 2 votes -> execute
requester -> key_issue request    -> 2 votes -> execute
recipient -> challenge -> private-key claim -> decrypt -> possession -> staged
requester -> key_activate request -> 2 votes -> execute -> active
client    -> signed HTTPS probe   -> authenticated
requester -> key_disable request  -> 2 votes -> execute -> disabled
client    -> signed HTTPS probe   -> rejected
```

<a id="states"></a>
## 状态与重试

审批 decision 与 executed 分开：approved 不代表已签发或已启用；pending/staged/active/retiring/disabled 是密钥状态，不等于审批结果。页面必须审阅 manifest 和 digest，而不是仅凭申请 ID 投票。

管理错误：401 无有效会话；403 当前权限、范围或 CSRF 不通过；400 字段、重复 JSON 键或编码错误；409 重复投票、目标修订或幂等冲突；404 无可读资源；503 权威设施不可用。开发实例流程接口共享突发 256、每秒补充 64 的本机限流，超限 429；这不替代生产分布式限流。

网络错误不自动代表失败。相同业务发起重试沿用同一幂等键和完全相同参数；认证重试使用新 nonce 和签名。领取消费后不重发，响应丢失需停用并新建版本。管理页一次点击创建一次申请，不自动重试网络请求。

已用真实临时 PostgreSQL 和 TLS 模拟 OIDC 会话验证完整 HTTP 链路、自批/越权/CSRF 拒绝、重复 JSON 和孤立 Unicode 代理项拒绝、默认入口关闭、启用前拒绝、启用后成功、重放拒绝和停用后拒绝。

【其他业务影响待确认】当前未修改其他业务、网关或 base；正式业务授权和客户端 SDK 接入仍需单独验证。
