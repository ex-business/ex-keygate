# 原生 MFA 与逐人 M-of-N 验证

目录：[范围](#scope) · [规则](#rules) · [配置与绑定](#configure) · [操作流程](#flow) · [插件协议](#plugins) · [恢复与验收](#acceptance)

<a id="scope"></a>
## 范围

KeyGate 在 SSO 身份登录之后，自行校验二次验证并管理人员流转。支持邮件验证码、短信验证码、TOTP 动态码和硬件验证插件。具体厂商尚未指定，邮件、短信与硬件通过 Go 接口或通用 HTTPS/mTLS 插件接入；未配置、失败或超时均拒绝验证，不伪造成功。当前工程仍限开发/测试软件根，不因此解除生产部署门禁。

SSO 证明“是谁”，原生 MFA 证明“本人完成了指定验证”，本地角色决定“是否有管理/审批权限”。三者分别检查。原生 MFA 不把用户注册、密码管理或发证系统迁入 KeyGate。

<a id="rules"></a>
## 规则

**业务 M-of-N 计数单位是不同自然人。** 例如 M=3、N=5：申请冻结五人的顺序和身份/授权修订；当前人员完成自己的验证组合并确认，才交给下一位；累计三名不同人员同意才批准。申请人及其同人别名不能参加审批，任何一人不能重复占票。

- 未轮到的人不能提前验证或确认；不给下一人传验证码、Cookie 或上一个人的验证结果。
- 每人的认证方式可单独配置，例如必须 TOTP，或邮件+短信+TOTP+硬件全部完成。绑定项和方式的内部门槛不改变业务的人员票数。
- `批准`增加一名赞成人并转交；`拒绝`结束申请。
- 当前人员也可完成本人验证后明确`放弃并转交`，放弃不计赞成。剩余人数不可能达到 M 时立即拒绝。
- 不替离线人员自动跳步，不自动降低 M。无人处理时申请到期，重新发起；名单/顺序调整必须走受控配置，旧申请失效。
- 现有敏感密钥操作保持 M>=2、N<=32。达到 M 后其余候选人员不能继续投票；不自动执行密钥操作，由原申请人触发获批清单。

所有证明绑定当前会话、人员修订、MFA 策略修订及具体申请 ID。管理会话验证用途为 `management`；审批证明必须绑定实际申请 ID，不能拿管理验证代替另一笔申请验证。前序撤权、换绑、策略变化、会话退出、到期、数据库或审计故障均拒绝后续放行。

<a id="configure"></a>
## 配置与绑定

配置不通过普通管理 HTTP 自助写入。首期采用受控离线启动文件，要求两名不同自然人的核验记录摘要，绑定前须在系统外核验邮箱/手机号归属、TOTP 导入和硬件凭据归属；这些声明不等同于 KeyGate 已验证了真实人工签名。提供该配置文件的操作员属于受信运维边界。

`cmd/keygate-dev` 新增参数：

| 参数 | 用途 |
| --- | --- |
| `-sso-file` | 固定 OIDC 连接元数据；默认仍为本机模拟 SSO |
| `-sso-secret-file` | 可选 confidential client 密钥私有文件，支持 client_secret_basic/post；不放入元数据 |
| `-mfa-config-file` | 私有人员绑定、本人验证组合和逐人顺序配置 |
| `-mfa-plugins-file` | 可选邮件/短信/硬件插件的固定端点、IP、专用 CA 和 mTLS 证书私钥文件 |

原有域默认不隐式启用原生 MFA；显式离线配置后全域启用，未配置人员保持拒绝管理与审批。SSO 登录及 H5 客户端身份认证本身不自动获得管理资格。外部 OIDC 不允许使用模拟人员初始化；可信集成器通过受控离线 Bootstrap 后调用 `AttachOIDCManagement` 与 `ProvisionNativeMFAOffline` 接入，开发命令当前仅为外部 SSO 提供身份登录，不自动初始化真实组织权限。

仅为本机模拟域生成私有测试绑定：

```sh
python3 scripts/create-dev-mfa-plan.py --output data/dev-mfa-plan.json
KEYGATE_ENV=development KEYGATE_ROOT_MODE=development_software \
  go run ./cmd/keygate-dev -enable-key-flow -mfa-config-file data/dev-mfa-plan.json
```

输出父目录必须为 0700，文件以 0600 排他创建，不能覆盖既有文件。此工具为三种模拟身份生成独立随机种子和 2-of-2 审批顺序，只用于开发；同一个操作员持有全部模拟种子不能证明真实多人独立性。种子只保存在私有文件，不进入页面、日志、连接元数据或 Git。各人从受控通道单独导入自己的 Base32 种子；使用 SHA1、六位、30 秒 TOTP。

`people` 中每人提供 `subject`、`policy`、`factors`。`policy.m` 是本人须通过的方式数；每条 `rules` 提供 `method`、该方式须完成的唯一绑定数 `m/n`、是否 `required`。简单的“本人必须 TOTP”配置为：

```json
{
  "m": 1,
  "rules": [{"method": "totp", "m": 1, "n": 1, "required": true}]
}
```

要求四种方式全部完成时 `policy.m=4`，四条规则分别为 email、sms、totp、hardware，均 m=1/n=1/required=true。每人使用自己的绑定，不能共用收件人、TOTP 种子或硬件凭据重复占位。

绑定字段：`id`、`method`、`label`；邮件/短信/硬件使用 `reference`，TOTP 使用 `totpSeed`。邮件规范化为小写标准地址；手机号采用 E.164；硬件 reference 是插件已登记核验的凭据引用。TOTP 只接受随机32字节、无 padding 的 Base32 种子，使用用途绑定密文保存，不能跨人搬移。N 必须等于显式配置的绑定数量，变更绑定时重新核验策略。

顶层 `witnessSubjects[2]` 和 `evidenceHash` 对应外部核验；`approverSubjects` 是已登记并有审批授权的不同自然人顺序，顶层 `m` 才是业务人员门槛。任何配置失败都不开放 HTTP 服务。换绑不恢复旧验证证明；同一 TOTP 种子保留已使用计数，不能借重新配置清除重放水位。

<a id="flow"></a>
## 操作流程

```text
SSO login + fresh auth_time
           |
           v
Applicant completes own management MFA -> submits frozen request
           |
           v
Current person completes request-bound MFA -> reviews digest
           |
      +----+--------------------+
      | approve                 | reject
      v                         v
Count distinct person       Request rejected
      |
      +-- count >= M --> Approved -> applicant executes frozen operation
      |
      +-- count < M ---> Next person repeats own MFA + confirmation
```

页面 `/manage` 提供“本人二次验证”。先用 `management` 验证以读取受保护管理信息；当前申请显示 M、N、已赞成数量和当前人员，点击“验证本次申请”后完成本人的全部必需方式，再点击批准/拒绝/明确放弃。验证成功不自动投票，不自动执行密钥操作。

| 接口 | 条件与结果 |
| --- | --- |
| POST /api/mfa/challenges | 身份 Cookie、CSRF、固定 Origin、JSON `{"purpose":"management"}` 或当前申请ID；返回 state/available |
| GET /api/mfa/challenges/{id} | 仅本人当前会话可读取；返回当前已通过绑定及期限，不返回种子、地址、验证码或密文 |
| POST /api/mfa/challenges/{id}/factors/{factor} | 空 JSON；投递验证码或准备 TOTP/硬件验证；201 返回 attemptId、expiresAt、硬件 options，不返回验证码 |
| POST /api/mfa/challenges/{id}/factors/{factor}/verify | 数字验证码 `{"code":"..."}` 或硬件断言 `{"proof":{...}}`；成功更新本人组合进度 |
| POST /api/requests/{id}/votes | 既有 digest/accept；本人必须具备该申请专用证明且轮到本人 |
| POST /api/requests/{id}/skip | digest/reason；仅当前已验证人员明确放弃，不计赞成 |

401 表示身份无效，403 表示未完成本人验证、非本人/非当前轮次或猜测额度耗尽，409 表示冲突/已完成/冷却中，503 表示插件、权威库或审计不可用。已就绪绑定重复准备会复用原投递ID和nonce；验证码不重发，硬件begin须按同一ID幂等恢复options。写操作不自动重试；外部投递结果不明保持失败，不以“再发一次”清除次数或替换挑战。

挑战最长三分钟，单项投递/准备最长两分钟，且不超过父会话期限。绑定五次/五分钟的验证次数跨会话、申请和节点共享，核验前先持久化消耗次数，插件超时和进程中断也不返还。新挑战有一秒人员冷却；换 challenge 不返还绑定的猜测额度。TOTP 允许相邻一个时间窗，同一步骤计数全局一次；管理验证后立即做申请验证可能需要等待下一动态码。

<a id="plugins"></a>
## 插件协议

Go 插件接口见 `internal/mfa/plugin.go`；通用远端适配器见 `internal/mfa/https.go`。邮件/短信插件负责投递，不决定人员票数；硬件插件必须实际校验凭据、KeyGate nonce、Origin/RP ID、持钥证明、用户验证和期限，不允许仅返回客户端自报成功。

固定 HTTPS origin、显式 1..4 个允许 IP、专用 CA、TLS1.3 与 mTLS；禁代理、动态 DNS 拨号、重定向，限制超时、响应头和正文，严格拒绝歧义 JSON。端点、IP、CA 和客户端证书摘要纳入节点登录配置摘要；换证书/信任配置须同步全部节点及 PolicyVersion，旧 Profile 会话不能继续使用。

插件配置是私有 JSON，email、sms、hardware 各自可配置：

```json
{
  "email": {
    "endpoint": "https://mfa-plugin.example:9443",
    "allowedIPs": ["192.0.2.10"],
    "caFile": "/private/plugin-ca.pem",
    "certificateFile": "/private/client.pem",
    "privateKeyFile": "/private/client-key.pem"
  },
  "sms": null,
  "hardware": null
}
```

远端路径：`POST /deliver`、`POST /hardware/begin`、`POST /hardware/verify`。HTTP 请求使用 JSON 和 `Idempotency-Key: <attempt ID>`；发送插件必须对重复 ID 幂等，不能因网络重试重复发送或改变目标。KeyGate 不自动重试投递。

所有成功响应必须为200、Content-Type严格为application/json，外层为：

```json
{"requestDigest":"<原始请求JSON字节的SHA256小写hex>","result":{"id":"<attempt ID>","accepted":true}}
```

`/deliver` 请求字段 id/method/destination/code/expiresAt，result 为 id/accepted。硬件 begin 接收 id/nonce/credential/principal/origin/expiresAt，result 为 id/options；浏览器示例页只执行 options.publicKey 的 WebAuthn 契约，不加载任意插件脚本。hardware verify 请求为 challenge 与 proof，result 为 id/verified。摘要匹配完整请求，不能把相同 ID 的其他断言响应拿来放行。

当前不实现真实邮件/短信厂商服务或真实硬件注册/证明验证器；它们由插件提供，本次交付是完整的可信调用、验证码核验、证明绑定与流转控制。工程测试里的发送器和硬件签名器是明确的模拟对象，不能当成真实厂商/硬件验收。

<a id="acceptance"></a>
## 恢复与验收

迁移12增加可信登录开始时间，13增加原生MFA、绑定、挑战、尝试、证明和顺序审批/放弃记录。旧迁移校验和不修改。升级须停服迁移，重建独立签名安全检查点；旧表清单不能直接验证新版本。恢复隔离会清除所有MFA证明和待验证挑战并撤销父身份，不恢复认证权限。TOTP加密保护根丢失时拒绝解密，不从密文或备份推测旧根，须经离线核验重新绑定。

遗失邮箱、手机、验证器或硬件不提供弱方式自助找回；首期通过受控离线重新核验两名不同自然人及证据后恢复/换绑。实际自然人核验、厂商账号、硬件注册和最终生产信任需真实接入时验收。

工程测试覆盖标准TOTP向量、重放、本人多方式组合、四方式HTTP闭环、不同人员/申请隔离、顺序交接、并发重复确认、前序撤权、明确放弃不足门槛、共享猜测次数、mTLS、严格JSON及完整请求摘要。原有一键验收继续覆盖 PostgreSQL race/故障切换、SDK和Go漏洞扫描。

参考：[OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html)、[RFC6238](https://www.rfc-editor.org/rfc/rfc6238)、[RFC8176](https://www.rfc-editor.org/rfc/rfc8176.html)、[WebAuthn](https://www.w3.org/TR/webauthn-3/)。这些协议不意味着一条 `amr=otp` 声明必然代表TOTP或真实硬件，外部声明与本地原生验证分别校验。
