# Passport 内省凭证执行适配器

KeyGate 负责申请、多人审批和执行记录；Passport 负责内省凭证及实时权限检查。此适配器接入现有开发/测试管理流程，批准后仍由原申请人触发执行，不向浏览器开放执行器凭证。生产部署、真实网络 mTLS 和通知送达仍需单独验收。

```text
申请：目标 + 动作 + audience + 目标版本 + 接收公钥
                       |
服务端固定 Passport 地址/执行器身份，生成稳定操作编号
                       |
      不可变清单及摘要 -> 多人审批
                       |
     原申请人触发执行 -> 持久化 unknown 记录
                       |
             按原操作编号查询 Passport
                       |
      +----------------+------------------+
      |                |                  |
   已提交          明确 404          超时/故障/不一致
      |                |                  |
 核对请求摘要      复查当前审批权限       保持 unknown
 写入完成结果      同编号同参数执行       禁止再次发送
```

## 启用和升级

先升级 Passport 到支持 `GET /management/v1/introspection-clients/operations/{operationId}` 的版本，并执行其迁移 007。旧版本没有该查询能力时，KeyGate 会拒绝执行，不能把普通 404 当成“未执行”。

KeyGate 本次新增 schema 26。已有持久化部署应按原有 `plan / upgrade / run` 流程：停服、捕获最新外部签名检查点、显式升级，再启动；支持 schema 21–25 升级到 26。普通 `run` 只校验账本，不写 DDL。新增操作记录已纳入检查点，不能在备份恢复时丢弃或手工清理。

适配器在 `keygate-dev` 显式启动受控流程后配置，环境变量如下：

| 配置 | 用途 |
| --- | --- |
| `KEYGATE_PASSPORT_URL` | 固定管理端点，如 `https://passport-management.example`；不能包含路径、用户信息、查询参数或片段 |
| `KEYGATE_PASSPORT_EXECUTOR_ID` | Passport 离线创建的专用执行器 ID |
| `KEYGATE_PASSPORT_SECRET_FILE` | 仅所有者可读的普通文件，保存 `epe_` 执行器凭证；禁止符号链接，支持单个末尾换行 |
| `KEYGATE_PASSPORT_CA_FILE` | 可选：专用 CA PEM |
| `KEYGATE_PASSPORT_CERT_FILE` / `KEYGATE_PASSPORT_KEY_FILE` | 可选：出站 mTLS 证书与受限私钥文件，必须成对配置 |
| `KEYGATE_PASSPORT_LOOPBACK_HTTP=1` | 仅显式本地演练；只接受字面量回环 IP 的 HTTP 地址 |

默认仅允许 HTTPS，启用证书校验及 TLS 1.3，禁止跳转和环境代理。未配置 URL 时适配器关闭；只配置部分凭证、未启用受控流程或文件无权限保障时启动失败。不得在申请 JSON 中提交端点、密钥或自报执行器身份。内置软件根仍遵守项目原有生产限制。

先在 Passport 运维终端发放最小授权，例如只允许 `trade-api`、audience `trade` 的三类动作。KeyGate 不会扩大 Passport 的执行器权限。

## 申请、审批和触发

继续使用现有 Cookie + CSRF 的 `POST /api/requests`，`X-Idempotency-Key` 为稳定申请幂等键。请求正文直接使用操作对象，例如：

```json
{
  "kind": "passport_introspection",
  "clientId": "trade-api",
  "expectedRevision": "1",
  "passport": {
    "operation": "rotate",
    "recipientPublicKey": "<RSA SPKI DER 的无填充标准 Base64>",
    "recipientFingerprint": "<DER SHA-256 十六进制>"
  }
}
```

`create` 要求 `expectedRevision="0"`，并在 `passport` 中提供非空 `audiences`；`rotate` 和 `disable` 要求当前正整数版本且不得提供 audience。`disable` 不允许接收公钥，其他两类要求 RSA 3072/4096 位、指数 65537 的接收公钥及匹配指纹。接收私钥保留在业务服务或受限接收器。

服务端在清单中自动填入 `passport.operationId` 与 `passport.endpointBinding`。操作编号由安全域、真实申请人和申请幂等键派生，跨进程稳定；同一申请键更改内容会冲突。摘要覆盖动作、目标、版本、audience、接收公钥、编号、端点身份及既有审批策略/人员修订。审批人应核对完整清单。客户端不能用新的执行参数覆盖已批准内容。

完成现有多人投票后，用 `POST /api/requests/{id}/execute`，正文仅为原 `digest`。服务端复查原申请人近期会话、资格、当前票、策略版本和有效期，再由内部适配器处理；无外部 `executor` 用户角色。对同一申请的并发执行在数据库串行化。目标当前版本冲突由 Passport 拒绝，禁止自动改为新版本重试。

查询当前目标版本仍使用 Passport 的受限管理查询能力；KeyGate 本次没有新增通用管理代理或用户可用的执行器 API。

## 超时与结果

KeyGate 联系 Passport 前，先原子保存清单摘要、操作编号、请求摘要及端点身份，并写入 `unknown` 执行记录和审计。即使请求超时或进程重启，这条记录也保留；已开始执行的申请不允许撤回。

每次执行尝试都先查询相同编号。查询成功时，必须核对动作、目标、精确请求摘要和预期提交版本；不能用目标版本变化推测某次操作成功。只有 Passport 返回标准 `EXECUTOR_OPERATION_NOT_FOUND` 的 404，且当前审批仍有效，才允许发送同编号、同参数的 POST。查询故障、认证失败、响应异常或绑定不一致均不触发 POST，不换新编号。后续执行器密钥轮换保持同一 ID 和端点可继续查询；更换端点或执行器 ID 会因绑定变化拒绝旧申请。

远程提交与 KeyGate 本地事务不能成为一个跨库原子事务。本地写回或审计失败时保持 `unknown`，下次先查询远程。首次成功响应中的新内省密钥使用审批公钥 RSA-OAEP-SHA256 加密，标签绑定申请 ID、摘要、操作编号及请求摘要，数据库和 HTTP 只保留/返回密文，日志不记录明文。

执行成功响应包含 `executed=true` 以及 `passport` 结果对象，明确区分交付状态。原申请人也可用近期有效会话查询 `GET /api/requests/{id}/passport-result`，返回：

| 字段 | 含义 |
| --- | --- |
| `operationId` | 原清单绑定的稳定操作编号 |
| `state` | `unknown` 或 `succeeded` |
| `revision` | 已确认的 Passport 提交版本 |
| `deliveryState` | `pending`、`encrypted`、`unavailable`、`not_required` |
| `ciphertext` / `oaepLabel` | 加密交付时的标准 Base64 字节数组表示；接收器用标签原字节解密 |

若远程已执行，但首次密钥响应丢失或本地提交失败，查询不能恢复明文，结果为 `succeeded + unavailable`。不得以原批准为由自动再轮换；读取当前版本后，另起申请、另行审批替代轮换。`disable` 的交付状态为 `not_required`。

原申请人被撤权后不能再从浏览器触发或查看执行器结果。受信进程内执行器可通过原有 `ExecuteLocal` 对持久化记录继续查询核对；若远程尚未提交，仍需复核当前审批，不得绕过撤权。没有自动后台恢复守护程序。备份回滚不能撤销已经发生的远程轮换；遇到 `unknown` 必须先与远程按原编号核对，不得重建记录。

## 验证

```sh
# 隔离 PostgreSQL 的完整项目回归
python3 scripts/test-postgres.py

# 启动真实相邻 ex-passport、临时 PostgreSQL/Redis，结束自动清理
python3 scripts/test-passport-adapter.py
```

第二条可通过 `KEYGATE_PASSPORT_CHECKOUT` 指定 Passport 工作副本。真实链路验证审批后创建、轮换、禁用、受限目标、RSA 密文交付、旧凭证失效，以及远程完成后丢弃响应、按编号查询恢复且没有第二次 POST。存储层故障测试另覆盖超时、重启、并发重试、查询不可用、本地提交失败和审批人撤权。真实网络 mTLS 仍待环境验收。

JWT 密钥生命周期使用独立执行器和配置，不继承本适配器权限。部署需 Passport 008、009，KeyGate 复用 schema 26；见 [Passport-JWT审批.md](Passport-JWT审批.md)。
