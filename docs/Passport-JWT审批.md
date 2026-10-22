# Passport JWT 密钥审批

KeyGate 负责不可变申请、多人审批和执行追踪，Passport 负责全局密钥环状态、签发与立即撤销。发布、换签、退役、紧急撤销都使用 `passport_jwt` 审批动作，不直接把 JWT 私钥交给 KeyGate。批准后由原申请人执行；紧急撤销同样需要达到审批人数。

## 部署顺序

1. 备份 Passport 数据库、配置及受限密钥文件；备份 KeyGate 数据库与最新外部签名检查点。
2. 停止旧节点混跑，部署支持密钥环及审批回执的 Passport 版本，显式执行 `passport-migrate`，依次应用 **008、009**。008 管理密钥环，009 追加 JWT 执行回执；应用不自动迁移。初始化后的环禁止回退旧单密钥模式或旧二进制。
3. 按 Passport `JWT_KEYRING.md` 离线导入、激活原密钥，配置 `PASSPORT_SIGNER_MODE=keyring`、`PASSPORT_JWT_KEYS_FILE`。保留原 kid/公钥；所有签名节点先预加载旧、新、备用私钥，再审批换签。密钥文件和清单使用受限权限。
4. KeyGate 仍使用 **schema 26**，本次复用其执行账本，无新 DDL。旧 schema 依既有 `plan / upgrade / run` 及签名检查点流程升级到 26；已在 26 的只需升级应用和配置，不重复迁移。不能丢弃操作记录来重试。
5. 离线创建独立 JWT 执行器，配置固定管理地址和受限凭证文件。执行器需明确授予 `jwt:publish,jwt:activate,jwt:retire,jwt:revoke`、允许操作的精确 kid，以及发行者全部 audience；激活必须同时授权当前和新 kid。原内省执行器保持原权限。
6. 配置全局申请人、全局策略管理员、全局审批人及 M-of-N 策略。管理台“密钥”页刷新 Passport JWT 状态，核对版本、kid 后发起申请。
7. 验证审批不足、权限失效、错误版本、故障重试拒绝，演练换签与撤销恢复。生产网络和真实 mTLS 仍需环境验收；本文所述完成的是代码和本地验证。

专用配置，不能复用内省适配器变量作为默认值：

| 配置 | 含义 |
| --- | --- |
| `KEYGATE_PASSPORT_JWT_URL` | 固定 Passport 管理入口，只含 scheme/host/port |
| `KEYGATE_PASSPORT_JWT_EXECUTOR_ID` | 独立 JWT 执行器用户名 |
| `KEYGATE_PASSPORT_JWT_SECRET_FILE` | 仅服务端可读的 epe_ 凭证文件 |
| `KEYGATE_PASSPORT_JWT_CA_FILE` | 可选可信 CA 文件 |
| `KEYGATE_PASSPORT_JWT_CERT_FILE` / `KEY_FILE` | 可选客户端证书与私钥，必须成对配置 |
| `KEYGATE_PASSPORT_JWT_LOOPBACK_HTTP` | 仅本机演练允许 HTTP；生产使用受保护 TLS/mTLS 入口 |

管理入口的服务发现使用 Passport 管理端口 `/health/executor-ready`，业务入口使用 `/health/ready`。撤销当前密钥后业务必须不就绪，但管理入口仍需可达，以便审批激活备用密钥。没有当前密钥时 Passport 允许控制面启动，业务签发/校验继续拒绝；数据库不可写时管理探针失败。不要把管理入口开放到公网。

## 申请与权限

管理台只向具有**全局 PolicyAdmin + Viewer** 的当前人员展示 JWT 元数据，申请另外要求全局 Requester；审批池只选择全局 Approver。业务范围角色无法申请、读取或批准这个发行者级动作。执行时重新核对申请人会话、角色版本、策略版本及每张票的当前权限。人员或策略变更使旧授权失效时，不能凭冻结票据继续执行。

申请类型为 `passport_jwt`，顶层 `clientId` 固定 `passport-jwt-management`，`expectedRevision` 为 Passport **全局密钥环 revision**，不是单个 kid 版本。`jwt` 中包含 `operation`、`kid`、`reason`；发布另外包含 `publicKey` 和服务端核验的 `publicKeyFingerprint`。服务端固定 endpointBinding，并根据环境、申请人和幂等键生成稳定 operationId；它们连同动作、原因、版本、公钥指纹写入不可变审批摘要。执行接口不能临时覆盖这些内容。

管理台发布接受 Ed25519 **公钥** PKIX PEM 或 public JWK（OKP/Ed25519 x），展示 SHA-256 指纹；拒绝私钥文件。KeyGate 不负责生成、分发或保管 JWT 私钥。状态查询：`GET /api/passport/jwt-keys`；申请、投票和执行复用既有 `/api/requests` 流程；完成结果仅原申请人可查询。

| 动作 | Passport 实际约束 |
| --- | --- |
| publish | 公钥唯一、kid 不复用，先预加载各节点私钥 |
| activate | 后续密钥须预发布至少 5 分钟；切换唯一当前签名密钥，旧密钥排空 |
| retire | 仅 draining，等待停止签名 1 小时 + 30 秒，且超过实际最晚 exp + 30 秒 |
| revoke | 立即拒绝该 kid，保留撤销墓碑；当前 kid 被撤销后签发暂停 |

UI 的时间禁用只提供操作提示，最终由 Passport 数据库时间及生命周期规则判断。审批期间版本变化会导致执行冲突，需要重新查询并新建申请。

## 超时与恢复

执行前先持久化 unknown 记录，再按原操作号查询 Passport。回执必须与审批摘要、请求哈希、动作、kid、预期完成版本一致才能确认成功；仅标准“操作不存在”允许复查当前审批后发送同号同参数请求。超时、错误 404、依赖故障或内容不一致保留 unknown，禁止换号盲目重试。重复点击和进程重启后重试不会重复变更密钥环。

JWT 操作没有秘密交付，成功状态为 not_required。Passport 审计记录执行器身份、操作号与审批摘要；KeyGate 同时保留申请、投票与完成记录。回滚应用时保留 schema 26、008/009 及其账本，禁止退回不理解新操作的版本执行这些申请；紧急撤销不能通过回滚恢复被撤销密钥，应审批启用已预发布备用密钥。

## 本地验收

`python3 scripts/test-passport-adapter.py --jwt` 使用临时 PostgreSQL/Redis 和真实 Passport，覆盖四类动作、提前换签/退役拒绝、全局版本、回执摘要、响应丢失后查询恢复、撤销后 Token 拒绝与备用密钥审批恢复。5 分钟和排空时间通过仅属于测试的数据库夹具推进，未宣称持续等待完整生产窗口。单元与数据库测试另覆盖权限隔离、审批失效、并发重试、数据库/审计故障拒绝。
