# Provider 协议 v1

状态：Go 类型、能力目录和只读 HTTPS/mTLS 核验传输已实现；真实硬件、KMS/HSM 和远程副作用操作仍为预留。管理和启动见[插件管理](../插件管理.md)。

目录：
- [边界](#boundary)
- [能力声明](#capabilities)
- [硬件预留](#hardware)
- [错误与调用规则](#errors)
- [根托管与异常结果预留](#roots)

<a id="boundary"></a>
## 边界

- 协议保持语言中立，Go 类型只是本工程的实现映射。跨语言实现后使用明确的 JSON 字段及二进制编码，不依赖 Go 动态插件 ABI。
- 主服务负责客户端身份绑定、认证策略、多审批、权限、防重放、审计及事务。Provider 只提供声明的能力，不自行放宽授权。
- Descriptor 仅包含 ID、实现版本、协议版本、类型及能力，不携带 URL、设备凭据或密钥。
- 能力目录在构造后不可变，拒绝重复 ID、未知类型、未知能力和不支持的协议版本；返回描述的修改不影响目录内容。

<a id="capabilities"></a>
## 能力声明

```json
{
  "id": "example-device",
  "version": "1",
  "protocolVersion": "1",
  "kind": "hardware",
  "capabilities": ["device_info"]
}
```

此示例只是契约展示，不会注册可用设备。类型为 `local`、`third_party` 或 `hardware`；能力包括 `verify`、`create`、`rotate`、`disable`、`device_info`、`challenge`。声明能力不等于实现，运行时还必须验证对应适配器接口已接入。

<a id="hardware"></a>
## 硬件预留

- 设备信息查询：设备引用、型号、就绪状态。
- 密钥引用：只传设备内密钥 ID 与版本，不要求密钥可导出。
- 认证运算：携带请求 ID、客户端 ID、密钥引用、算法、被验证消息和证明。
- 挑战认证：预留请求 ID、主体、受众、用途和挑战 ID。实际接入前必须补齐密码学随机挑战、过期时间、一次性消费、可信验证源和设备证明验证；不能仅比对客户端声明。
- 设备内算法、生命周期与密钥不可导出策略取决于实际厂商；没有实现时拒绝，不回退软件密钥。

<a id="errors"></a>
## 错误与调用规则

统一区分能力不支持、设备不可用、描述无效和操作结果未知；认证未通过不解释为 Provider 故障后可绕过。错误向外映射时不得泄露凭据或设备内部详情。

所有运行调用携带超时上下文。对创建、轮换、停用等有副作用操作，协议扩展必须包含唯一操作 ID 和幂等/结果查询约定，结果未知时先核对，不直接重试。远程接入必须具备端点白名单、双向身份认证和网络出口限制。

### HTTPS 核验传输

服务端必须要求可信客户端证书，TLS 1.3；客户端固定服务端 CA、主机名和目标 IP 白名单，不允许代理或重定向。请求响应使用 `application/json`，二进制为标准 base64，key.version 为十进制字符串。单次三秒，不自动重试。

`GET /v1/health` 无正文，响应：

```json
{"protocolVersion":"1","providerId":"third-party-demo","providerVersion":"1","ready":true}
```

`POST /v1/verify` 请求：

```json
{"protocolVersion":"1","providerId":"third-party-demo","providerVersion":"1","requestId":"request-1","environment":"test","clientId":"plugin-diagnostic","audience":"plugin-diagnostic","purpose":"conformance","key":{"id":"mock-conformance","version":"1"},"algorithm":"ed25519","payload":"<base64>","proof":"<base64>"}
```

响应：

```json
{"protocolVersion":"1","providerId":"third-party-demo","providerVersion":"1","requestId":"request-1","requestDigest":"<lowercase SHA-256 hex>","verified":true}
```

`requestDigest` 是收到的原始请求正文完整字节的 SHA-256，不重新序列化。客户端核对协议、插件版本、请求 ID、摘要及必填布尔值。响应上限 16 KiB，payload 上限 64 KiB、proof 上限 512 字节；拒绝重复／未知字段、大小写别名、无效 UTF-8、未配对 Unicode 代理项、尾随内容和压缩响应。请求标识字段使用字母数字开头，后续仅字母数字、点、下划线或连字符，最长 128 字符。

模拟插件仅接受固定公开 conformance 向量，其证明不代表真实客户端身份。真实业务调用方仍须负责消息语义、用途绑定、客户端状态、策略和原子防重放，本批未将远程 Verifier 接入真实客户端认证路由。


<a id="roots"></a>
## 根托管与异常结果预留

`provider.RootCustodian` 预留不可变 RootReference（Provider/Key/Version/Fingerprint/Purpose）、作用域绑定的 WrapRoot/UnwrapRoot、InspectRoot 及 QueryRootOperation。`RootOperationFencer` 预留旧执行器隔离确认。明文只允许在可信调用边界内短暂传递，不能写入描述、日志或管理 HTTP。

本批没有实现或装配 KMS/HSM。现有软件执行器继续使用专用本地 Wrapper，不能把这些接口注入当前本地事务执行路径。远程适配器须另行实现幂等、预算、权威 UNKNOWN 核对及隔离验证，不能因声明接口就获准执行。
