# @ex-keygate/browser

同源 H5 会话 SDK，TypeScript 类型与原生 ESM 产物一并提供，无运行时第三方依赖。当前版本未发布到 npm，使用本地目录安装或由同源 ExKeyGate 提供的 `/sdk/browser.js` 导入。

```sh
npm install /path/to/ex-keygate/sdk/browser
```

```ts
import {KeygateBrowserClient, KeygateError} from '@ex-keygate/browser';
const auth = new KeygateBrowserClient({clientId: 'my-h5'});
// 登录按钮的用户点击中调用；页面将跳转到服务端固定 SSO 登录入口。
loginButton.onclick = () => auth.login();
// 回调后点击继续返回应用，再读取会话或认证。
const session = await auth.session();
const identity = await auth.authenticate();
await auth.logout();
```

服务端须已通过多人审批创建 browser/federated_session/none/oidc 客户端，并登记可登录的人员。SDK 的 clientId 是公开逻辑作用域，不是应用秘密或业务权限。H5 Cookie 不能调用管理 API。

仅 HTTPS、同源部署；同源页面与脚本必须属于同一个信任边界。跨域、嵌入式第三方页面、移动端原生和桌面端不在本期范围内。默认登录完成入口为 `/h5?client=...`；可信启动配置 `BrowserReturnPaths` 可为具体客户端固定 `/app` 等同源路径，SDK 不接受任意回调 URL。

`connect()` 可在已完成同源 SSO 后显式建立或轮换本客户端会话，继承身份到期时间；不是自动刷新。`session()` 返回身份、到期时间与临时 CSRF；`authenticate()` 校验当前实际请求；`logout()` 仅退出当前客户端。企业 SSO 或父身份退出会使其 H5 会话失效。

SDK 不读取 Cookie、不持久化密钥／凭据，不把 ID Token 当 Bearer。不要将会话响应、CSRF 或自定义错误响应正文写入日志；SDK 错误只保留 HTTP 状态与服务端 request ID。401 应重新登录；403 检查 CSRF、Origin 和权限；409 表示当前 SDK 实例正执行其他会话变更；0 表示网络／超时结果不明。写请求不自动重发或自动重新建立会话。

开发校验：`npm ci --ignore-scripts`、`npm run build`、`npm run verify`、`npm test`。`verify` 在临时目录重编译并核对已分发的 JS 和类型声明，防止源代码与产物漂移。
