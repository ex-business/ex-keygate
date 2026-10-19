export interface BrowserSession {
    clientId: string;
    principalId: string;
    authenticatedAt: string;
    expiresAt: string;
    csrfToken: string;
}
export interface Authentication {
    authenticated: true;
    clientId: string;
    principalId: string;
    expiresAt: string;
}
export declare class KeygateError extends Error {
    readonly status: number;
    readonly requestId: string;
    constructor(status: number, requestId?: string);
}
/** 同源 H5 会话客户端。Cookie 由浏览器管理，SDK 只短暂保存用途绑定的 CSRF，不存储密钥或 Bearer。 */
export declare class KeygateBrowserClient {
    #private;
    readonly clientId: string;
    constructor(options: {
        clientId: string;
    });
    /** 从用户点击直接导航到固定登录入口；回调的继续链接由受控服务配置决定。 */
    login(): void;
    session(): Promise<BrowserSession>;
    /** 已有 SSO 身份时显式建立／轮换本客户端会话；不延长原认证期限。 */
    connect(): Promise<BrowserSession>;
    authenticate(): Promise<Authentication>;
    /** 退出本 H5 客户端；不隐式退出其他客户端或企业 SSO。 */
    logout(): Promise<void>;
}
