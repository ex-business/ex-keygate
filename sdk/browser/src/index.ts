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
export class KeygateError extends Error {
  constructor(public readonly status: number, public readonly requestId: string = '') {
    super(`Keygate request failed (${status})`);
    this.name = 'KeygateError';
  }
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new KeygateError(502);
  return value as Record<string, unknown>;
}
function timestamp(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

/** 同源 H5 会话客户端。Cookie 由浏览器管理，SDK 只短暂保存用途绑定的 CSRF，不存储密钥或 Bearer。 */
export class KeygateBrowserClient {
  readonly clientId: string;
  readonly #origin: string;
  #csrf = '';
  #busy = false;

  constructor(options: {clientId: string}) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(options.clientId) || window.location.protocol !== 'https:') {
      throw new KeygateError(400);
    }
    this.clientId = options.clientId;
    this.#origin = window.location.origin;
    Object.freeze(this);
  }

  /** 从用户点击直接导航到固定登录入口；回调的继续链接由受控服务配置决定。 */
  login(): void {
    this.#assertOrigin();
    this.#csrf = '';
    window.location.assign(`${this.#origin}/h5/login/${encodeURIComponent(this.clientId)}`);
  }

  #assertOrigin(): void {
    if (window.location.origin !== this.#origin || window.location.protocol !== 'https:') throw new KeygateError(400);
  }
  #path(suffix: string): string { return `/api/browser/${encodeURIComponent(this.clientId)}/${suffix}`; }

  async #call(path: string, method: 'GET' | 'POST', csrf = ''): Promise<unknown> {
    this.#assertOrigin();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
      const headers: Record<string, string> = {Accept: 'application/json'};
      if (method === 'POST') { headers['Content-Type'] = 'application/json'; headers['X-CSRF-Token'] = csrf; }
      // 只访问固定同源路径，不跟随重定向；超时和提交不明由调用方处理，不重放有副作用请求。
      const response = await fetch(new URL(path, this.#origin), {
        method, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        signal: controller.signal, ...(method === 'POST' ? {body: '{}'} : {})
      });
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) this.#csrf = '';
        throw new KeygateError(response.status, response.headers.get('X-Request-ID') ?? '');
      }
      if (response.status === 204) return undefined;
      if (response.headers.get('Content-Type')?.split(';')[0]?.trim() !== 'application/json') throw new KeygateError(502);
      const text = await response.text();
      if (text.length > 16384) throw new KeygateError(502);
      try {return JSON.parse(text) as unknown;} catch {throw new KeygateError(502);}
    } catch (error) {
      if (error instanceof KeygateError) throw error;
      // 不把上游正文或 Cookie 写入错误，避免业务日志无意记录凭据。
      throw new KeygateError(0);
    } finally { clearTimeout(timeout); }
  }

  #session(value: unknown): BrowserSession {
    const data = object(value);
    if (data.clientId !== this.clientId || typeof data.principalId !== 'string' ||
        !timestamp(data.authenticatedAt) || !timestamp(data.expiresAt) ||
        typeof data.csrfToken !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(data.csrfToken)) throw new KeygateError(502);
    const session: BrowserSession = {clientId:this.clientId,principalId:data.principalId,authenticatedAt:data.authenticatedAt,expiresAt:data.expiresAt,csrfToken:data.csrfToken};
    this.#csrf = session.csrfToken;
    return {...session};
  }

  async session(): Promise<BrowserSession> { return this.#session(await this.#call(this.#path('session'), 'GET')); }

  /** 已有 SSO 身份时显式建立／轮换本客户端会话；不延长原认证期限。 */
  async connect(): Promise<BrowserSession> {
    return this.#mutate(async () => {
      const identity = object(await this.#call('/auth/session', 'GET'));
      if (typeof identity.csrfToken !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(identity.csrfToken)) throw new KeygateError(502);
      return this.#session(await this.#call(this.#path('session'), 'POST', identity.csrfToken));
    });
  }

  async authenticate(): Promise<Authentication> {
    if (!this.#csrf) await this.session();
    const data = object(await this.#call(this.#path('authenticate'), 'POST', this.#csrf));
    if (data.authenticated !== true || data.clientId !== this.clientId || typeof data.principalId !== 'string' || !timestamp(data.expiresAt)) throw new KeygateError(502);
    return {authenticated:true,clientId:this.clientId,principalId:data.principalId,expiresAt:data.expiresAt};
  }

  /** 退出本 H5 客户端；不隐式退出其他客户端或企业 SSO。 */
  async logout(): Promise<void> {
    return this.#mutate(async () => {
      try {
        if (!this.#csrf) await this.session();
        await this.#call(this.#path('logout'), 'POST', this.#csrf);
      } finally { this.#csrf = ''; }
    });
  }
  async #mutate<T>(run: () => Promise<T>): Promise<T> {
    if (this.#busy) throw new KeygateError(409);
    this.#busy = true;
    try { return await run(); } finally { this.#busy = false; }
  }
}
