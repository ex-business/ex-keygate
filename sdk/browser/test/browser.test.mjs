import {test,beforeEach} from 'node:test';
import assert from 'node:assert/strict';
import {KeygateBrowserClient,KeygateError} from '../dist/index.js';
let calls,assigned;
const origin='https://keygate.example';
const csrf='a'.repeat(43);
const session={clientId:'h5-one',principalId:'oidc-subject',authenticatedAt:'2026-10-19T12:00:00Z',expiresAt:'2026-10-19T12:05:00Z',csrfToken:csrf};
function json(body,status=200){return new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json','X-Request-ID':'req-public'}});}
beforeEach(()=>{
 calls=[];assigned='';globalThis.window={location:{protocol:'https:',origin,assign:value=>{assigned=value;}}};
 Object.defineProperty(window,'localStorage',{get(){throw new Error('禁止存储凭据');}});
 Object.defineProperty(window,'sessionStorage',{get(){throw new Error('禁止存储凭据');}});
 globalThis.fetch=async(url,options)=>{calls.push({url:String(url),...options});return json(session);};
});
test('只允许HTTPS及固定客户端，登录导航不能指定第三方地址',()=>{
 assert.throws(()=>new KeygateBrowserClient({clientId:'../../other'}),KeygateError);
 const client=new KeygateBrowserClient({clientId:'h5-one'});client.login();assert.equal(assigned,origin+'/h5/login/h5-one');
 assert.throws(()=>{client.clientId='other';},TypeError);
 window.location.protocol='http:';assert.throws(()=>new KeygateBrowserClient({clientId:'h5-one'}),KeygateError);
});
test('查询及认证使用同源Cookie和用途绑定CSRF，不携带Bearer',async()=>{
 const client=new KeygateBrowserClient({clientId:'h5-one'});
 globalThis.fetch=async(url,options)=>{calls.push({url:String(url),...options});return String(url).endsWith('authenticate')?json({authenticated:true,clientId:'h5-one',principalId:session.principalId,expiresAt:session.expiresAt}):json(session);};
 const result=await client.authenticate();assert.equal(result.authenticated,true);assert.equal(calls.length,2);
 for(const call of calls){assert.equal(new URL(call.url).origin,origin);assert.equal(call.credentials,'same-origin');assert.equal(call.redirect,'error');assert.equal(call.cache,'no-store');assert.equal(call.headers.Authorization,undefined);assert.equal(call.headers.Cookie,undefined);}
 assert.equal(calls[1].headers['X-CSRF-Token'],csrf);assert.equal(calls[1].body,'{}');
});
test('connect只兑换已有身份，不混用身份CSRF和客户端CSRF',async()=>{
 const identityCSRF='b'.repeat(43);const client=new KeygateBrowserClient({clientId:'h5-one'});
 globalThis.fetch=async(url,options)=>{calls.push({url:String(url),...options});return String(url).endsWith('/auth/session')?json({csrfToken:identityCSRF}):json(session,201);};
 assert.equal((await client.connect()).clientId,'h5-one');assert.equal(calls.length,2);assert.equal(calls[1].headers['X-CSRF-Token'],identityCSRF);
});
test('失败时不重试写请求，也不自动重新建立会话',async()=>{
 const client=new KeygateBrowserClient({clientId:'h5-one'});await client.session();
 globalThis.fetch=async(url,options)=>{calls.push({url:String(url),...options});return new Response('',{status:403});};
 await assert.rejects(client.authenticate(),e=>e instanceof KeygateError&&e.status===403);
 assert.equal(calls.filter(c=>c.method==='POST').length,1);assert.equal(calls.some(c=>c.method==='POST'&&c.url.endsWith('/session')),false);
 await assert.rejects(client.session(),KeygateError);
});
test('退出清除SDK临时CSRF且保留服务端错误供调用方处理',async()=>{
 const client=new KeygateBrowserClient({clientId:'h5-one'});await client.session();
 globalThis.fetch=async(url,options)=>{calls.push({url:String(url),...options});return new Response(null,{status:204});};
 await client.logout();assert.equal(calls.at(-1).headers['X-CSRF-Token'],csrf);
 globalThis.fetch=async(url,options)=>{calls.push({url:String(url),...options});return new Response('',{status:401});};
 await assert.rejects(client.authenticate(),e=>e.status===401);assert.equal(calls.at(-1).method,'GET');
});
test('错误响应不回显正文，网络异常不重发',async()=>{
 const client=new KeygateBrowserClient({clientId:'h5-one'});
 globalThis.fetch=async()=>{calls.push(1);throw new Error('private response token');};
 await assert.rejects(client.session(),e=>e.status===0&&!e.message.includes('private'));assert.equal(calls.length,1);
});
test('客户端错配和畸形响应拒绝，未声明字段不会进入SDK结果',async()=>{
 const client=new KeygateBrowserClient({clientId:'h5-one'});
 globalThis.fetch=async()=>json({...session,clientId:'another'});await assert.rejects(client.session(),e=>e.status===502);
 globalThis.fetch=async()=>new Response('{bad',{headers:{'Content-Type':'application/json'}});await assert.rejects(client.session(),e=>e.status===502);
 globalThis.fetch=async()=>json({...session,accessToken:'unexpected'});assert.equal((await client.session()).accessToken,undefined);
});
test('同一SDK实例拒绝并发建立和退出，避免覆盖会话',async()=>{
 let release;globalThis.fetch=()=>new Promise(resolve=>{release=()=>resolve(json({csrfToken:csrf}));});
 const client=new KeygateBrowserClient({clientId:'h5-one'});const pending=client.connect();
 await assert.rejects(client.connect(),e=>e.status===409);await assert.rejects(client.logout(),e=>e.status===409);
 globalThis.fetch=async()=>json(session,201);release();await pending;
});
