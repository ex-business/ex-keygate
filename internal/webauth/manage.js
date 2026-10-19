'use strict';
let session;
let config;
let clients = [];
const result = document.getElementById('result');
async function call(path, method = 'GET', data) {
  const headers = {};
  if (method === 'POST') {
    headers['Content-Type'] = 'application/json';
    headers['X-CSRF-Token'] = session?.csrfToken || '';
    headers['X-Idempotency-Key'] = crypto.randomUUID();
  }
  const response = await fetch(path, {method, headers, credentials: 'same-origin', body: data === undefined ? undefined : JSON.stringify(data)});
  const text = await response.text();
  if (!response.ok) {const error=new Error(`${response.status}: ${text}`);error.status=response.status;throw error;}
  return text ? JSON.parse(text) : null;
}
function option(parent, value, label) {
  const node = document.createElement('option');
  node.value = value;
  node.textContent = label;
  parent.append(node);
}
function action(row, label, callback) {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  button.addEventListener('click', async () => {
    button.disabled = true;
    try { result.textContent = JSON.stringify(await callback(), null, 2); await refresh(); }
    catch (error) { result.textContent = error.message; }
    finally { button.disabled = false; }
  });
  row.append(button);
}
async function refresh() {
  session = await call('/auth/session');
  document.getElementById('identity').textContent = `身份：${session.principalId}；全域配置读取权限：${session.managementAuthorized ? '已授权' : '未授权'}；会话到期：${session.expiresAt}`;
  // 独立审计员和局部授权无需全域 Profile；仅容忍明确的权限拒绝，其余故障继续提示。
  try {config = await call('/api/config');}
  catch(error) {if(error.status!==403) throw error;config={profiles:[],rootId:''};}
  clients = await call('/api/clients');
  await refreshProviders();
  const records = await call('/api/requests');
  const profiles = document.getElementById('profiles');
  profiles.replaceChildren();
  for (const profile of config.profiles) option(profiles, profile.id, `${profile.clientType} / ${profile.method}`);
  const selector = document.getElementById('clients');
  const selectedClient = selector.value;
  selector.replaceChildren();
  for (const client of clients) option(selector, client.id, `${client.id} / ${client.type} / ${client.state} / rev ${client.revision}`);
  if (clients.some(client => client.id === selectedClient)) selector.value = selectedClient;
  document.getElementById('client-state').textContent = JSON.stringify(clients, null, 2);
  const queue = document.getElementById('requests');
  queue.replaceChildren();
  for (const record of records) {
    const row = document.createElement('section');
    const pre = document.createElement('pre');
    pre.textContent = JSON.stringify(record, null, 2);
    row.append(pre);
    if (record.progress) {
      const progress = document.createElement('p');
      progress.textContent = `人员流转：${record.progress.completed}/${record.progress.m}，候选人数 ${record.progress.n}；当前人员：${record.progress.currentPrincipalId || '已结束'}`;
      row.append(progress);
    }
    if (!record.executed && record.decision === 'pending' && (!record.progress || record.progress.currentPrincipalId === session.principalId)) {
      action(row, '验证本次申请', async () => {document.getElementById('mfa-purpose').value=record.id;return startMFA(record.id);});
      action(row, '批准此摘要', () => call(`/api/requests/${encodeURIComponent(record.id)}/votes`, 'POST', {digest: record.digest, accept: true}));
      if(record.progress) action(row, '本人放弃并转交（不计赞成）',()=>call(`/api/requests/${encodeURIComponent(record.id)}/skip`,'POST',{digest:record.digest,reason:'本人明确放弃本次审批'}));
      action(row, '拒绝此摘要', () => call(`/api/requests/${encodeURIComponent(record.id)}/votes`, 'POST', {digest: record.digest, accept: false}));
    }
    if (!record.executed && record.decision === 'approved') action(row, '原申请人执行', () => call(`/api/requests/${encodeURIComponent(record.id)}/execute`, 'POST', {digest: record.digest}));
    queue.append(row);
  }
}
async function submit(callback) {
  try { result.textContent = JSON.stringify(await callback(), null, 2); await refresh(); }
  catch (error) { result.textContent = error.message; }
}
document.getElementById('refresh').addEventListener('click', async () => {try {await refresh();} catch (error) {result.textContent = error.message;}});
document.getElementById('logout').addEventListener('click', async () => {
  try {
    await call('/auth/logout', 'POST');
    session = undefined; config = undefined; clients = []; mfaState=undefined;document.getElementById('mfa-factors').replaceChildren();document.getElementById('mfa-state').textContent='';
    for (const id of ['requests', 'clients', 'profiles', 'providers']) document.getElementById(id).replaceChildren();
    document.getElementById('client-state').textContent = '';
    document.getElementById('key-state').textContent = '';
    document.getElementById('identity').textContent = '已退出';
    result.textContent = '已退出';
  } catch (error) {result.textContent = error.message;}
});
document.getElementById('create').addEventListener('submit', event => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  submit(() => call('/api/requests', 'POST', {kind: 'client_create', clientId: data.get('clientId'), expectedRevision: '0', name: data.get('name'), profileId: data.get('profileId'), profileVersion: '1'}));
});
document.getElementById('key-operation').addEventListener('submit', event => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  submit(async () => {
    const client = clients.find(item => item.id === data.get('clientId'));
    if (!client) throw new Error('请先创建客户端并刷新状态');
    const operation = {kind: data.get('kind'), clientId: client.id, expectedRevision: client.revision, name: '', profileId: '', profileVersion: '0', keyVersion: data.get('keyVersion')};
    if (operation.kind.startsWith('recovery_')) for (const field of ['recoveryId','incidentId','evidenceHash']) operation[field]=data.get(field);
    if (operation.kind === 'key_issue' || operation.kind === 'recovery_issue') {
      if (data.get('rotationOf')) {operation.rotationOf = data.get('rotationOf');operation.rotationReason=data.get('rotationReason');}
      const recipient = JSON.parse(data.get('recipient'));
      for (const key of ['recipientPublicKey', 'recipientFingerprint', 'recipientSigningKey', 'recipientSigningFingerprint']) {
        if (typeof recipient[key] !== 'string') throw new Error(`缺少接收方字段 ${key}`);
        operation[key] = recipient[key];
      }
      operation.rootId = config.rootId;
      operation.notAfter = new Date(Date.now() + 3600000).toISOString();
    }
    if (data.get('retireAt')) operation.retireAt = data.get('retireAt');
    return call('/api/requests', 'POST', operation);
  });
});
submit(refresh);

async function keyState() {
  const data = new FormData(document.getElementById('key-operation'));
  if (!data.get('clientId')) throw new Error('请先选择客户端');
  const state = await call(`/api/clients/${encodeURIComponent(data.get('clientId'))}/keys/${encodeURIComponent(data.get('keyVersion'))}`);
  document.getElementById('key-state').textContent = JSON.stringify(state, null, 2);
}
document.getElementById('key-status').addEventListener('click', async () => {
  try {await keyState();} catch (error) {document.getElementById('key-state').textContent = error.message;}
});

document.getElementById('lifecycle-status').addEventListener('click', () => submit(() => call(`/api/clients/${encodeURIComponent(document.getElementById('clients').value)}/lifecycle`)));
document.getElementById('lifecycle-maintain').addEventListener('click', () => submit(() => call('/api/lifecycle/maintain', 'POST', {})));

document.getElementById('revoke').addEventListener('submit',event=>{event.preventDefault();const d=new FormData(event.currentTarget);submit(()=>{const key=new FormData(document.getElementById('key-operation'));const root=d.get('scope')==='root';return call('/api/revocations','POST',{incidentId:d.get('incidentId'),reason:d.get('reason'),clientId:root?'':key.get('clientId'),keyVersion:root?'0':key.get('keyVersion'),rootId:root?config.rootId:''});});});

document.getElementById('recovery-status').addEventListener('click',()=>submit(()=>call(`/api/clients/${encodeURIComponent(document.getElementById('clients').value)}/recoveries`)));
document.getElementById('abort-recovery').addEventListener('submit',e=>{e.preventDefault();submit(()=>call(`/api/recoveries/${encodeURIComponent(new FormData(e.target).get('id'))}/abort`,'POST',{}));});
document.getElementById('provision-root').addEventListener('submit',e=>{e.preventDefault();submit(()=>call('/api/requests','POST',{kind:'root_provision',clientId:'root-management',expectedRevision:'0',name:'',profileId:'',profileVersion:'0',rootId:new FormData(e.target).get('rootId')}));});

document.getElementById('audit').addEventListener('submit',e=>{e.preventDefault();const d=new FormData(e.target);const exportMode=e.submitter.value==='export';submit(()=>call(exportMode?'/api/audit/exports':'/api/audit/query','POST',{clientId:d.get('clientId'),action:d.get('action'),result:d.get('result'),requestId:d.get('requestId'),targetId:d.get('targetId'),after:exportMode?'0':d.get('after'),limit:exportMode?5000:100,from:new Date(Date.now()-86400000).toISOString(),until:new Date().toISOString()}));});
document.getElementById('audit-exports').addEventListener('click',()=>submit(()=>call('/api/audit/exports')));
document.getElementById('auth-failures').addEventListener('click',()=>submit(()=>call('/api/audit/auth-failures')));
document.getElementById('audit-download').addEventListener('submit',async e=>{e.preventDefault();try{const id=new FormData(e.target).get('id');const response=await fetch(`/api/audit/exports/${encodeURIComponent(id)}`,{credentials:'same-origin'});if(!response.ok)throw new Error(`下载拒绝 ${response.status}`);const url=URL.createObjectURL(await response.blob());const link=document.createElement('a');link.href=url;link.download='keygate-audit.jsonl';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(error){result.textContent=error.message;}});

async function refreshProviders() {
  const container = document.getElementById('providers');
  container.replaceChildren();
  let plugins;
  try {plugins = await call('/api/providers');}
  catch (error) {if (error.status !== 403) throw error;container.textContent='当前身份无全域插件查看权限';return;}
  for (const item of plugins) {
    const row=document.createElement('section');
    const pre=document.createElement('pre');
    pre.textContent=JSON.stringify(item,null,2);row.append(pre);
    const policy=item.policy;
    if (item.installedDigest && item.executor !== 'reserved') {
      action(row,'申请启用当前安装配置（多人审批）',()=>call('/api/requests','POST',{kind:'provider_enable',clientId:'provider-management',expectedRevision:String(policy.Revision),providerId:policy.ID,providerDigest:item.installedDigest}));
      if(policy.Enabled && policy.Digest===item.installedDigest) action(row,'健康检查 / 公开向量自检',()=>call(`/api/providers/${encodeURIComponent(policy.ID)}/check`,'POST',{}));
    }
    if(policy.Enabled) action(row,'应急停用插件',()=>call(`/api/providers/${encodeURIComponent(policy.ID)}/disable`,'POST',{}));
    if(item.executor==='reserved') {const note=document.createElement('p');note.textContent='接口预留，尚无可执行实现';row.append(note);}
    container.append(row);
  }
}

let mfaState;
async function startMFA(purpose) {
 const response=await call('/api/mfa/challenges','POST',{purpose});
 renderMFA(response);return {challengeId:response.state.id,completed:response.state.completed};
}
function renderMFA(response) {
 mfaState=response.state;
 document.getElementById('mfa-state').textContent=JSON.stringify({purpose:mfaState.purpose,completed:mfaState.completed,verified:mfaState.verified,policy:mfaState.policy,expiresAt:mfaState.expiresAt},null,2);
 const container=document.getElementById('mfa-factors');container.replaceChildren();
 for (const factor of mfaState.factors) {
  const row=document.createElement('section');const label=document.createElement('p');label.textContent=`${factor.label} (${factor.method})`;
  row.append(label);
  if (!response.available[factor.method]) {label.textContent+='：插件未配置，不能计入验证';container.append(row);continue;}
  if (mfaState.completed || mfaState.verified.includes(factor.id)) {label.textContent+='：已完成';container.append(row);continue;}
  const input=document.createElement('input');input.type='password';input.autocomplete='one-time-code';input.maxLength=8;input.setAttribute('aria-label',factor.label+' 验证码');
  if (factor.method!=='hardware') row.append(input);
  const base=`/api/mfa/challenges/${encodeURIComponent(mfaState.id)}/factors/${encodeURIComponent(factor.id)}`;
  const status=document.createElement('span');row.append(status);
  const begin=document.createElement('button');begin.type='button';begin.textContent=factor.method==='totp'?'准备动态码验证':factor.method==='hardware'?'开始硬件验证':'发送验证码';
  let hardwareOptions;
  begin.addEventListener('click',async()=>{
   begin.disabled=true;
   try {const attempt=await call(base,'POST',{});hardwareOptions=attempt.options;status.textContent=' 已准备验证';verify.disabled=false;}
   catch(error){status.textContent=error.message;}
  });row.append(begin);
  const verify=document.createElement('button');verify.type='button';verify.textContent='核验此方式';verify.disabled=true;
  verify.addEventListener('click',async()=>{
   verify.disabled=true;
   try {
    let body={code:input.value};input.value='';
    if(factor.method==='hardware') {
     // 页面只执行明确的WebAuthn客户端契约；不把任意插件脚本加载进同源管理页面。
     if(!hardwareOptions?.publicKey) throw new Error('当前硬件插件未提供 WebAuthn publicKey 客户端契约');
     const decode=value=>Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
     const encode=value=>btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
     const options=structuredClone(hardwareOptions.publicKey);options.userVerification='required';options.challenge=decode(options.challenge);
     if(options.allowCredentials) for(const credential of options.allowCredentials) credential.id=decode(credential.id);
     const assertion=await navigator.credentials.get({publicKey:options});
     body={proof:{id:assertion.id,rawId:encode(assertion.rawId),type:assertion.type,response:{clientDataJSON:encode(assertion.response.clientDataJSON),authenticatorData:encode(assertion.response.authenticatorData),signature:encode(assertion.response.signature),userHandle:assertion.response.userHandle?encode(assertion.response.userHandle):null}}};
    }
    const response=await call(base+'/verify','POST',body);renderMFA(response);
    if(response.state.completed){document.getElementById('result').textContent='本人验证已完成，请返回申请行确认；确认后才转交下一人。';try{await refresh();}catch{}}
   }catch(error){status.textContent=error.message;verify.disabled=false;}
  });row.append(verify);container.append(row);
 }
}
document.getElementById('mfa-start').addEventListener('click',async()=>{
 try{await startMFA(document.getElementById('mfa-purpose').value);}catch(error){document.getElementById('mfa-state').textContent=error.message;}
});
