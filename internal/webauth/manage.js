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
  if (!response.ok) throw new Error(`${response.status}: ${text}`);
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
  document.getElementById('identity').textContent = `身份：${session.principalId}；管理读取权限：${session.managementAuthorized ? '已授权' : '未授权'}；会话到期：${session.expiresAt}`;
  config = await call('/api/config');
  clients = await call('/api/clients');
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
    if (!record.executed && record.decision === 'pending') {
      action(row, '批准此摘要', () => call(`/api/requests/${encodeURIComponent(record.id)}/votes`, 'POST', {digest: record.digest, accept: true}));
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
    session = undefined; config = undefined; clients = [];
    for (const id of ['requests', 'clients', 'profiles']) document.getElementById(id).replaceChildren();
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
    if (operation.kind === 'key_issue') {
      if (data.get('rotationOf')) operation.rotationOf = data.get('rotationOf');
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
