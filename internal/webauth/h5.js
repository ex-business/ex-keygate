import {KeygateBrowserClient,KeygateError} from '/sdk/browser.js';
let client;
const result=document.getElementById('result');
const form=document.getElementById('client');
const actions=['login','connect','session','authenticate','logout'];
function choose(id) {
 client=new KeygateBrowserClient({clientId:id});
 form.elements.clientId.value=id;
 document.getElementById('selected').textContent=`当前客户端：${id}`;
 for(const name of actions)document.getElementById(name).disabled=false;
}
function showError(error){result.textContent=error instanceof KeygateError?`操作失败：${error.status}；401 请重新登录，403 请检查权限或 CSRF。请求：${error.requestId}`:'操作失败';}
form.addEventListener('submit',event=>{event.preventDefault();try{choose(form.elements.clientId.value);result.textContent='客户端已选择';}catch(error){showError(error);}});
for(const name of actions)document.getElementById(name).addEventListener('click',async()=>{
 if(!client)return;
 for(const action of actions)document.getElementById(action).disabled=true;
 try {
  const value=await client[name]();
  // 页面只展示身份和状态，不将 CSRF 或会话凭据写入演示输出。
  if(value&&typeof value==='object'){const {csrfToken,...publicValue}=value;result.textContent=JSON.stringify(publicValue,null,2);}
  else result.textContent='操作完成';
 }catch(error){showError(error);}
 finally{for(const action of actions)document.getElementById(action).disabled=false;}
});
const values=new URLSearchParams(window.location.search);
if([...values.keys()].some(key=>key!=='client')||values.getAll('client').length>1)result.textContent='客户端参数无效';
else if(values.get('client')){try{choose(values.get('client'));result.textContent='可以查询会话或认证';}catch(error){showError(error);}}
