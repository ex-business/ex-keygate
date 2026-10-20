'use strict';
const $=s=>document.querySelector(s);
let loginCSRF='',sessionCSRF='',challenge=null,generation=0;
function showError(message){$('#error').textContent=message;$('#error').hidden=!message;}
async function api(path,method='GET',body,prelogin=false){
 const response=await fetch(path,{method,credentials:'same-origin',cache:'no-store',redirect:'error',signal:AbortSignal.timeout(12000),headers:method==='POST'?{'Content-Type':'application/json','X-CSRF-Token':prelogin?loginCSRF:sessionCSRF}:{},body:body===undefined?undefined:JSON.stringify(body)});
 if(!response.ok){const error=new Error(response.status===401?(prelogin?'账号或密码不正确，或暂时无法登录。连续失败后请稍后重试。':'登录状态已失效，请重新登录。'):response.status===403?'验证未通过，请核对验证信息或重新登录。':response.status===429?'尝试过于频繁，请稍后再试。':response.status===503?'登录服务暂时不可用，请稍后再试。':'请求未完成，请重新核对。');error.status=response.status;throw error;}
 return response.status===204?null:response.json();
}
async function busy(button,action){if(button.disabled)return;button.disabled=true;showError('');try{await action();}catch(e){showError(e.message||'连接失败，请稍后再试。');}finally{if(button.isConnected)button.disabled=false;}}
function entry(){generation++;challenge=null;sessionCSRF='';$('#factors').replaceChildren();$('#verification').hidden=true;$('#password-form').hidden=false;$('#sso-section').hidden=false;$('#loading').hidden=true;$('#title').textContent='登录管理平台';$('#subtitle').textContent='请输入管理账号和密码。';$('#step-password').classList.add('active');$('#step-mfa').classList.remove('active');}
async function options(){const c=await api('/auth/options');loginCSRF=c.csrfToken;$('#submit-password').disabled=!c.password;$('#username').disabled=!c.password;$('#password').disabled=!c.password;$('#sso-note').hidden=!c.simulatedSSO;if(!c.password)$('#subtitle').textContent='本地账号尚未配置，请使用 SSO 或联系管理员。';}
// 口令只建立待验证会话；必须向服务端核对本人management证明，不能依赖前端状态进入业务。
async function continueSession(){const session=await api('/auth/session');sessionCSRF=session.csrfToken;const own=await api('/api/console/identity');if(own.identity.mfaVerified){location.replace('/manage');return;}
 if(!own.identity.mfaRequired)throw new Error('本地账号必须配置二次验证，请联系管理员。');
 $('#password-form').hidden=true;$('#sso-section').hidden=true;$('#verification').hidden=false;$('#loading').hidden=true;$('#title').textContent='完成安全验证';$('#subtitle').textContent='身份已确认，请使用本人已绑定的验证方式继续。';$('#step-password').classList.remove('active');$('#step-mfa').classList.add('active');
 const ticket=++generation;const result=await api('/api/mfa/challenges','POST',{purpose:'management'});if(ticket!==generation)return;renderFactors(result,ticket);
}
function renderFactors(result,ticket){
 challenge=result.state;const id=challenge.id,current=()=>generation===ticket&&challenge?.id===id;
 if(challenge.completed){continueSession().catch(e=>showError(e.message));return;}
 const container=$('#factors');container.replaceChildren();const verified=new Set(challenge.verified);
 for(const factor of challenge.factors){const card=document.createElement('div');card.className='factor';const title=document.createElement('h3');title.textContent=factor.label;card.append(title);
 if(verified.has(factor.id)){const passed=document.createElement('p');passed.className='passed';passed.textContent='已通过';card.append(passed);container.append(card);continue;}
 if(!result.available[factor.method]){const note=document.createElement('p');note.className='note';note.textContent='此验证插件尚未接入，请联系管理员。';card.append(note);container.append(card);continue;}
 const input=document.createElement('input');input.type='password';input.inputMode='numeric';input.autocomplete='one-time-code';input.maxLength=factor.method==='totp'?6:8;input.placeholder=factor.method==='totp'?'输入六位动态码':'输入八位验证码';input.setAttribute('aria-label',factor.label+' 验证码');if(factor.method!=='hardware')card.append(input);
 const prepare=document.createElement('button'),verify=document.createElement('button'),note=document.createElement('p');note.className='note';note.setAttribute('role','status');prepare.type=verify.type='button';prepare.className='plain';prepare.textContent=factor.method==='totp'?'准备动态码验证':factor.method==='hardware'?'开始硬件验证':'发送验证码';verify.textContent='验证并继续';verify.disabled=true;let hardwareOptions=null;
 const base='/api/mfa/challenges/'+encodeURIComponent(id)+'/factors/'+encodeURIComponent(factor.id);
 prepare.addEventListener('click',()=>busy(prepare,async()=>{const attempt=await api(base,'POST',{});if(!current())return;hardwareOptions=attempt.options;verify.disabled=false;note.textContent=factor.method==='totp'?'请输入验证器当前显示的动态码。':factor.method==='hardware'?'请使用本人硬件安全密钥。':'验证码已交由插件发送，请及时输入。';input.focus();}));
 verify.addEventListener('click',()=>busy(verify,async()=>{const value=input.value;input.value='';const body=factor.method==='hardware'?{proof:await hardwareAssertion(hardwareOptions)}:{code:value};const next=await api(base+'/verify','POST',body);if(current())renderFactors(next,ticket);}));
 card.append(prepare,verify,note);container.append(card);
 }
}
$('#password-form').addEventListener('submit',e=>{e.preventDefault();const form=e.currentTarget;if(!form.reportValidity())return;busy($('#submit-password'),async()=>{const value=$('#password').value;$('#password').value='';await api('/auth/password','POST',{username:$('#username').value.trim().toLowerCase(),password:value},true);await continueSession();});});
$('#cancel-login').addEventListener('click',()=>busy($('#cancel-login'),async()=>{generation++;try{await api('/auth/logout','POST');}catch(e){if(e.status!==401)throw e;}location.replace('/login');}));
(async()=>{try{await options();if(new URLSearchParams(location.search).get('reauth')==='1'){history.replaceState(null,'','/login');entry();await options();return;}try{await continueSession();}catch(e){if(e.status!==401)throw e;entry();await options();}}catch(e){$('#loading').hidden=true;showError(e.message);}})();

async function hardwareAssertion(options) {if(!options?.publicKey)throw new Error('硬件插件未提供浏览器支持的验证契约，请联系接入人员。');const decode=value=>Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));const encode=value=>btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');const publicKey=structuredClone(options.publicKey);publicKey.userVerification='required';publicKey.challenge=decode(publicKey.challenge);if(publicKey.allowCredentials)for(const c of publicKey.allowCredentials)c.id=decode(c.id);const assertion=await navigator.credentials.get({publicKey});if(!assertion)throw new Error('硬件验证未完成。');return {id:assertion.id,rawId:encode(assertion.rawId),type:assertion.type,response:{clientDataJSON:encode(assertion.response.clientDataJSON),authenticatorData:encode(assertion.response.authenticatorData),signature:encode(assertion.response.signature),userHandle:assertion.response.userHandle?encode(assertion.response.userHandle):null}};}
