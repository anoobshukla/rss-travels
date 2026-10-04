let pollTimer;
async function api(path,body){
  let response;
  try{response=await fetch(path,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:body===undefined?{}:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)})}catch{throw Error('Unable to connect. Check your internet connection and try again.')}
  let data;try{data=await response.json()}catch{throw Error('The login service is not available on this preview yet.')}
  if(!response.ok){if(response.status===401&&path!=='/api/login')showLogin('Your session ended. Please sign in again.');throw Error(typeof data.detail==='string'?data.detail:'Please check the fields and try again.')}
  return data;
}
function authShell(title,description,fields,button){return `<div class="auth-card"><a class="brand" href="/"><span class="mark">R</span><span>RSS <b>Travels</b><small>EVERY JOURNEY, TAKEN CARE OF</small></span></a><p class="eyebrow">YOUR TRAVEL WORKSPACE</p><h1>${title}</h1><p class="subtitle">${description}</p><form id="auth-form">${fields}<p class="error" role="alert" id="auth-error"></p><button class="primary" type="submit">${button}</button></form><p class="auth-help">Accounts are created by RSS Travels. For access or a password reset, contact an owner.</p></div>`}
function showLogin(message=''){
  clearInterval(pollTimer);account=null;bookings=[];customers=[];team=[];
  document.body.classList.add('signed-out');$('#app-screen').hidden=true;$('#auth-screen').hidden=false;$('#modal').close();$('#content').innerHTML='';
  $('#auth-screen').innerHTML=authShell('Welcome back.','Sign in to see your bookings and keep every journey organised.','<label>Email address<input type="email" name="email" autocomplete="username" required maxlength="254" placeholder="you@example.com"></label><label>Password<input type="password" name="password" autocomplete="current-password" required maxlength="128"></label>','Sign in →');$('#auth-error').textContent=message;
  $('#auth-form').onsubmit=async e=>{e.preventDefault();const form=e.target,button=form.querySelector('button');button.disabled=true;$('#auth-error').textContent='';try{account=await api('/api/login',Object.fromEntries(new FormData(form)));if(account.mustChangePassword)showPassword(true);else await enterWorkspace()}catch(error){$('#auth-error').textContent=error.message}finally{button.disabled=false}};
}
function showPassword(required=false){
  clearInterval(pollTimer);$('#app-screen').hidden=true;$('#auth-screen').hidden=false;document.body.classList.add('signed-out');
  $('#auth-screen').innerHTML=authShell(required?'Make this account yours.':'Change your password.',required?'Replace your temporary password before opening your workspace.':'Use a unique password of at least 12 characters.','<label>Current password<input type="password" name="currentPassword" autocomplete="current-password" required maxlength="128"></label><label>New password<input type="password" name="newPassword" autocomplete="new-password" required minlength="12" maxlength="128"></label><label>Confirm new password<input type="password" name="confirm" autocomplete="new-password" required minlength="12" maxlength="128"></label>','Save password →')+'<button class="text-btn" id="password-back">'+(required?'Sign out':'Back to workspace')+'</button>';
  $('#password-back').onclick=async()=>{if(required)await logout();else await enterWorkspace()};
  $('#auth-form').onsubmit=async e=>{e.preventDefault();const f=Object.fromEntries(new FormData(e.target));if(f.newPassword!==f.confirm){$('#auth-error').textContent='The new passwords do not match.';return}const button=e.target.querySelector('button');button.disabled=true;try{account=await api('/api/password',f);await enterWorkspace()}catch(error){const errorNode=$('#auth-error');if(errorNode)errorNode.textContent=error.message}finally{button.disabled=false}};
}
async function refresh(background=false){
  if(!account)return;
  const fresh=await api('/api/bookings');
  if(!account)return;
  bookings=fresh;
  if(!background||!$('#modal').open)render();
  $('#sync-status').textContent='✓ Shared workspace · Updated '+new Date().toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit'});
}
async function enterWorkspace(){
  role=account.role;page=['customer','driver'].includes(role)?'bookings':'overview';query='';filter='All';
  try{customers=['owner','employee'].includes(role)?await api('/api/customers'):[];drivers=['owner','employee'].includes(role)?await api('/api/drivers'):[];team=role==='owner'?await api('/api/users'):[];await refresh()}catch(error){showLogin(error.message);return}
  $('#auth-screen').hidden=true;$('#app-screen').hidden=false;document.body.classList.remove('signed-out');$('#account-name').textContent=account.name;
  clearInterval(pollTimer);pollTimer=setInterval(async()=>{if(document.hidden||$('#modal').open)return;try{await refresh(true)}catch(error){if(account)$('#sync-status').textContent='Updates paused: '+error.message}},15000);
}
async function logout(){try{await api('/api/logout',{})}catch(error){toast('Could not sign out: '+error.message);return}showLogin()}
$('#logout').onclick=logout;$('#change-password').onclick=()=>showPassword();
function renderTeam(){
  $('#content').innerHTML+=`<div class="section-head"><p class="subtitle">Create accounts and share temporary passwords privately. No email is sent.</p><button class="primary" id="create-account">＋ Create account</button></div>${team.map(u=>`<div class="team-row"><span class="avatar">${escape(u.name.slice(0,2).toUpperCase())}</span><div><h3>${escape(u.name)}</h3><p>${escape(u.email)} · ${escape(u.role)} · ${u.active?'Active':'Disabled'}${u.mustChangePassword?' · Password change required':''}</p></div>${u.id!==account.id?`<button class="text-btn" data-reset="${u.id}">Reset password</button>${u.role!=='owner'?`<button class="text-btn" data-active="${u.id}">${u.active?'Disable':'Enable'}</button>`:''}`:''}</div>`).join('')}`;
  $('#create-account').onclick=createAccount;
  document.querySelectorAll('[data-reset]').forEach(b=>b.onclick=()=>resetAccount(b.dataset.reset));
  document.querySelectorAll('[data-active]').forEach(b=>b.onclick=async()=>{const user=team.find(u=>u.id===b.dataset.active);b.disabled=true;try{await api('/api/users/'+user.id+'/active',{active:!user.active});await reloadTeam();toast('Account access updated')}catch(error){toast(error.message);b.disabled=false}});
}
async function reloadTeam(){drivers=await api('/api/drivers');team=await api('/api/users');customers=await api('/api/customers');render()}
function createAccount(){
  openModal(`${modalHead('Create an account')}<p class="info">Share the temporary password privately. This person must change it on first login. No email will be sent.</p><form id="account-form"><div class="fields"><label class="wide">Full name<input name="name" required maxlength="120"></label><label class="wide">Email address<input type="email" name="email" required maxlength="254" autocomplete="off"></label><label>Role<select name="role"><option value="customer">Customer — own bookings</option><option value="employee">Employee — bookings & payments</option><option value="driver">Driver — assigned trips only</option><option value="owner">Owner — full access</option></select></label><label>Temporary password<input type="password" name="password" required minlength="12" maxlength="128" autocomplete="new-password"></label></div><p class="error" id="account-error" role="alert"></p><div class="form-actions"><button class="primary">Create account</button></div></form>`);
  $('#account-form').onsubmit=async e=>{e.preventDefault();const button=e.target.querySelector('button');button.disabled=true;try{await api('/api/users',Object.fromEntries(new FormData(e.target)));$('#modal').close();await reloadTeam();toast('Account created. Share its temporary password privately.')}catch(error){$('#account-error').textContent=error.message}finally{button.disabled=false}};
}
function resetAccount(id){
  const user=team.find(u=>u.id===id);
  openModal(`${modalHead('Reset password')}<p class="info">Set a temporary password for ${escape(user.name)}. Their existing sessions will end. Share the replacement privately.</p><form id="reset-form"><div class="fields"><label class="wide">New temporary password<input name="password" type="password" required minlength="12" maxlength="128" autocomplete="new-password"></label></div><p class="error" role="alert" id="reset-error"></p><div class="form-actions"><button class="primary">Reset password</button></div></form>`);
  $('#reset-form').onsubmit=async e=>{e.preventDefault();const button=e.target.querySelector('button');button.disabled=true;try{await api('/api/users/'+id+'/reset',Object.fromEntries(new FormData(e.target)));$('#modal').close();await reloadTeam();toast('Password reset. Existing sessions revoked.')}catch(error){$('#reset-error').textContent=error.message}finally{button.disabled=false}};
}
(async()=>{showLogin();try{account=await api('/api/me');if(account.mustChangePassword)showPassword(true);else await enterWorkspace()}catch(error){if(!error.message.includes('sign in'))$('#auth-error').textContent=error.message}})();
