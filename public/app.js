let token=null,refreshPromise=null;
const $=id=>document.getElementById(id);
function show(status,data){$('status').textContent=String(status);$('output').textContent=typeof data==='string'?data:JSON.stringify(data,null,2);}
async function call(path,{method='GET',body,retry=true}={}) {
 const response=await fetch('/api/v1'+path,{method,credentials:'same-origin',headers:{...(method!=='GET'?{'Content-Type':'application/json'}:{}),...(token?{Authorization:'Bearer '+token}:{})},...(method!=='GET'?{body:JSON.stringify(body || {})}:{})});
 const data=response.status===204?{message:'Done'}:await response.json();
 if(response.status===401 && retry && !path.startsWith('/auth/')) {try{await rotate();return call(path,{method,body,retry:false});}catch{}}
 if(!response.ok) throw Object.assign(Error(data.error || 'Request failed'),{status:response.status,data});
 return {status:response.status,data};
}
function signedIn(data){token=data.accessToken;$('auth').hidden=true;$('dashboard').hidden=false;$('greeting').textContent='Hello, '+data.user.name;$('identity').textContent=data.user.email+' / '+data.user.tenant;$('role').textContent=data.user.role;}
async function rotate(){if(!refreshPromise)refreshPromise=call('/auth/refresh',{method:'POST',retry:false}).then(r=>{signedIn(r.data);return r;}).finally(()=>refreshPromise=null);return refreshPromise;}
function reportError(e){show(e.status || 'ERROR',e.data || e.message);}
function summary(r){const data={...r.data};delete data.accessToken;show(r.status,data);}
async function payroll(){const r=await call('/payroll');$('payroll').replaceChildren();for(const item of r.data){const row=document.createElement('div');row.className='row';row.textContent=item.id+' · '+item.status;const button=document.createElement('button');button.textContent='Approve payroll';button.addEventListener('click',()=>run(async()=>{const result=await call('/payroll/approve',{method:'POST',body:{payrollId:item.id}});summary(result);await payroll();}));row.append(button);$('payroll').append(row);}if(!r.data.length)$('payroll').textContent='No payroll records in this workspace.';}
async function run(action){try{await action();}catch(e){reportError(e);}}
for(const form of ['login','register'])$(form).addEventListener('submit',async e=>{e.preventDefault();const button=e.target.querySelector('button');button.disabled=true;await run(async()=>{const r=await call('/auth/'+form,{method:'POST',body:Object.fromEntries(new FormData(e.target)),retry:false});signedIn(r.data);summary(r);e.target.elements.password.value='';await payroll();});button.disabled=false;});
$('profile').onclick=()=>run(async()=>summary(await call('/employee/profile')));
$('refresh').onclick=()=>run(async()=>{summary(await rotate());});
$('logout').onclick=()=>run(async()=>{await call('/auth/logout',{method:'POST',retry:false});token=null;$('auth').hidden=false;$('dashboard').hidden=true;$('user-list').replaceChildren();show(204,'Signed out. This session is revoked.');});
$('users').onclick=()=>run(async()=>{const r=await call('/users');show(r.status,r.data);$('user-list').replaceChildren();for(const user of r.data){const row=document.createElement('div');row.className='row';row.textContent=user.email+' · '+user.role;const button=document.createElement('button');button.className='secondary';button.textContent='Delete user';button.onclick=()=>{if(confirm('Delete '+user.email+'?'))run(async()=>{summary(await call('/users/'+user.id,{method:'DELETE'}));row.remove();});};row.append(button);$('user-list').append(row);}});
(async()=>{try{const r=await call('/config');if(!r.data.githubEnabled){$('github').hidden=true;$('oauth-note').textContent='GitHub sign-in becomes available after server OAuth credentials are configured.';}try{await rotate();await payroll();show(200,'Session restored securely.');}catch{if(location.search.includes('oauth=success'))show('ERROR','Could not restore the OAuth session. Check HTTPS and cookies.');}history.replaceState({},'',location.pathname);}catch(e){reportError(e);}})();
