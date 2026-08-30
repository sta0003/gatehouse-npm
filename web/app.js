const $ = selector => document.querySelector(selector);
let hosts = [], stats = null, users = [], backupInfo = null, me = null, currentView = 'overview', livePaused = false;

async function api(path, options={}) {
  const response = await fetch(path, {headers:{'Content-Type':'application/json'}, ...options});
  const body = await response.json().catch(()=>({}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}
function toast(message){const el=$('#toast');el.textContent=message;el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2400)}
function esc(value){return String(value).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}
function formatNumber(value){return new Intl.NumberFormat(undefined,{notation:value>9999?'compact':'standard',maximumFractionDigits:1}).format(value)}
function formatBytes(value){if(!value)return '0 B';const units=['B','KB','MB','GB'];const index=Math.min(Math.floor(Math.log(value)/Math.log(1024)),3);return `${(value/1024**index).toFixed(index?1:0)} ${units[index]}`}

async function boot(){
  const status=await api('/api/status');
  $('#login').classList.toggle('hidden',status.authenticated);
  $('#app').classList.toggle('hidden',!status.authenticated);
  if(!status.authenticated)return;
  me=await api('/api/me');
  $('#users-nav').classList.toggle('hidden',me.role!=='admin');
  $('#backups-nav').classList.toggle('hidden',me.role!=='admin');
  $('#password-warning').classList.toggle('hidden',!status.default_password);
  await refreshAll();
}
async function refreshAll(){
  const results=await Promise.all([api('/api/hosts'),api('/api/stats'),me?.role==='admin'?api('/api/users'):Promise.resolve([]),me?.role==='admin'?api('/api/backups/info'):Promise.resolve(null)]);
  [hosts,stats,users,backupInfo]=results;
  renderHosts();renderStats();renderUsers();renderCertificates();renderBackupInfo();
}
async function refreshStats(){try{stats=await api('/api/stats');renderStats()}catch(_) {}}

function setView(view){
  if(!['overview','routes','certificates','activity','users','backups'].includes(view) || (['users','backups'].includes(view)&&me?.role!=='admin')) view='overview';
  currentView=view;
  const copy={overview:['OVERVIEW','Network overview'],routes:['PROXY HOSTS','Proxy hosts'],certificates:['CERTIFICATES','TLS certificates'],activity:['LIVE TRAFFIC','Live traffic'],users:['USERS','User management'],backups:['BACKUP & RESTORE','Disaster recovery']}[view];
  $('#view-crumb').textContent=copy[0];$('#view-title').textContent=copy[1];
  $('#metrics-section').classList.toggle('hidden',view!=='overview');
  $('#charts-section').classList.toggle('hidden',view!=='overview');
  $('#lower-section').classList.toggle('hidden',['activity','users','certificates','backups'].includes(view));
  $('#lower-section').classList.toggle('single',view!=='overview');
  $('#routes').classList.toggle('hidden',!['overview','routes'].includes(view));
  $('#activity').classList.toggle('hidden',view!=='overview');
  $('#traffic-detail').classList.toggle('hidden',view!=='activity');
  $('#certificates-detail').classList.toggle('hidden',view!=='certificates');
  $('#users-detail').classList.toggle('hidden',view!=='users');
  $('#backups-detail').classList.toggle('hidden',view!=='backups');
  $('#add-host').classList.toggle('hidden',['users','backups'].includes(view));
  $('#route-kicker').textContent=view==='certificates'?'TLS MANAGEMENT':'ROUTING';
  $('#route-title').textContent=view==='certificates'?'Certificates':'Proxy hosts';
  $('#search').placeholder=view==='certificates'?'Search certificates':'Search routes';
  document.querySelectorAll('.sidebar nav a').forEach(link=>link.classList.toggle('active',link.dataset.view===view));
  renderHosts();renderCertificates();
}

function renderBackupInfo(){
  if(!backupInfo)return;
  $('#backup-route-count').textContent=backupInfo.routes;
  $('#backup-user-count').textContent=backupInfo.users;
  $('#backup-cert-count').textContent=backupInfo.certificates;
}

function renderStats(){
  const active=hosts.filter(host=>host.enabled).length;
  $('#request-count').textContent=formatNumber(stats.requests);
  $('#request-note').textContent=stats.requests?`${formatBytes(stats.bytes)} transferred`:'No traffic recorded';
  $('#active-count').textContent=active;
  $('#route-note').textContent=`${hosts.length} configured · ${hosts.filter(host=>host.certificate).length} secured`;
  $('#latency').textContent=formatNumber(stats.avg_latency_ms);
  $('#error-rate').textContent=stats.error_rate;
  $('#error-note').textContent=stats.error_rate===0?'Healthy':stats.error_rate<5?'Within tolerance':'Needs attention';
  $('#nav-route-count').textContent=hosts.length;
  drawTraffic();drawStatus();renderActivity();renderLiveTraffic();
}
function drawTraffic(){
  const svg=$('#traffic-chart'), values=stats.timeline, width=900, height=225, pad={l:38,r:12,t:12,b:28};
  const max=Math.max(1,...values.map(point=>point.requests));
  const x=index=>pad.l+index*(width-pad.l-pad.r)/(values.length-1);
  const y=value=>height-pad.b-value*(height-pad.t-pad.b)/max;
  const line=values.map((point,index)=>`${index?'L':'M'}${x(index).toFixed(1)},${y(point.requests).toFixed(1)}`).join(' ');
  const errors=values.map((point,index)=>`${index?'L':'M'}${x(index).toFixed(1)},${y(point.errors).toFixed(1)}`).join(' ');
  const area=`${line} L${x(values.length-1)},${height-pad.b} L${x(0)},${height-pad.b} Z`;
  const grid=[0,.25,.5,.75,1].map(ratio=>`<line class="chart-gridline" x1="${pad.l}" y1="${y(max*ratio)}" x2="${width-pad.r}" y2="${y(max*ratio)}"/><text class="chart-label" x="${pad.l-8}" y="${y(max*ratio)+3}" text-anchor="end">${Math.round(max*ratio)}</text>`).join('');
  const labels=values.map((point,index)=>index%4===0?`<text class="chart-label" x="${x(index)}" y="${height-7}" text-anchor="middle">${new Date(point.time).toLocaleTimeString([],{hour:'numeric'})}</text>`:'').join('');
  svg.setAttribute('viewBox',`0 0 ${width} ${height}`);
  svg.innerHTML=`<defs><linearGradient id="traffic-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#39d8e8" stop-opacity=".28"/><stop offset="1" stop-color="#39d8e8" stop-opacity="0"/></linearGradient></defs>${grid}${labels}<path class="chart-area" d="${area}"/><path class="chart-line" d="${line}"/><path class="chart-error-line" d="${errors}"/>`;
  $('#chart-empty').classList.toggle('hidden',stats.requests!==0);
}
function drawStatus(){
  const colors={'2xx':'#5de3a3','3xx':'#39d8e8','4xx':'#ffbe5c','5xx':'#ff6684'}, circumference=2*Math.PI*58;
  const total=Object.values(stats.status).reduce((sum,value)=>sum+value,0);let offset=0;
  $('#donut-series').innerHTML=Object.entries(stats.status).map(([name,value])=>{const length=total?value/total*circumference:0;const circle=`<circle class="donut-segment" cx="80" cy="80" r="58" stroke="${colors[name]}" stroke-dasharray="${length} ${circumference-length}" stroke-dashoffset="${-offset}"/>`;offset+=length;return circle}).join('');
  $('#donut-total').textContent=formatNumber(total);
  $('#status-legend').innerHTML=Object.entries(stats.status).map(([name,value])=>`<div class="status-item"><i style="background:${colors[name]}"></i><span>${name}</span><strong>${formatNumber(value)}</strong></div>`).join('');
}
function renderActivity(){
  $('#activity-list').innerHTML=stats.recent.length?stats.recent.map(item=>`<div class="activity-row"><span class="status-code ${item.status>=400?'bad':''}">${item.status}</span><div><strong>${esc(item.host)}</strong><small>${item.latency_ms}ms response</small></div><time>${new Date(item.time).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</time></div>`).join(''):'<div class="activity-empty">Waiting for the first request…</div>';
}
function renderLiveTraffic(){
  if(!stats.live)return;
  $('#live-request-count').textContent=formatNumber(stats.live.requests);
  $('#live-byte-count').textContent=formatBytes(stats.live.bytes);
  $('#live-source-count').textContent=formatNumber(stats.live.sources);
  $('#last-updated').textContent=livePaused?'Updates paused':`Updated ${new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'})}`;
  drawLiveChart();renderDestinations();renderSources();renderLiveStream();
}
function drawLiveChart(){
  const svg=$('#live-traffic-chart'),values=stats.minute_timeline||[],width=900,height=225,pad={l:38,r:12,t:12,b:28};
  if(!values.length)return;
  const max=Math.max(1,...values.map(point=>point.requests)),barWidth=Math.max(2,(width-pad.l-pad.r)/values.length-3);
  const x=index=>pad.l+index*(width-pad.l-pad.r)/values.length;
  const y=value=>height-pad.b-value*(height-pad.t-pad.b)/max;
  const grid=[0,.25,.5,.75,1].map(ratio=>`<line class="chart-gridline" x1="${pad.l}" y1="${y(max*ratio)}" x2="${width-pad.r}" y2="${y(max*ratio)}"/><text class="chart-label" x="${pad.l-8}" y="${y(max*ratio)+3}" text-anchor="end">${Math.round(max*ratio)}</text>`).join('');
  const bars=values.map((point,index)=>`<rect x="${x(index)}" y="${y(point.requests)}" width="${barWidth}" height="${height-pad.b-y(point.requests)}" rx="2" fill="${point.requests?'#39d8e8':'rgba(255,255,255,.035)'}" opacity="${point.requests?'.78':'1'}"><title>${new Date(point.time).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}: ${point.requests} requests, ${formatBytes(point.bytes)}</title></rect>`).join('');
  const labels=values.map((point,index)=>index%15===0?`<text class="chart-label" x="${x(index)}" y="${height-7}">${new Date(point.time).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</text>`:'').join('');
  svg.setAttribute('viewBox',`0 0 ${width} ${height}`);svg.innerHTML=`${grid}${bars}${labels}`;
}
function renderDestinations(){
  const max=Math.max(1,...stats.destinations.map(item=>item.requests));
  $('#destination-list').innerHTML=stats.destinations.length?stats.destinations.map(item=>`<div class="breakdown-row"><div class="breakdown-top"><strong title="${esc(item.host)}">${esc(item.host)}</strong><small>${formatNumber(item.requests)} req</small></div><div class="meter"><i style="width:${item.requests/max*100}%"></i></div><div class="breakdown-meta"><span title="${esc(item.upstream)}">${esc(item.upstream)}</span><span>${formatBytes(item.bytes)} · ${item.errors} errors</span></div></div>`).join(''):'<div class="activity-empty">No destination traffic yet.</div>';
}
function renderSources(){
  const max=Math.max(1,...stats.sources.map(item=>item.requests));
  $('#source-list').innerHTML=stats.sources.length?stats.sources.slice(0,10).map(item=>`<div class="breakdown-row"><div class="breakdown-top"><strong>${esc(item.ip)}</strong><small>${formatNumber(item.requests)} req</small></div><div class="meter"><i style="width:${item.requests/max*100}%"></i></div><div class="breakdown-meta"><span>${formatBytes(item.bytes)}</span><span>Last ${new Date(item.last_seen).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</span></div></div>`).join(''):'<div class="activity-empty">No source addresses yet.</div>';
}
function statusClass(code){return code>=500?'server-error':code>=400?'client-error':code>=300?'redirect':''}
function renderLiveStream(){
  const query=$('#traffic-filter').value.toLowerCase();
  const rows=stats.recent.filter(item=>`${item.source} ${item.host} ${item.uri} ${item.upstream} ${item.status}`.toLowerCase().includes(query));
  $('#live-stream').innerHTML=rows.length?rows.map(item=>`<div class="stream-row"><time>${new Date(item.time).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'})}</time><span class="stream-source" title="${esc(item.source)}">${esc(item.source)}</span><span class="stream-request" title="${esc(item.uri)}"><b class="stream-method">${esc(item.method)}</b>${esc(item.uri)}</span><span class="stream-destination"><strong>${esc(item.host)}</strong><small title="${esc(item.upstream)}">${esc(item.upstream)}</small></span><span class="stream-status ${statusClass(item.status)}">${item.status}</span><span class="stream-latency">${item.latency_ms} ms</span><span class="stream-size">${formatBytes(item.bytes)}</span></div>`).join(''):'<div class="stream-empty">No matching requests.</div>';
}
function renderUsers(){
  if(!me||me.role!=='admin')return;
  $('#users-list').innerHTML=users.map(user=>`<div class="user-row"><div class="user-identity"><span class="user-avatar">${esc(user.username[0].toUpperCase())}</span><div><strong>${esc(user.username)}</strong><small>${user.id===me.id?'Current account':'Dashboard account'}</small></div></div><span class="role-badge ${user.role}">${user.role==='admin'?'ADMINISTRATOR':'OPERATOR'}</span><span class="state ${user.enabled?'on':''}">${user.enabled?'ENABLED':'DISABLED'}</span><span class="user-created">${new Date(user.created_at*1000).toLocaleDateString()}</span><div class="user-actions"><button class="edit-user" data-id="${user.id}" aria-label="Edit user"><svg viewBox="0 0 24 24"><path d="m14 6 4 4M5 19l3.5-.7L19 7.8 16.2 5 5.7 15.5 5 19Z"/></svg></button>${user.id!==me.id?`<button class="delete-user" data-id="${user.id}" aria-label="Delete user"><svg viewBox="0 0 24 24"><path d="M5 7h14m-9-3h4m-7 3 1 13h8l1-13M10 11v5m4-5v5"/></svg></button>`:''}</div></div>`).join('');
}
function openUser(user={}){
  const form=$('#user-form'),isSelf=user.id===me.id;form.reset();form.id.value=user.id||'';form.username.value=user.username||'';form.role.value=user.role||'operator';form.enabled.checked=user.enabled??true;form.password.required=!user.id;form.username.disabled=isSelf;form.role.disabled=isSelf;form.enabled.disabled=isSelf;$('#password-help').textContent=user.id?'Leave blank to keep the current password':'At least 12 characters';$('#user-dialog-title').textContent=user.id?'Edit user':'Add user';$('#user-form-error').textContent='';$('#user-dialog').showModal();
}
function certificateStatus(info){return {valid:'VALID',expiring:'EXPIRING SOON',expired:'EXPIRED',invalid:'INVALID',missing:'NOT INSTALLED',not_enabled:'NOT ENABLED'}[info?.status]||'UNKNOWN'}
function renderCertificates(){
  const list=$('#certificate-list');if(!list)return;
  const installed=hosts.filter(host=>host.certificate_info?.installed),expiring=installed.filter(host=>['expiring','expired','invalid'].includes(host.certificate_info.status)),missing=hosts.filter(host=>!host.certificate_info?.installed);
  $('#cert-protected').textContent=installed.length;$('#cert-coverage').textContent=hosts.length?`${Math.round(installed.length/hosts.length*100)}% of proxy hosts protected`:'No proxy hosts configured';$('#cert-expiring').textContent=expiring.length;$('#cert-missing').textContent=missing.length;
  const next=installed.filter(host=>host.certificate_info.expires_at).sort((a,b)=>new Date(a.certificate_info.expires_at)-new Date(b.certificate_info.expires_at))[0];
  $('#cert-next-expiry').textContent=next?new Date(next.certificate_info.expires_at).toLocaleDateString([],{day:'2-digit',month:'short'}):'—';$('#cert-next-note').textContent=next?`${next.certificate_info.days_remaining} days · ${next.domains.split(' ')[0]}`:'No active certificate';
  const query=$('#certificate-search').value.toLowerCase();const shown=hosts.filter(host=>`${host.domains} ${host.certificate_info?.issuer||''} ${certificateStatus(host.certificate_info)}`.toLowerCase().includes(query));
  list.innerHTML=shown.length?shown.map(host=>{const info=host.certificate_info||{status:'missing'},primary=host.domains.split(' ')[0],aliases=host.domains.split(' ').slice(1);return `<div class="certificate-row"><div class="certificate-domain"><span class="certificate-mark ${info.installed?'secure':''}"><svg viewBox="0 0 24 24"><path d="M12 3 5 6v5c0 4.6 2.9 8 7 10 4.1-2 7-5.4 7-10V6l-7-3Z"/>${info.installed?'<path d="m9 12 2 2 4-5"/>':''}</svg></span><div><strong>${esc(primary)}</strong><small>${aliases.length?`${aliases.length} additional name${aliases.length===1?'':'s'}`:'Primary hostname only'}</small></div></div><span class="cert-status ${esc(info.status)}">${certificateStatus(info)}</span><div class="certificate-issuer"><strong>${esc(info.issuer||'—')}</strong><small title="${esc(info.serial||'')}">${info.serial?`Serial …${esc(info.serial.slice(-12))}`:'No certificate metadata'}</small></div><div class="certificate-expiry"><strong>${info.expires_at?new Date(info.expires_at).toLocaleDateString():'—'}</strong><small>${info.days_remaining===null||info.days_remaining===undefined?'Not issued':info.days_remaining<0?`${Math.abs(info.days_remaining)} days overdue`:`${info.days_remaining} days remaining`}</small></div><div class="certificate-renewal"><strong>${info.installed?'Automatic':'Not configured'}</strong><small>${info.installed?'Checked every 12 hours':'Request a certificate'}</small></div><div class="certificate-actions">${info.installed?`<button class="ghost renew-cert" data-id="${host.id}">Renew</button>`:`<button class="primary request-cert" data-id="${host.id}">Enable HTTPS</button>`}<button class="icon-button cert-edit" data-id="${host.id}" aria-label="Edit proxy host"><svg viewBox="0 0 24 24"><path d="m14 6 4 4M5 19l3.5-.7L19 7.8 16.2 5 5.7 15.5 5 19Z"/></svg></button></div></div>`}).join(''):'<div class="certificate-empty">No matching certificates.</div>';
}
function openCertificate(host,renew=false){const form=$('#cert-form');form.reset();form.id.value=host.id;form.force.value=renew?'1':'0';$('#cert-dialog-title').textContent=renew?'Renew certificate':'Enable HTTPS';$('#cert-dialog-info').textContent=renew?`This immediately requests a replacement certificate for ${host.domains.split(' ')[0]}. Use it only when renewal is required.`:'Public DNS must point to this gateway and inbound port 80 must be reachable before requesting a certificate.';$('#cert-email-label').classList.toggle('hidden',renew);form.email.required=!renew;$('#cert-submit').textContent=renew?'Renew certificate':'Request certificate';$('#cert-error').textContent='';$('#cert-dialog').showModal()}
function renderHosts(){
  const query=$('#search').value.toLowerCase();
  const shown=hosts.filter(host=>`${host.domains} ${host.upstream_host}`.toLowerCase().includes(query)).sort((a,b)=>currentView==='certificates'?Number(b.certificate)-Number(a.certificate):0);
  $('#empty').classList.toggle('hidden',hosts.length!==0);
  $('#hosts').innerHTML=shown.map(host=>`<article class="host-row">
    <div class="domain-cell"><strong>${esc(host.domains.split(' ')[0])}</strong><small>${host.domains.split(' ').slice(1).map(esc).join(' · ')||'Primary hostname'}</small></div>
    <div class="target-cell"><span>${esc(host.upstream_scheme)}://${esc(host.upstream_host)}:${host.upstream_port}</span><small>${host.websocket?'WebSocket upgrades enabled':'Standard HTTP proxy'}${host.allowlist||host.blocklist?` · ${host.allowlist?`${host.allowlist.split(/\s+/).filter(Boolean).length} allowed`:''}${host.allowlist&&host.blocklist?' · ':''}${host.blocklist?`${host.blocklist.split(/\s+/).filter(Boolean).length} blocked`:''}`:''}</small></div>
    <span class="security ${host.certificate?'secure':'plain'}">${host.certificate?'◆ TLS':'◇ HTTP'}</span>
    <span class="state ${host.enabled?'on':''}">${host.enabled?'ACTIVE':'PAUSED'}</span>
    <div class="row-actions"><button class="toggle-route ${host.enabled?'active':'paused'}" data-id="${host.id}" aria-label="${host.enabled?'Disable':'Enable'} route" title="${host.enabled?'Disable':'Enable'} route"><svg viewBox="0 0 24 24"><path d="M12 3v9"/><path d="M7.1 6.4a8 8 0 1 0 9.8 0"/></svg></button><button class="edit" data-id="${host.id}" aria-label="Edit route"><svg viewBox="0 0 24 24"><path d="m14 6 4 4M5 19l3.5-.7L19 7.8 16.2 5 5.7 15.5 5 19Z"/></svg></button>${!host.certificate?`<button class="cert" data-id="${host.id}" aria-label="Enable HTTPS"><svg viewBox="0 0 24 24"><rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg></button>`:''}<button class="delete" data-id="${host.id}" aria-label="Delete route"><svg viewBox="0 0 24 24"><path d="M5 7h14m-9-3h4m-7 3 1 13h8l1-13M10 11v5m4-5v5"/></svg></button></div>
  </article>`).join('');
}
function hostPayload(host,enabled=host.enabled){return {domains:host.domains,upstream_scheme:host.upstream_scheme,upstream_host:host.upstream_host,upstream_port:Number(host.upstream_port),websocket:Boolean(host.websocket),enabled:Boolean(enabled),allowlist:host.allowlist||'',blocklist:host.blocklist||''}}
function openHost(host={}){
  const form=$('#host-form');form.reset();form.id.value=host.id||'';form.domains.value=host.domains||'';form.upstream_scheme.value=host.upstream_scheme||'http';form.upstream_host.value=host.upstream_host||'';form.upstream_port.value=host.upstream_port||80;form.allowlist.value=host.allowlist||'';form.blocklist.value=host.blocklist||'';form.websocket.checked=host.websocket??true;form.enabled.checked=host.enabled??true;$('#dialog-title').textContent=host.id?'Edit proxy host':'New proxy host';$('#form-error').textContent='';$('#host-dialog').showModal();
}

$('#login-form').addEventListener('submit',async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;try{await api('/api/login',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(event.target)))});await boot()}catch(error){$('#login-error').textContent=error.message}finally{button.disabled=false}});
$('#logout').addEventListener('click',async()=>{await api('/api/logout',{method:'POST',body:'{}'});me=null;users=[];await boot()});
$('#refresh').addEventListener('click',async event=>{event.currentTarget.disabled=true;try{await refreshAll();toast('Dashboard refreshed')}finally{event.currentTarget.disabled=false}});
['#add-host','#add-host-secondary'].forEach(selector=>$(selector).addEventListener('click',()=>openHost()));
$('#search').addEventListener('input',renderHosts);
$('#certificate-search').addEventListener('input',renderCertificates);
$('#traffic-filter').addEventListener('input',renderLiveStream);
$('#toggle-live').addEventListener('click',event=>{livePaused=!livePaused;event.currentTarget.textContent=livePaused?'Resume':'Pause';renderLiveTraffic();if(!livePaused)refreshStats()});
$('#add-user').addEventListener('click',()=>openUser());
document.querySelectorAll('.close-user').forEach(button=>button.addEventListener('click',()=>$('#user-dialog').close()));
$('#user-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,id=form.id.value,button=event.submitter;button.disabled=true;button.textContent='Saving…';const existing=users.find(user=>user.id===Number(id));const data={username:form.username.disabled?existing.username:form.username.value,role:form.role.disabled?existing.role:form.role.value,password:form.password.value,enabled:form.enabled.disabled?existing.enabled:form.enabled.checked};try{await api(id?`/api/users/${id}`:'/api/users',{method:id?'PUT':'POST',body:JSON.stringify(data)});form.closest('dialog').close();if(id&&Number(id)===me.id&&data.password){toast('Password changed. Please sign in again');setTimeout(()=>location.reload(),1000);return}users=await api('/api/users');renderUsers();toast(id?'User updated':'User created')}catch(error){$('#user-form-error').textContent=error.message}finally{button.disabled=false;button.textContent='Save user'}});
$('#users-list').addEventListener('click',async event=>{const button=event.target.closest('button'),id=Number(button?.dataset.id);if(!id)return;const user=users.find(item=>item.id===id);if(button.classList.contains('edit-user'))openUser(user);if(button.classList.contains('delete-user')&&confirm(`Delete user ${user.username}?`)){try{await api(`/api/users/${id}`,{method:'DELETE'});users=await api('/api/users');renderUsers();toast('User deleted')}catch(error){toast(error.message)}}});
document.querySelectorAll('.close').forEach(button=>button.addEventListener('click',()=>$('#host-dialog').close()));
document.querySelectorAll('.close-cert').forEach(button=>button.addEventListener('click',()=>$('#cert-dialog').close()));
document.querySelectorAll('.sidebar nav a').forEach(link=>link.addEventListener('click',event=>{event.preventDefault();history.replaceState(null,'',link.getAttribute('href'));setView(link.dataset.view)}));
$('#host-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,id=form.id.value,button=event.submitter;button.disabled=true;button.textContent='Applying…';const data={domains:form.domains.value,upstream_scheme:form.upstream_scheme.value,upstream_host:form.upstream_host.value,upstream_port:Number(form.upstream_port.value),websocket:form.websocket.checked,enabled:form.enabled.checked,allowlist:form.allowlist.value,blocklist:form.blocklist.value};try{await api(id?`/api/hosts/${id}`:'/api/hosts',{method:id?'PUT':'POST',body:JSON.stringify(data)});form.closest('dialog').close();await refreshAll();toast('NGINX configuration applied')}catch(error){$('#form-error').textContent=error.message}finally{button.disabled=false;button.textContent='Save and apply'}});
$('#hosts').addEventListener('click',async event=>{const button=event.target.closest('button'),id=Number(button?.dataset.id);if(!id)return;const host=hosts.find(item=>item.id===id);if(button.classList.contains('toggle-route')){button.disabled=true;try{await api(`/api/hosts/${id}`,{method:'PUT',body:JSON.stringify(hostPayload(host,!host.enabled))});await refreshAll();toast(host.enabled?'Proxy host disabled':'Proxy host enabled')}catch(error){toast(error.message)}finally{button.disabled=false}}if(button.classList.contains('edit'))openHost(host);if(button.classList.contains('cert'))openCertificate(host);if(button.classList.contains('delete')&&confirm(`Delete ${host.domains}?`)){try{await api(`/api/hosts/${id}`,{method:'DELETE'});await refreshAll();toast('Proxy host deleted')}catch(error){toast(error.message)}}});
$('#certificate-list').addEventListener('click',event=>{const button=event.target.closest('button'),id=Number(button?.dataset.id);if(!id)return;const host=hosts.find(item=>item.id===id);if(button.classList.contains('request-cert'))openCertificate(host);if(button.classList.contains('renew-cert'))openCertificate(host,true);if(button.classList.contains('cert-edit'))openHost(host)});
$('#cert-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,button=event.submitter,force=form.force.value==='1';button.disabled=true;button.textContent=force?'Renewing…':'Requesting…';try{await api(`/api/hosts/${form.id.value}/certificate`,{method:'POST',body:JSON.stringify({email:form.email.value,force})});form.closest('dialog').close();await refreshAll();toast(force?'Certificate renewed':'HTTPS certificate installed')}catch(error){$('#cert-error').textContent=error.message}finally{button.disabled=false;button.textContent=force?'Renew certificate':'Request certificate'}});

$('#backup-create-form').addEventListener('submit',async event=>{
  event.preventDefault();const form=event.target,button=event.submitter,error=$('#backup-create-error');error.textContent='';
  if(form.passphrase.value!==form.confirmation.value){error.textContent='Passphrases do not match';return}
  button.disabled=true;button.querySelector('span').textContent='Building encrypted backup…';
  try{
    const response=await fetch('/api/backups/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passphrase:form.passphrase.value})});
    if(!response.ok){const body=await response.json().catch(()=>({}));throw new Error(body.error||`Backup failed (${response.status})`)}
    const blob=await response.blob(),header=response.headers.get('Content-Disposition')||'',match=header.match(/filename="([^"]+)"/),name=match?.[1]||'gatehouse-backup.ghbackup';
    const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=name;document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url);form.reset();toast('Encrypted backup downloaded');
  }catch(exception){error.textContent=exception.message}finally{button.disabled=false;button.querySelector('span').textContent='Download backup'}
});

$('#backup-restore-form').backup.addEventListener('change',event=>{$('#backup-file-name').textContent=event.target.files[0]?.name||'Choose .ghbackup file'});
$('#backup-restore-form').addEventListener('submit',async event=>{
  event.preventDefault();const form=event.target,file=form.backup.files[0],button=event.submitter,error=$('#backup-restore-error');error.textContent='';
  if(!file){error.textContent='Choose a Gatehouse backup file';return}
  if(file.size>64*1024*1024){error.textContent='Backup file must be smaller than 64 MiB';return}
  if(!confirm('Restore this backup and overwrite the current Gatehouse configuration?'))return;
  button.disabled=true;button.querySelector('span').textContent='Validating and restoring…';
  try{
    const encoded=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result).split(',',2)[1]);reader.onerror=()=>reject(new Error('Could not read the backup file'));reader.readAsDataURL(file)});
    await api('/api/backups/restore',{method:'POST',body:JSON.stringify({backup:encoded,passphrase:form.passphrase.value})});
    toast('Restore complete. Signing you out…');setTimeout(()=>location.reload(),1200);
  }catch(exception){error.textContent=exception.message;button.disabled=false;button.querySelector('span').textContent='Validate and restore'}
});

boot().then(()=>setView(location.hash.slice(1))).catch(error=>{$('#login').classList.remove('hidden');$('#login-error').textContent=error.message});
setInterval(()=>{if(!livePaused)refreshStats()},3000);
