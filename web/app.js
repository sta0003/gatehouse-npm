const $ = selector => document.querySelector(selector);
let hosts = [], stats = null, users = [], me = null, currentView = 'overview', livePaused = false;

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
  $('#password-warning').classList.toggle('hidden',!status.default_password);
  await refreshAll();
}
async function refreshAll(){
  const results=await Promise.all([api('/api/hosts'),api('/api/stats'),me?.role==='admin'?api('/api/users'):Promise.resolve([])]);
  [hosts,stats,users]=results;
  renderHosts();renderStats();renderUsers();
}
async function refreshStats(){try{stats=await api('/api/stats');renderStats()}catch(_) {}}

function setView(view){
  if(!['overview','routes','certificates','activity','users'].includes(view) || (view==='users'&&me?.role!=='admin')) view='overview';
  currentView=view;
  const copy={overview:['OVERVIEW','Network overview'],routes:['PROXY HOSTS','Proxy hosts'],certificates:['CERTIFICATES','TLS certificates'],activity:['LIVE TRAFFIC','Live traffic'],users:['USERS','User management']}[view];
  $('#view-crumb').textContent=copy[0];$('#view-title').textContent=copy[1];
  $('#metrics-section').classList.toggle('hidden',view!=='overview');
  $('#charts-section').classList.toggle('hidden',view!=='overview');
  $('#lower-section').classList.toggle('hidden',['activity','users'].includes(view));
  $('#lower-section').classList.toggle('single',view!=='overview');
  $('#routes').classList.toggle('hidden',!['overview','routes','certificates'].includes(view));
  $('#activity').classList.toggle('hidden',view!=='overview');
  $('#traffic-detail').classList.toggle('hidden',view!=='activity');
  $('#users-detail').classList.toggle('hidden',view!=='users');
  $('#route-kicker').textContent=view==='certificates'?'TLS MANAGEMENT':'ROUTING';
  $('#route-title').textContent=view==='certificates'?'Certificates':'Proxy hosts';
  $('#search').placeholder=view==='certificates'?'Search certificates':'Search routes';
  document.querySelectorAll('.sidebar nav a').forEach(link=>link.classList.toggle('active',link.dataset.view===view));
  renderHosts();
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
function renderHosts(){
  const query=$('#search').value.toLowerCase();
  const shown=hosts.filter(host=>`${host.domains} ${host.upstream_host}`.toLowerCase().includes(query)).sort((a,b)=>currentView==='certificates'?Number(b.certificate)-Number(a.certificate):0);
  $('#empty').classList.toggle('hidden',hosts.length!==0);
  $('#hosts').innerHTML=shown.map(host=>`<article class="host-row">
    <div class="domain-cell"><strong>${esc(host.domains.split(' ')[0])}</strong><small>${host.domains.split(' ').slice(1).map(esc).join(' · ')||'Primary hostname'}</small></div>
    <div class="target-cell"><span>${esc(host.upstream_scheme)}://${esc(host.upstream_host)}:${host.upstream_port}</span><small>${host.websocket?'WebSocket upgrades enabled':'Standard HTTP proxy'}</small></div>
    <span class="security ${host.certificate?'secure':'plain'}">${host.certificate?'◆ TLS':'◇ HTTP'}</span>
    <span class="state ${host.enabled?'on':''}">${host.enabled?'ACTIVE':'PAUSED'}</span>
    <div class="row-actions"><button class="edit" data-id="${host.id}" aria-label="Edit route"><svg viewBox="0 0 24 24"><path d="m14 6 4 4M5 19l3.5-.7L19 7.8 16.2 5 5.7 15.5 5 19Z"/></svg></button>${!host.certificate?`<button class="cert" data-id="${host.id}" aria-label="Enable HTTPS"><svg viewBox="0 0 24 24"><rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg></button>`:''}<button class="delete" data-id="${host.id}" aria-label="Delete route"><svg viewBox="0 0 24 24"><path d="M5 7h14m-9-3h4m-7 3 1 13h8l1-13M10 11v5m4-5v5"/></svg></button></div>
  </article>`).join('');
}
function openHost(host={}){
  const form=$('#host-form');form.reset();form.id.value=host.id||'';form.domains.value=host.domains||'';form.upstream_scheme.value=host.upstream_scheme||'http';form.upstream_host.value=host.upstream_host||'';form.upstream_port.value=host.upstream_port||80;form.websocket.checked=host.websocket??true;form.enabled.checked=host.enabled??true;$('#dialog-title').textContent=host.id?'Edit proxy host':'New proxy host';$('#form-error').textContent='';$('#host-dialog').showModal();
}

$('#login-form').addEventListener('submit',async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;try{await api('/api/login',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(event.target)))});await boot()}catch(error){$('#login-error').textContent=error.message}finally{button.disabled=false}});
$('#logout').addEventListener('click',async()=>{await api('/api/logout',{method:'POST',body:'{}'});me=null;users=[];await boot()});
$('#refresh').addEventListener('click',async event=>{event.currentTarget.disabled=true;try{await refreshAll();toast('Dashboard refreshed')}finally{event.currentTarget.disabled=false}});
['#add-host','#add-host-secondary'].forEach(selector=>$(selector).addEventListener('click',()=>openHost()));
$('#search').addEventListener('input',renderHosts);
$('#traffic-filter').addEventListener('input',renderLiveStream);
$('#toggle-live').addEventListener('click',event=>{livePaused=!livePaused;event.currentTarget.textContent=livePaused?'Resume':'Pause';renderLiveTraffic();if(!livePaused)refreshStats()});
$('#add-user').addEventListener('click',()=>openUser());
document.querySelectorAll('.close-user').forEach(button=>button.addEventListener('click',()=>$('#user-dialog').close()));
$('#user-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,id=form.id.value,button=event.submitter;button.disabled=true;button.textContent='Saving…';const existing=users.find(user=>user.id===Number(id));const data={username:form.username.disabled?existing.username:form.username.value,role:form.role.disabled?existing.role:form.role.value,password:form.password.value,enabled:form.enabled.disabled?existing.enabled:form.enabled.checked};try{await api(id?`/api/users/${id}`:'/api/users',{method:id?'PUT':'POST',body:JSON.stringify(data)});form.closest('dialog').close();if(id&&Number(id)===me.id&&data.password){toast('Password changed. Please sign in again');setTimeout(()=>location.reload(),1000);return}users=await api('/api/users');renderUsers();toast(id?'User updated':'User created')}catch(error){$('#user-form-error').textContent=error.message}finally{button.disabled=false;button.textContent='Save user'}});
$('#users-list').addEventListener('click',async event=>{const button=event.target.closest('button'),id=Number(button?.dataset.id);if(!id)return;const user=users.find(item=>item.id===id);if(button.classList.contains('edit-user'))openUser(user);if(button.classList.contains('delete-user')&&confirm(`Delete user ${user.username}?`)){try{await api(`/api/users/${id}`,{method:'DELETE'});users=await api('/api/users');renderUsers();toast('User deleted')}catch(error){toast(error.message)}}});
document.querySelectorAll('.close').forEach(button=>button.addEventListener('click',()=>$('#host-dialog').close()));
document.querySelectorAll('.close-cert').forEach(button=>button.addEventListener('click',()=>$('#cert-dialog').close()));
document.querySelectorAll('.sidebar nav a').forEach(link=>link.addEventListener('click',event=>{event.preventDefault();history.replaceState(null,'',link.getAttribute('href'));setView(link.dataset.view)}));
$('#host-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,id=form.id.value,button=event.submitter;button.disabled=true;button.textContent='Applying…';const data={domains:form.domains.value,upstream_scheme:form.upstream_scheme.value,upstream_host:form.upstream_host.value,upstream_port:Number(form.upstream_port.value),websocket:form.websocket.checked,enabled:form.enabled.checked};try{await api(id?`/api/hosts/${id}`:'/api/hosts',{method:id?'PUT':'POST',body:JSON.stringify(data)});form.closest('dialog').close();await refreshAll();toast('NGINX configuration applied')}catch(error){$('#form-error').textContent=error.message}finally{button.disabled=false;button.textContent='Save and apply'}});
$('#hosts').addEventListener('click',async event=>{const button=event.target.closest('button'),id=Number(button?.dataset.id);if(!id)return;const host=hosts.find(item=>item.id===id);if(button.classList.contains('edit'))openHost(host);if(button.classList.contains('cert')){$('#cert-form').reset();$('#cert-form').id.value=id;$('#cert-error').textContent='';$('#cert-dialog').showModal()}if(button.classList.contains('delete')&&confirm(`Delete ${host.domains}?`)){try{await api(`/api/hosts/${id}`,{method:'DELETE'});await refreshAll();toast('Proxy host deleted')}catch(error){toast(error.message)}}});
$('#cert-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,button=event.submitter;button.disabled=true;button.textContent='Requesting…';try{await api(`/api/hosts/${form.id.value}/certificate`,{method:'POST',body:JSON.stringify({email:form.email.value})});form.closest('dialog').close();await refreshAll();toast('HTTPS certificate installed')}catch(error){$('#cert-error').textContent=error.message}finally{button.disabled=false;button.textContent='Request certificate'}});

boot().then(()=>setView(location.hash.slice(1))).catch(error=>{$('#login').classList.remove('hidden');$('#login-error').textContent=error.message});
setInterval(()=>{if(!livePaused)refreshStats()},3000);
