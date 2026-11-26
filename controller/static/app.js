'use strict';
let csrf = '', username = '', currentPage = 'dashboard', currentFingerprint = '';
const $ = (s) => document.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));
const tag = (s, color='grey') => `<span class="tag ${color}">${esc(s)}</span>`;
const date = s => s ? new Date(s).toLocaleString('ru-RU') : '—';
const hbfPorts = r => r.proto==='icmp'||r.proto==='icmpv6' ? (r.icmp_type||'ICMP') : (Array.isArray(r.ports)?r.ports.map(([a,b])=>a===b?String(a):`${a}-${b}`).join(','):(r.ports || r.port || '—'));
const hbfTraffic = r => `${String(r.action||'drop').toUpperCase()} ${String(r.family||'ipv4').toUpperCase()} ${String(r.proto||'tcp').toUpperCase()}/${hbfPorts(r)}${r.states?' · ct '+r.states:''}${r.log_drop?' · LOG':''}`;
const hbfRule = r => `${r.direction} ${hbfTraffic(r)}: ${Array.isArray(r.source)?r.source.join(', '):r.source} → ${Array.isArray(r.destination)?r.destination.join(', '):r.destination}`;
const page = $('#page');
const titleMap = {dashboard:'Обзор',hosts:'Хосты',policies:'Политики',topology:'Топология',logs:'Журналы',deploy:'Развёртывание',history:'Версии и восстановление',audit:'Аудит',settings:'Система'};

async function api(url, method='GET', body=null) {
  const opts={method,headers:{}};
  if(method!=='GET')opts.headers['X-HBF-CSRF']=csrf;
  if(body!==null){opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(body)}
  const r=await fetch(url,opts);
  let obj;try{obj=await r.json()}catch{obj={detail:'Неверный ответ сервера'}}
  if(!r.ok){if(r.status===401){showLogin()}throw Error(typeof obj.detail==='string'?obj.detail:JSON.stringify(obj.detail))}
  return obj;
}
function showLogin(){csrf='';$('#layout').classList.add('hidden');$('#login').classList.remove('hidden')}
function showApp(){ $('#login').classList.add('hidden');$('#layout').classList.remove('hidden');$('#userPill').textContent=username; navigate(currentPage)}
function flash(message,bad=false){$('#notice').innerHTML=`<div class="flash ${bad?'bad':''}">${esc(message)}</div>`;setTimeout(()=>{$('#notice').innerHTML=''},7000)}
function notify(e){flash(e.message||String(e),true)}
function heading(text,detail,button=''){return `<div class="content-heading"><div><h3>${esc(text)}</h3><p class="muted">${esc(detail)}</p></div>${button}</div>`}
function table(headers,rows){return `<div class="panel table-wrap"><table><thead><tr>${headers.map(h=>`<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.length?rows.join(''):`<tr><td colspan="${headers.length}" class="empty">Нет записей</td></tr>`}</tbody></table></div>`}
function btn(label, action, className='soft'){return `<button class="btn ${className}" data-action="${esc(action)}">${esc(label)}</button>`}
function mod(html,onSubmit){$('#modalBody').innerHTML=`<div class="modal-content">${html}</div>`;const dialog=$('#modal');dialog.showModal();if(onSubmit){$('#modalForm').addEventListener('submit',async e=>{e.preventDefault();try{await onSubmit(new FormData(e.target));dialog.close();await navigate(currentPage)}catch(err){$('#modalError').textContent=err.message}})}}
const foot=`<p id="modalError" class="error"></p><div class="modal-foot"><button type="button" class="btn" onclick="document.querySelector('#modal').close()">Отмена</button><button type="submit" class="btn primary">Сохранить</button></div>`;
function bindActions(){page.querySelectorAll('[data-action]').forEach(b=>{if(b.dataset.hbfBound)return;b.dataset.hbfBound='1';b.addEventListener('click',()=>action(b.dataset.action).catch(notify))})}
async function navigate(next){currentPage=next;$('#pageTitle').textContent=titleMap[next]||next;document.querySelectorAll('nav button').forEach(x=>x.classList.toggle('active',x.dataset.page===next));page.innerHTML='<div class="muted">Загрузка…</div>';try{const routes={dashboard,hostsPage,policiesPage,topologyPage,logsPage,deployPage,historyPage,auditPage,settingsPage};await (routes[{dashboard:'dashboard',hosts:'hostsPage',policies:'policiesPage',topology:'topologyPage',logs:'logsPage',deploy:'deployPage',history:'historyPage',audit:'auditPage',settings:'settingsPage'}[next]])();bindActions()}catch(err){page.innerHTML=`<div class="panel panel-body"><p class="error">${esc(err.message)}</p></div>`}}

async function dashboard(){
 const [summary,agents]=await Promise.all([api('/api/summary'),api('/api/agents')]);
 const reachable=agents.filter(a=>a.reachable).length;
 const job=summary.last_deployment;
 const jobStatus=job?job.state:'не выполнялся';
 page.innerHTML=`${heading('Состояние инфраструктуры','Контроль хостов, правил и последних операций')}
 <div class="grid-stats">
 <div class="card"><span class="label">Хосты</span><div class="metric">${summary.hosts}</div><small>Зарегистрировано</small></div>
 <div class="card"><span class="label">Агенты онлайн</span><div class="metric">${reachable}<small> / ${agents.length}</small></div><small>Подключение по SSH</small></div>
 <div class="card"><span class="label">Активные политики</span><div class="metric">${summary.active_policies}</div><small>Всего: ${summary.policies}</small></div>
 <div class="card"><span class="label">Последний Deploy</span><div class="metric" style="font-size:20px;padding-top:14px">${esc(jobStatus)}</div><small>${job?date(job.updated):'Нет истории'}</small></div>
 </div>
 <div class="section-grid"><div class="panel"><div class="panel-head"><h3>Управляемые узлы</h3>${btn('Все хосты','go:hosts')}</div><div class="table-wrap"><table><thead><tr><th>Хост</th><th>Адрес</th><th>Агент</th><th>Транзакция</th></tr></thead><tbody>${agents.map(h=>`<tr><td><b>${esc(h.label)}</b><div class="note">${esc(h.id)}</div></td><td class="monospace">${esc(h.ip)}</td><td>${h.reachable?tag('ONLINE','green'):tag('OFFLINE','red')}</td><td>${h.state?tag(h.state,h.state==='CLEAN'?'green':'yellow'):tag('UNKNOWN','red')}</td></tr>`).join('')}</tbody></table></div></div>
 <div class="panel"><div class="panel-head"><h3>Последовательность управления</h3></div><div class="panel-body"><div class="step"><strong>01</strong><div>Создайте правило в разделе «Политики».</div></div><div class="step"><strong>02</strong><div>Проверьте состав правил и готовность агентов.</div></div><div class="step"><strong>03</strong><div>Запустите Deploy с явным подтверждением.</div></div><div class="step"><strong>04</strong><div>Проверьте VERIFY, COMMIT и результаты тестирования.</div></div><p class="hint">Каждый узел имеет локальный 10-минутный watchdog. Межсерверный COMMIT не атомарен.</p>${btn('Перейти к Deploy','go:deploy','primary')}</div></div></div>`;
}

async function topologyPage(){
 const [model,agents,summary]=await Promise.all([api('/api/topology'),api('/api/agents'),api('/api/summary')]);
 window.HBFTopology.render(page,{model,agents,summary});
}

async function hostsPage(){
 const [h,enrolled,agents]=await Promise.all([api('/api/hosts'),api('/api/registry'),api('/api/agents')]);
 const state=new Map(agents.map(a=>[a.id,a]));
 const ip6=new Map(enrolled.map(x=>[x.id,x.ipv6||'']));
 page.innerHTML=heading('Инвентаризация хостов','IP-адреса закрепляются при Ansible enrollment; метки и группы можно менять.',btn('Добавить хост','host:add','primary'))+
 `<div class="panel-body"><input id="hostFilter" placeholder="Поиск по названию, IP, группе, VLAN, зоне, роли" aria-label="Поиск хостов"></div>`+
 table(['Название','ID / IP','Группа','Управление','Карантин','Действия'],h.map(x=>`<tr><td><b>${esc(x.label)}</b></td><td><span class="rule-name">${esc(x.id)}</span><div class="note">${esc(x.ip)}</div>${ip6.get(x.id)?`<div class="note">IPv6: ${esc(ip6.get(x.id))}</div>`:''}</td><td>${tag(x.grp)}<div class="note">${x.vlan?'VLAN '+x.vlan+' · ':''}${esc(x.zone||'')} ${esc(x.role||'')}</div></td><td>${x.enabled?tag('Активен','green'):tag('Отключён','grey')}</td><td>${state.get(x.id)?.reachable?(state.get(x.id)?.quarantined?tag('КАРАНТИН','red'):tag('Норма','green')):tag('Недоступен','yellow')}</td><td class="actions">${x.enabled&&state.get(x.id)?.reachable?(state.get(x.id)?.quarantined?btn('Снять карантин','host:release:'+x.id,'small'):btn('Карантин','host:quarantine:'+x.id,'danger small')):''}${btn('Изменить','host:edit:'+x.id,'small')}${btn('Удалить','host:delete:'+x.id,'danger small')}</td></tr>`))+
 `<p class="warning">Карантин немедленно блокирует IPv4/IPv6 INPUT, OUTPUT и FORWARD, включая существующие прикладные соединения. Исключения: loopback и SSH/22 только от IP контроллера. Карантин сохраняется после перезагрузки. При потере управления снимите его локально через консоль ВМ командой sudo /usr/local/sbin/hbf-alpha-agent quarantine-off. Deploy при карантине запрещён.</p><p class="hint">Новый физический сервер сначала должен быть зарегистрирован установочным Ansible playbook. Веб-панель не принимает произвольные IP, чтобы не отправлять команды на незарегистрированные устройства.</p>`;
 const filter=$('#hostFilter');filter.addEventListener('input',()=>{const term=filter.value.toLowerCase();page.querySelectorAll('tbody tr').forEach((row,i)=>{const host=h[i];row.hidden=!([host.id,host.label,host.ip,host.grp,host.vlan,host.zone,host.role,host.site].join(' ').toLowerCase().includes(term))})});
}

async function hostModal(id){
 const [hs,enrolled]=await Promise.all([api('/api/hosts'),api('/api/registry')]);
 const editing=!!id,h=hs.find(x=>x.id===id)||{id:'',label:'',grp:'lab',enabled:1,vlan:null,zone:'',role:'',site:'',description:''};
 const choices=enrolled.filter(e=>!hs.some(x=>x.id===e.id)||e.id===id);
 const html=`<h3>${editing?'Редактировать хост':'Добавить хост'}</h3><form id="modalForm"><label>Зарегистрированный узел<select name="id" ${editing?'disabled':''} required>${choices.map(e=>`<option value="${esc(e.id)}" ${e.id===h.id?'selected':''}>${esc(e.id)} — ${esc(e.ip)}</option>`).join('')}</select></label><div class="form-grid"><label>Название<input name="label" required maxlength="100" value="${esc(h.label||choices[0]?.label||choices[0]?.id||'')}"></label><label>Группа<input name="grp" maxlength="64" value="${esc(h.grp)}"></label></div><div class="form-grid"><label>VLAN (необязательно)<input name="vlan" type="number" min="1" max="4094" value="${esc(h.vlan??'')}"></label><label>Зона<input name="zone" maxlength="64" value="${esc(h.zone||'')}"></label><label>Роль<input name="role" maxlength="64" value="${esc(h.role||'')}"></label><label>Площадка<input name="site" maxlength="64" value="${esc(h.site||'')}"></label></div><label>Описание<textarea name="description" maxlength="300" rows="2">${esc(h.description||'')}</textarea></label><label class="check"><input type="checkbox" name="enabled" ${h.enabled?'checked':''}>Узел управляется HBF</label>${foot}</form>`;
 mod(html,async fd=>{const body={id:editing?id:fd.get('id'),label:fd.get('label'),grp:fd.get('grp'),vlan:fd.get('vlan')?Number(fd.get('vlan')):null,zone:fd.get('zone'),role:fd.get('role'),site:fd.get('site'),description:fd.get('description'),enabled:fd.has('enabled')};await api(editing?'/api/hosts/'+encodeURIComponent(id):'/api/hosts',editing?'PUT':'POST',body);flash('Хост сохранён. Для применения изменений запустите Deploy.')});
}

async function policiesPage(){
 const ps=await api('/api/policies');
 page.innerHTML=heading('Политики сетевого доступа','ACCEPT / DROP / REJECT · TCP, UDP, ICMP · IPv4/IPv6 · портовые и IP-группы · ct state · DROP logging.',btn('Создать правило','policy:add','primary'))+
 `<div class="panel-body policy-filters"><input id="policyFilter" placeholder="Название, IP, ID, теги, порт, ticket" aria-label="Поиск политик"><select id="policyStatusFilter"><option value="all">Все статусы</option><option value="active">Активные</option><option value="disabled">Неактивные</option></select></div>`+
 table(['Правило','Источник → Назначение','Трафик','Статус','Действия'],ps.map(p=>`<tr><td><b>${esc(p.name)}</b><div class="rule-name">${esc(p.id)}</div><div class="note">${esc(p.tags||'')} ${esc(p.ticket||'')}</div></td><td>${esc(p.src)} <span class="muted">→</span> ${esc(p.dst)}</td><td>${tag(hbfTraffic(p))}</td><td>${p.enabled?tag('Включено','green'):tag('Выключено','grey')}</td><td class="actions">${btn('Изменить','policy:edit:'+p.id,'small')}${btn(p.enabled?'Выкл.':'Вкл.','policy:toggle:'+p.id,'small')}${btn('Удалить','policy:delete:'+p.id,'danger small')}</td></tr>`))+
 `<p class="hint">Сначала сохраняется проект, затем требуется Deploy. Цепочки HBF имеют policy accept: ACCEPT позволяет создавать исключения перед DROP с более высоким порядком (меньшим priority), но не переопределяет другие таблицы nftables. TCP/UDP-порты 22 и 8088 защищены от любых правил.</p>`;
 const filter=()=>{const term=$('#policyFilter').value.toLowerCase(),status=$('#policyStatusFilter').value;page.querySelectorAll('tbody tr').forEach((row,i)=>{const p=ps[i];row.hidden=!([p.id,p.name,p.src,p.dst,p.proto,p.port,p.ports,p.action,p.family,p.states,p.src_cidrs,p.dst_cidrs,p.note,p.tags,p.owner,p.ticket].join(' ').toLowerCase().includes(term)&&(status==='all'||Boolean(p.enabled)===(status==='active')))})};
 $('#policyFilter').addEventListener('input',filter);$('#policyStatusFilter').addEventListener('change',filter);
}

async function policyModal(id){
 const [ps,hs]=await Promise.all([api('/api/policies'),api('/api/hosts')]);
 const editing=!!id,p=ps.find(x=>x.id===id)||{name:'',src:hs[0]?.id,dst:hs[1]?.id,proto:'tcp',port:9090,
   ports:'',family:'ipv4',action:'drop',states:'',src_cidrs:'',dst_cidrs:'',icmp_type:'',priority:100,
   log_drop:0,enabled:1,note:'',tags:'',owner:'',ticket:''};
 const options=sel=>hs.map(h=>`<option value="${esc(h.id)}" ${h.id===sel?'selected':''}>${esc(h.label)} (${esc(h.id)})</option>`).join('');
 const choice=(name,items,selected)=>`<select name="${name}">${items.map(([v,label])=>`<option value="${v}" ${v===selected?'selected':''}>${label}</option>`).join('')}</select>`;
 const html=`<h3>${editing?'Изменить правило':'Новая политика HBF'}</h3><form id="modalForm">
 <label>Название правила<input name="name" maxlength="100" value="${esc(p.name)}" required placeholder="Allow app / Block database"></label>
 <div class="form-grid"><label>Источник (узел HBF)<select name="src">${options(p.src)}</select></label>
 <label>Назначение (узел HBF)<select name="dst">${options(p.dst)}</select></label></div>
 <div class="form-grid"><label>Решение ${choice('action',[['accept','ACCEPT'],['drop','DROP'],['reject','REJECT']],p.action||'drop')}</label>
 <label>Семейство IP ${choice('family',[['ipv4','IPv4'],['ipv6','IPv6 (нужен Ansible enrollment)']],p.family||'ipv4')}</label></div>
 <div class="form-grid"><label>Протокол ${choice('proto',[['tcp','TCP'],['udp','UDP'],['icmp','ICMPv4'],['icmpv6','ICMPv6']],p.proto)}</label>
 <label>Порты назначения (список / диапазоны)<input name="ports" maxlength="400" value="${esc(p.ports||((p.proto==='tcp'||p.proto==='udp')&&p.port?p.port:''))}" placeholder="443,8443,9000-9010"></label></div>
 <div class="form-grid"><label>Тип ICMP (только для ICMP) ${choice('icmp_type',[['','—'],['echo-request','echo-request'],['echo-reply','echo-reply'],['destination-unreachable','destination-unreachable (IPv4)'],['time-exceeded','time-exceeded (IPv4)']],p.icmp_type||'')}</label>
 <label>Приоритет (меньше = раньше)<input name="priority" type="number" min="1" max="10000" required value="${esc(p.priority??100)}"></label></div>
 <div class="form-grid"><label>IP/CIDR источника (через запятую, необязательно)<textarea name="src_cidrs" maxlength="850" rows="2" placeholder="По умолчанию: IP узла источника">${esc(p.src_cidrs||'')}</textarea></label>
 <label>IP/CIDR назначения (через запятую, необязательно)<textarea name="dst_cidrs" maxlength="850" rows="2" placeholder="По умолчанию: IP узла назначения">${esc(p.dst_cidrs||'')}</textarea></label></div>
 <label>Состояния conntrack (через запятую; пустое поле = любые)<input name="states" maxlength="48" value="${esc(p.states||'')}" placeholder="new,established,related"></label>
 <label class="check"><input type="checkbox" name="log_drop" ${p.log_drop?'checked':''}>Логировать DROP (3 события/сек., burst 5; само DROP без лимита)</label>
 <label>Комментарий<textarea name="note" maxlength="300" rows="2">${esc(p.note)}</textarea></label>
 <div class="form-grid"><label>Теги<input name="tags" maxlength="160" value="${esc(p.tags||'')}"></label>
 <label>Владелец правила<input name="owner" maxlength="80" value="${esc(p.owner||'')}"></label></div>
 <label>Change / Ticket ID<input name="ticket" maxlength="80" value="${esc(p.ticket||'')}"></label>
 <label class="check"><input type="checkbox" name="enabled" ${p.enabled?'checked':''}>Правило активно</label>
 <p class="hint">IPv6 требует адресов hbf_host_ipv6 на обоих узлах. CIDR-списки для OUTPUT/INPUT должны включать IP локального интерфейса соответствующего узла; агент проверит это при STAGE. Для ICMP используйте явный тип; IPv6 NDP не блокируется. TCP/UDP 22 и 8088 защищены даже внутри диапазонов.</p>${foot}</form>`;
 mod(html,async fd=>{
   const proto=fd.get('proto'),isIcmp=proto==='icmp'||proto==='icmpv6';
   const body={name:fd.get('name'),src:fd.get('src'),dst:fd.get('dst'),proto,family:fd.get('family'),
     action:fd.get('action'),port:0,ports:isIcmp?'':String(fd.get('ports')||'').trim(),
     icmp_type:isIcmp?fd.get('icmp_type'):'',priority:Number(fd.get('priority')),
     src_cidrs:fd.get('src_cidrs'),dst_cidrs:fd.get('dst_cidrs'),states:fd.get('states'),
     log_drop:fd.has('log_drop'),note:fd.get('note'),tags:fd.get('tags'),owner:fd.get('owner'),
     ticket:fd.get('ticket'),enabled:fd.has('enabled')};
   await api(editing?'/api/policies/'+encodeURIComponent(id):'/api/policies',editing?'PUT':'POST',body);
   flash('Политика сохранена — проверьте План/Diff и затем Deploy.');
 });
 const protoField=document.querySelector('#modalForm [name="proto"]');
 const familyField=document.querySelector('#modalForm [name="family"]');
 const portField=document.querySelector('#modalForm [name="ports"]');
 const icmpField=document.querySelector('#modalForm [name="icmp_type"]');
 const logField=document.querySelector('#modalForm [name="log_drop"]');
 const actField=document.querySelector('#modalForm [name="action"]');
 const sync=()=>{
   if(familyField.value==='ipv6'&&protoField.value==='icmp')protoField.value='icmpv6';
   if(familyField.value==='ipv4'&&protoField.value==='icmpv6')protoField.value='icmp';
   const icmp=protoField.value.startsWith('icmp');
   portField.disabled=icmp;
   icmpField.disabled=!icmp;
   if(icmp&&icmpField.value==='')icmpField.value='echo-request';
   logField.disabled=actField.value!=='drop';
   if(logField.disabled)logField.checked=false;
 };
 [familyField,protoField,actField].forEach(e=>e.addEventListener('change',sync));sync();
}

async function deployPage(){
 const [preview,history,diff]=await Promise.all([api('/api/preview'),api('/api/deployments'),api('/api/plan-diff')]);
 currentFingerprint=preview.fingerprint;
 page.innerHTML=heading('План развёртывания','Проверка кандидатов, транзакционное применение на узлах и наблюдение за журналом.',btn('Предпроверка агентов','deploy:preflight','soft'))+
 `<div class="warning">Внимание: действие изменяет nftables на выбранных узлах. Есть локальный watchdog на 600 секунд, но межузловой COMMIT не атомарен. Не проводите первый тест без доступа к консолям обеих ВМ.</div>
 <div class="panel" style="margin-top:20px"><div class="panel-head"><h3>План: ${preview.targets.length} узла(ов)</h3>${tag('Fingerprint '+preview.fingerprint.slice(0,12))}</div><div class="table-wrap"><table><thead><tr><th>Узел</th><th>IPv4</th><th>Правил</th><th>Правила</th></tr></thead><tbody>${preview.targets.map(t=>`<tr><td><b>${esc(t.id)}</b></td><td class="monospace">${esc(t.host_ip)}</td><td>${t.rule_count}</td><td>${t.rules.length?t.rules.map(r=>`<div class="note">${esc(hbfRule(r))}</div>`).join(''):tag('Очистить HBF Alpha правила','grey')}</td></tr>`).join('')}</tbody></table></div></div>
 <div class="panel"><div class="panel-head"><h3>План изменений относительно последнего успешного Deploy</h3></div>
 <div class="table-wrap"><table><thead><tr><th>Хост</th><th>Добавить</th><th>Удалить</th><th>Без изменений</th><th>Сведения</th></tr></thead><tbody>
 ${diff.targets.map(d=>`<tr><td><b>${esc(d.id)}</b></td><td>${d.baseline_known?tag('+'+d.add.length,'green'):'—'}</td><td>${d.baseline_known?tag('-'+d.remove.length,'red'):'—'}</td><td>${d.baseline_known?d.unchanged.length:'—'}</td><td>${d.baseline_known?`${d.add.map(r=>`<div class="note">+ ${esc(hbfRule(r))}</div>`).join('')}${d.remove.map(r=>`<div class="note">− ${esc(hbfRule(r))}</div>`).join('')}`:tag('Baseline неизвестен','yellow')}</td></tr>`).join('')}
 </tbody></table></div><div class="panel-body note">${esc(diff.note)}</div></div>
 <div class="panel"><div class="panel-head"><h3>Запуск Deploy</h3></div><div class="panel-body"><p class="muted" style="margin-bottom:14px">Введите <span class="inline-code">DEPLOY</span> и нажмите кнопку. Сначала будет выполнен preflight обоих агентов.</p><div class="split"><input style="max-width:230px" id="deployConfirm" placeholder="DEPLOY" autocomplete="off"><button class="btn primary" data-action="deploy:start">Применить политику</button></div><div id="preflightResult" style="margin-top:12px"></div></div></div>
 <div class="panel"><div class="panel-head"><h3>Последние операции</h3>${btn('Обновить','go:deploy')}</div>${history.length?`<div class="table-wrap"><table><thead><tr><th>Дата</th><th>Задание</th><th>Состояние</th><th></th></tr></thead><tbody>${history.slice(0,10).map(j=>`<tr><td>${date(j.created)}</td><td class="rule-name">${esc(j.id)}</td><td>${tag(j.state,j.state==='success'?'green':j.state==='running'?'yellow':'red')}</td><td>${btn('Журнал','deploy:log:'+j.id,'small')}${j.state==='partial'?btn('Сверить','deploy:reconcile:'+j.id,'danger small'):''}</td></tr>`).join('')}</tbody></table></div>`:'<div class="empty">Заданий ещё не было</div>'}</div>`;
}

async function logsPage(){
 const [jobs,auditRows,agents]=await Promise.all([api('/api/deployments'),api('/api/audit'),api('/api/agents')]);
 page.innerHTML=heading('Журналы операций','Развёртывания, восстановление, проверки агентов и отклонённые изменения.')+
 `<div class="panel"><div class="panel-body"><div class="btn-row" id="logTabs"><button class="btn soft" data-log="deploy">Deploy</button><button class="btn soft" data-log="rollback">Rollback / Partial</button><button class="btn soft" data-log="agents">Агенты</button><button class="btn soft" data-log="validation">Ошибки валидации</button></div></div><div id="logContent"></div></div>`;
 const show=kind=>{
  const root=$('#logContent');
  if(kind==='deploy'||kind==='rollback'){
   const rows=jobs.filter(j=>kind==='deploy'||['partial','reconciled','failed'].includes(j.state)||JSON.stringify(j.logs).includes('ROLLBACK'));
   root.innerHTML=table(['Дата','ID','Состояние','Журнал'],rows.map(j=>`<tr><td>${date(j.created)}</td><td>${esc(j.id)}</td><td>${tag(j.state,j.state==='success'?'green':'yellow')}</td><td>${btn('Открыть','deploy:log:'+j.id,'small')}</td></tr>`));
  }else if(kind==='agents'){
   root.innerHTML=table(['Хост','IP','Связь','Транзакция'],agents.map(a=>`<tr><td>${esc(a.label)}</td><td>${esc(a.ip)}</td><td>${a.reachable?tag('ONLINE','green'):tag('OFFLINE','red')}</td><td>${esc(a.state||a.error||'—')}</td></tr>`))+'<p class="hint">Это текущие статусы агентов, а не удалённый journalctl. Подробные ошибки Deploy — в журнале задания.</p>';
  }else{
   const rows=auditRows.filter(a=>a.action==='validation_error'||a.action==='deploy_failed'||a.action==='deploy_partial');
   root.innerHTML=table(['Время','Оператор','Событие','Детали'],rows.map(a=>`<tr><td>${date(a.created)}</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td><td>${esc(a.details)}</td></tr>`));
  }
  page.querySelectorAll('#logTabs [data-log]').forEach(b=>b.classList.toggle('primary',b.dataset.log===kind));
  bindActions();
 };
 page.querySelectorAll('#logTabs [data-log]').forEach(b=>b.addEventListener('click',()=>show(b.dataset.log)));
 show('deploy');
}

async function historyPage(){
 const revs=await api('/api/revisions');
 page.innerHTML=heading('История изменений','Восстановление версии возвращает политики в базу, затем требуется Deploy.')+
 table(['Версия','Дата','Оператор','Операция','Действия'],revs.map(r=>`<tr><td class="rule-name">#${r.id}</td><td>${date(r.created)}</td><td>${esc(r.actor)}</td><td>${esc(r.reason)}</td><td>${btn('Восстановить политики','history:restore:'+r.id,'small')}</td></tr>`))+
 `<p class="warning">Восстановление версии изменяет <b>только сохранённые политики</b>, не состояние firewall. После восстановления выполните предпросмотр и новый Deploy.</p>`;
}

async function auditPage(){
 const records=await api('/api/audit');
 page.innerHTML=heading('Журнал аудита','Записи о действиях и развёртываниях в локальной базе HBF Alpha.')+
 table(['Время','Оператор','Действие','Детали'],records.map(r=>`<tr><td>${date(r.created)}</td><td>${esc(r.actor)}</td><td>${tag(r.action)}</td><td class="note">${esc(r.details)}</td></tr>`));
}

function saveDownload(filename, data, mime) {
 const blob=new Blob([data],{type:mime});
 const url=URL.createObjectURL(blob);
 const a=document.createElement('a');a.href=url;a.download=filename;a.click();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}

function yamlImportModal(){
 const dialog=$('#modal');
 $('#modalBody').innerHTML=`<div class="modal-content">
 <h3>Импорт политик YAML · Alpha 1.4 R2</h3>
 <p class="hint">Поддерживаются старые поля source, destination, protocol, destination_port и новые поля HBF. Только зарегистрированные хосты. SSH/22 и 8088 защищены.</p>
 <p class="warning"><b>Безопасный процесс:</b> предпросмотр → подтверждение импорта в базу → отдельный Plan/Diff и Deploy. Загрузка YAML не изменяет nftables.</p>
 <label>YAML-файл<input id="yamlFile" type="file" accept=".yaml,.yml,text/yaml,application/x-yaml" required></label>
 <label>Режим импорта<select id="yamlMode"><option value="merge">Добавить/обновить по ID (остальные сохранить)</option><option value="replace">Полностью заменить все политики</option></select></label>
 <div class="btn-row"><button class="btn" id="yamlPreviewBtn">Проверить и показать изменения</button></div>
 <div id="yamlPreviewInfo" class="note"></div>
 <label>Подтверждение (вводится после предпросмотра)<input id="yamlConfirm" autocomplete="off" placeholder="IMPORT_YAML"></label>
 <p id="yamlError" class="error"></p>
 <div class="modal-foot"><button type="button" class="btn" id="yamlCancel">Отмена</button><button type="button" class="btn primary" id="yamlCommitBtn" disabled>Импортировать в базу</button></div>
 </div>`;
 dialog.showModal();
 const fileEl=$('#yamlFile'),modeEl=$('#yamlMode'),commitBtn=$('#yamlCommitBtn');
 let snapshot=null, generation=0;
 const invalidate=()=>{generation++;snapshot=null;commitBtn.disabled=true;$('#yamlPreviewInfo').textContent='Предпросмотр не выполнен';$('#yamlConfirm').value='';$('#yamlConfirm').placeholder=modeEl.value==='replace'?'REPLACE_POLICIES':'IMPORT_YAML';};
 fileEl.addEventListener('change',invalidate);
 modeEl.addEventListener('change',invalidate);
 $('#yamlCancel').addEventListener('click',()=>dialog.close());
 $('#yamlPreviewBtn').addEventListener('click',async()=>{
   try{
     $('#yamlError').textContent='';
     invalidate();
     const myGeneration=generation;
     const file=fileEl.files?.[0];
     if(!file||file.size>1048576)throw Error('Выберите YAML-файл не более 1 МиБ');
     const text=await file.text();const mode=modeEl.value;
     const result=await api('/api/yaml/preview','POST',{text,mode});
     if(!dialog.open || myGeneration!==generation || fileEl.files?.[0]!==file || modeEl.value!==mode)return;
     const c=result.counts, ch=result.changes;
     $('#yamlPreviewInfo').innerHTML=`<div class="panel panel-body"><b>Предпросмотр · ${mode==='merge'?'объединение':'полная замена'}</b><p>Добавить: <b>${c.add}</b> · Обновить: <b>${c.update}</b> · Без изменений: <b>${c.unchanged}</b> · Удалить: <b>${c.remove}</b> · Итого: <b>${c.total}</b></p>${['add','update','remove'].map(k=>ch[k].length?`<p><b>${{add:'Новые',update:'Обновляемые',remove:'Удаляемые'}[k]}:</b> ${esc(ch[k].join(', '))}</p>`:'').join('')}<p class="warning">Импорт не применяет правила на серверах. После импорта проверьте Plan/Diff.</p></div>`;
     snapshot={text,mode,fingerprint:result.fingerprint};commitBtn.disabled=false;
   }catch(err){$('#yamlError').textContent=err.message||String(err)}
 });
 commitBtn.addEventListener('click',async()=>{
   try{
     if(!snapshot)throw Error('Сначала выполните предпросмотр');
     if(modeEl.value!==snapshot.mode)throw Error('Режим изменился — повторите предпросмотр');
     const expected=snapshot.mode==='replace'?'REPLACE_POLICIES':'IMPORT_YAML';
     if($('#yamlConfirm').value.trim()!==expected)throw Error('Введите '+expected+' для подтверждения');
     const res=await api('/api/yaml/import','POST',{...snapshot,confirm:expected});
     dialog.close();flash(`YAML сохранён: новых ${res.counts.add}, обновлено ${res.counts.update}, удалено ${res.counts.remove}. Далее Plan/Diff → Deploy.`);
     await navigate('policies');
   }catch(err){$('#yamlError').textContent=err.message||String(err)}
 });
 invalidate();
}

async function settingsPage(){
 const agents=await api('/api/agents');
 page.innerHTML=heading('Состояние системы','Установленные агенты и ограничения лабораторной альфы.',`<div class="btn-row">${btn('Экспорт YAML','settings:yaml-export')}${btn('Импорт YAML','settings:yaml-import')}${btn('Экспорт JSON','settings:export')}${btn('Импорт JSON','settings:import')}${btn('Обновить','go:settings')}</div>`)+
 table(['Узел','IP','SSH','Транзакция','Карантин','Boot policy'],agents.map(a=>`<tr><td><b>${esc(a.id)}</b></td><td>${esc(a.ip)}</td><td>${a.reachable?tag('Подключён','green'):tag('Ошибка','red')}</td><td>${a.state?tag(a.state,a.state==='CLEAN'?'green':'yellow'):esc(a.error)}</td><td>${a.quarantined?tag('КАРАНТИН','red'):tag('Норма','green')}</td><td>${a.boot_policy?tag('Есть','green'):tag('Нет','grey')}</td></tr>`))+
 `<div class="panel"><div class="panel-head"><h3>Границы Alpha 1.4 R2</h3></div><div class="panel-body"><p>Установка и регистрация хостов — через Ansible. Веб-панель не выдаёт права sudo и не устанавливает агентов.</p><p>HBF поддерживает ACCEPT, DROP, REJECT, TCP/UDP/ICMP, IPv4/IPv6, диапазоны и списки портов, CIDR-группы, conntrack и rate-limited DROP logging. Базовая policy accept сохранена, NAT/маршрутизация и физическое обнаружение не реализованы; ACCEPT не отменяет решения других firewall.</p><p>Доступ к панели — по локальному адресу <span class="inline-code">127.0.0.1:8088</span>; для удалённого доступа используйте SSH-туннель.</p><p>Нет строгой атомарности COMMIT между серверами. Состояние <span class="inline-code">partial</span> требует ручной сверки.</p><p class="hint">Код агента, sudoers и реестр доступных серверов устанавливаются root-администратором. Веб-приложение работает от <b>admin_hbf</b>, а на узлах — <b>agent_hbf</b>.</p></div></div>`;
}

async function action(key){
 const [kind,what,id]=key.split(':');
 if(kind==='go')return navigate(what);
 if(kind==='host'){
   if(what==='add')return hostModal();
   if(what==='quarantine'||what==='release'){
     const on=what==='quarantine';
     if(!confirm(on?`Включить карантин ${id}? Весь трафик кроме loopback и управления SSH/22 с контроллера будет прерван. Продолжить?`:`Снять карантин ${id}? Это вернёт ранее применённые обычные политики HBF, но не разрешает трафик, заблокированный другими firewall.`))return;
     const r=await api('/api/hosts/'+encodeURIComponent(id)+'/quarantine','POST',{confirm:on?'QUARANTINE':'RELEASE'});
     flash(on?'Карантин включён для '+id:'Карантин снят с '+id);return navigate('hosts');
   }
   if(what==='edit')return hostModal(id);
   if(what==='delete'&&confirm('Удалить хост '+id+'?')){await api('/api/hosts/'+encodeURIComponent(id),'DELETE');flash('Хост удалён из списка');return navigate('hosts')}
 }
 if(kind==='policy'){
   if(what==='add')return policyModal();
   if(what==='edit')return policyModal(id);
   const policy=(await api('/api/policies')).find(p=>p.id===id);
   if(!policy)return;
   if(what==='toggle'){await api('/api/policies/'+encodeURIComponent(id),'PUT',{...policy,enabled:!policy.enabled});flash('Статус правила изменён — требуется Deploy.');return navigate('policies')}
   if(what==='delete'&&confirm('Удалить правило '+policy.name+'?')){await api('/api/policies/'+encodeURIComponent(id),'DELETE');flash('Правило удалено — требуется Deploy.');return navigate('policies')}
 }
 if(kind==='settings'){
   if(what==='yaml-import')return yamlImportModal();
   if(what==='yaml-export'){const r=await api('/api/yaml/export');saveDownload(r.filename,r.yaml,'text/yaml;charset=utf-8');return;}
   if(what==='export'){
     const data=await api('/api/export');const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
     const u=URL.createObjectURL(blob);const a=document.createElement('a');a.href=u;a.download='hbf-alpha-backup.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);return;
   }
   if(what==='import'){
     mod(`<h3>Импорт политик JSON</h3><p class="warning">Текущие политики будут заменены. Изменения появятся в nftables только после Deploy.</p><form id="modalForm"><label>Выбери экспорт HBF Alpha<input type="file" name="file" accept=".json,application/json" required></label>${foot}</form>`,async fd=>{
       const file=fd.get('file');if(!file||file.size>1000000)throw Error('Файл отсутствует или слишком большой');
       const json=JSON.parse(await file.text());const result=await api('/api/import','POST',json);flash('Импортировано политик: '+result.count+'. Требуется Deploy.');
     });return;
   }
 }
 if(kind==='deploy'){
   if(what==='preflight'){
     $('#preflightResult').textContent='Проверяю оба агента…';
     const r=await api('/api/preflight');
     $('#preflightResult').innerHTML=r.ready?`<span class="healthy">✓ Preflight пройден, ${r.hosts} хоста(ов).</span>`:`<span class="error">${r.blockers.map(esc).join('; ')}</span>`;return;
   }
   if(what==='start'){
     if($('#deployConfirm').value!=='DEPLOY')throw Error('Для подтверждения введите DEPLOY');
     if(!confirm('Применить политики на всех зарегистрированных узлах?'))return;
     const r=await api('/api/deploy','POST',{fingerprint:currentFingerprint,confirm:'DEPLOY'});
     flash('Deploy запущен: '+r.job_id);return watchJob(r.job_id);
   }
   if(what==='reconcile'){
     if(!confirm('Сверка частичного DEPLOY не восстанавливает различающиеся политики. Проверить CLEAN на обоих узлах и разрешить новый Deploy?'))return;
     const r=await api('/api/reconcile/'+encodeURIComponent(id),'POST',{confirm:'ACK_PARTIAL'});
     flash(r.note);return navigate('deploy');
   }
   if(what==='log')return watchJob(id);
 }
 if(kind==='history'&&what==='restore'){
   if(!confirm('Восстановить политики версии #'+id+'? Текущие политики в БД будут заменены. Firewall изменится только после Deploy.'))return;
   await api('/api/revisions/'+encodeURIComponent(id)+'/restore','POST');flash('Версия восстановлена в БД. Запустите Deploy.');return navigate('history');
 }
}

async function watchJob(id){
 const dialog=$('#modal');
 $('#modalBody').innerHTML=`<div class="modal-content"><h3>Журнал развёртывания <span class="rule-name">${esc(id)}</span></h3><p id="jobState">Чтение…</p><pre id="jobLogs"></pre><div class="modal-foot"><button type="button" class="btn" id="closeLog">Закрыть</button></div></div>`;
 if(!dialog.open)dialog.showModal();
 $('#closeLog').onclick=()=>dialog.close();
 async function tick(){
   if(!dialog.open)return;
   try{
     const r=await api('/api/deployments/'+encodeURIComponent(id));
     $('#jobState').innerHTML=tag(r.state,r.state==='success'?'green':r.state==='running'?'yellow':'red');
     $('#jobLogs').textContent=r.logs.map(x=>`[${x.at}] ${x.message}`).join('\n');
     $('#jobLogs').scrollTop=$('#jobLogs').scrollHeight;
     if(r.state==='running')setTimeout(tick,2500);
   }catch(e){$('#jobState').textContent=e.message}
 }
 tick();
}

document.querySelectorAll('nav button').forEach(b=>b.addEventListener('click',()=>navigate(b.dataset.page)));
$('#logoutBtn').addEventListener('click',async()=>{try{await api('/api/logout','POST')}catch{}showLogin()});
$('#loginForm').addEventListener('submit',async e=>{e.preventDefault();$('#loginError').textContent='';try{const r=await api('/api/login','POST',{username:$('#username').value,password:$('#password').value});csrf=r.csrf;username=r.username;$('#password').value='';showApp()}catch(err){$('#loginError').textContent=err.message}});
(async()=>{try{const r=await api('/api/me');csrf=r.csrf;username=r.username;showApp()}catch{showLogin()}})();
