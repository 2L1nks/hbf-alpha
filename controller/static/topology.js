'use strict';
/* HBF Alpha 1.2 R2 Topology Graph — accessible neutral grid, draggable nodes,
 * wheel zoom, pan and compact policy lanes. This is a read-only visual model
 * of declared HBF policies, not observed network connectivity.
 */
window.HBFTopology = (() => {
  const GRID = 32, MIN_ZOOM = 0.28, MAX_ZOOM = 3.5;
  const state = {
    mode:'auto', expanded:new Set(), search:'', group:'', proto:'all', status:'active',
    port:'', selected:null, zoom:1, tx:0, ty:0, positions:new Map()
  };
  const escapeText=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const safeNum=n=>Number.isFinite(+n)?Number(n):0;
  const portText=p=>(p.proto==='icmp'||p.proto==='icmpv6')?(p.icmp_type||'ICMP'):(p.ports||String(p.port||'—'));
  const clamp=(x,min,max)=>Math.min(max,Math.max(min,x));
  const snap=x=>Math.round(x/GRID)*GRID;
  const attrNode=id=>escapeText(id);
  function filterPolicy(p){
    if(state.proto!=='all'&&p.proto!==state.proto)return false;
    if(state.status==='active'&&!p.enabled)return false;
    if(state.status==='disabled'&&p.enabled)return false;
    if(state.port){
      const port=Number(state.port),ranges=String(portText(p)).split(',');
      if(!ranges.some(v=>{const pair=v.split('-').map(Number);return pair.length===1?pair[0]===port:pair[0]<=port&&port<=pair[1]}))return false;
    }
    return true;
  }
  function graphView(model){
    const found=model.nodes.filter(h=>{
      const text=[h.id,h.label,h.ip,h.grp,h.zone,h.role,h.site,h.vlan,h.description].join(' ').toLowerCase();
      return (!state.search||text.includes(state.search.toLowerCase()))&&
             (!state.group||(h.grp||'Без группы')===state.group);
    });
    const hosts=new Map(found.map(h=>[h.id,h])),groups=new Map();
    for(const h of found){const g=h.grp||'Без группы';if(!groups.has(g))groups.set(g,[]);groups.get(g).push(h)}
    const groupMode=state.mode==='groups'||(state.mode==='auto'&&groups.size>=2);
    const nodes=new Map(),hostNode=new Map();
    const orderedGroups=[...groups.keys()].sort((a,b)=>a.localeCompare(b,'ru'));
    for(const g of orderedGroups){
      const subset=groups.get(g),collapsed=groupMode&&!state.expanded.has(g);
      if(collapsed){
        const id='g:'+g;nodes.set(id,{id,group:g,kind:'group',hosts:subset,label:g,count:subset.length});
        for(const h of subset)hostNode.set(h.id,id);
      }else{
        for(const h of subset){
          const id='h:'+h.id;nodes.set(id,{id,group:g,kind:'host',host:h,label:h.label,hosts:[h],count:1});
          hostNode.set(h.id,id);
        }
      }
    }
    const edges=new Map();
    for(const edge of model.edges){
      if(!hosts.has(edge.source)||!hosts.has(edge.target))continue;
      const a=hostNode.get(edge.source),b=hostNode.get(edge.target);
      if(!a||!b)continue;
      const activeHosts=Boolean(hosts.get(edge.source).enabled&&hosts.get(edge.target).enabled);
      const filtered=edge.rules.filter(p=>filterPolicy({...p,enabled:Boolean(p.enabled)&&activeHosts}));
      if(!filtered.length)continue;
      const key=JSON.stringify([a,b]);
      if(!edges.has(key))edges.set(key,{id:key,source:a,target:b,rules:[],active:0});
      const target=edges.get(key);
      target.rules.push(...filtered);
      target.active+=filtered.filter(p=>p.enabled&&activeHosts).length;
    }
    return {nodes:[...nodes.values()],edges:[...edges.values()].map(e=>({...e,count:e.rules.length})),groups:orderedGroups,hosts:found};
  }
  // Default positions are grouped on a generous grid; browser-only user
  // adjustments override these coordinates (no server policy edits).
  function layout(view){
    const grouped=new Map();
    for(const n of view.nodes){if(!grouped.has(n.group))grouped.set(n.group,[]);grouped.get(n.group).push(n)}
    const names=[...grouped.keys()].sort((a,b)=>a.localeCompare(b,'ru'));
    const cols=names.length<=2?Math.max(1,names.length):2;
    const cellWidth=448,margin=96,gap=80,positions=new Map(),labels=[];
    const rowHeights=[];
    for(let k=0;k<names.length;k++){
      const members=grouped.get(names[k]);
      const nodeRows=Math.ceil(members.length/3);
      rowHeights[Math.floor(k/cols)]=Math.max(rowHeights[Math.floor(k/cols)]||0,
                                     members.length===1?256:Math.max(320,nodeRows*128+144));
    }
    const rowOffsets=[];let y=margin;
    for(const h of rowHeights){rowOffsets.push(y);y+=h+gap}
    for(let k=0;k<names.length;k++){
      const group=names[k],members=grouped.get(group),col=k%cols,row=Math.floor(k/cols);
      const ox=margin+col*(cellWidth+gap),oy=rowOffsets[row];
      if(members.length===1&&members[0].kind==='group'){
        positions.set(members[0].id,{x:snap(ox+cellWidth/2),y:snap(oy+112),r:41});
      }else{
        labels.push({text:group,x:ox+cellWidth/2,y:oy+24});
        const perRow=Math.min(3,members.length),step=cellWidth/(perRow+1);
        members.forEach((n,i)=>positions.set(n.id,{
          x:snap(ox+step*(i%perRow+1)),y:snap(oy+112+Math.floor(i/perRow)*128),r:33}));
      }
    }
    for(const [id,p] of positions){
      const saved=state.positions.get(id);
      if(saved&&Number.isFinite(saved.x)&&Number.isFinite(saved.y)){
        positions.set(id,{...p,x:saved.x,y:saved.y});
      }
    }
    return {positions,labels,width:Math.max(640,margin*2+cols*cellWidth+Math.max(0,cols-1)*gap),
            height:Math.max(480,y-gap+40)};
  }
  function curvePoints(a,b,bend){
    const dx=b.x-a.x,dy=b.y-a.y,len=Math.max(1,Math.hypot(dx,dy)),ux=dx/len,uy=dy/len;
    const sx=a.x+ux*((a.r||33)+5),sy=a.y+uy*((a.r||33)+5);
    const ex=b.x-ux*((b.r||33)+11),ey=b.y-uy*((b.r||33)+11);
    const mx=(sx+ex)/2,my=(sy+ey)/2;
    return {sx,sy,ex,ey,cx:mx-uy*bend,cy:my+ux*bend};
  }
  function collisionScore(a,b,bend,obstacles){
    const {sx,sy,ex,ey,cx,cy}=curvePoints(a,b,bend);
    let total=0;
    for(const o of obstacles){
      if(o===a||o===b)continue;
      const radius=(o.r||33)+20;
      for(let step=1;step<34;step++){
        const t=step/34,one=1-t;
        const x=one*one*sx+2*one*t*cx+t*t*ex;
        const y=one*one*sy+2*one*t*cy+t*t*ey;
        if(Math.hypot(x-o.x,y-o.y)<radius){total++;break}
      }
    }
    return total;
  }
  function baseBend(a,b,reciprocal,obstacles=[]){
    if(a===b||Math.hypot(a.x-b.x,a.y-b.y)<1)return 0;
    const choices=reciprocal?[65,110,175,250,320]:[0,64,-64,120,-120,195,-195,290,-290];
    let best=choices[0],score=Infinity;
    for(const c of choices){const s=collisionScore(a,b,c,obstacles);
      if(s<score){score=s;best=c}if(!s)break;
    }
    return best;
  }
  // lane=-1 / +1 draws two distinct policies. For self-pairs each lane is
  // a separate arc around the same host/group (a===b by stable identity).
  function edgePath(a,b,reciprocal=false,obstacles=[],lane=0){
    if(a===b||Math.hypot(a.x-b.x,a.y-b.y)<1){
      const r=a.r||33,side=lane>0?-1:1;
      const reach=110+Math.abs(lane)*20;
      const x0=a.x+side*r*.65,x1=a.x+side*(r+reach);
      const top=a.y-r-72-Math.abs(lane)*16;
      return {d:`M ${x0} ${a.y-r*.72} C ${x1} ${top}, ${a.x-side*(r+reach)} ${top}, ${a.x-side*r*.65} ${a.y-r*.72}`,
              label:{x:a.x+lane*45,y:a.y-r-82-Math.abs(lane)*8}};
    }
    const bend=baseBend(a,b,reciprocal,obstacles)+lane*26;
    const {sx,sy,ex,ey,cx,cy}=curvePoints(a,b,bend);
    return {d:`M ${sx} ${sy} Q ${cx} ${cy} ${ex} ${ey}`,
            label:{x:(sx+ex+2*cx)/4,y:(sy+ey+2*cy)/4}};
  }
  function visibleEdgeSlots(edge){
    const count=edge.rules.length;
    if(count===0)return {lanes:[],overflow:false};
    return {lanes:count===1?[0]:[-1,1],overflow:count>2};
  }
  function nodeInfo(n,model,agentMap){
    const row=(label,val)=>`<div><b>${escapeText(label)}:</b> ${escapeText(val??'—')}</div>`;
    if(n.kind==='group')return `<b>Группа: ${escapeText(n.group)}</b>${row('Хостов',n.count)}<div>${n.hosts.map(x=>escapeText(x.label)).join(', ')}</div><small>Нажмите, чтобы раскрыть группу</small>`;
    const h=n.host,agent=agentMap.get(h.id);
    const inbound=model.edges.filter(e=>e.target===h.id).reduce((a,e)=>a+e.rules.length,0);
    const outbound=model.edges.filter(e=>e.source===h.id).reduce((a,e)=>a+e.rules.length,0);
    return `<b>${escapeText(h.label)}</b>${row('ID',h.id)}${row('IPv4',h.ip)}${row('Группа',h.grp)}${row('VLAN',h.vlan)}${row('Зона',h.zone)}${row('Роль',h.role)}${row('Площадка',h.site)}${row('Описание',h.description)}${row('Агент',agent?(agent.reachable?(agent.state||'ONLINE'):'OFFLINE'):'не проверен')}${row('Карантин',agent?(agent.reachable?(agent.quarantined?'ВКЛЮЧЁН':agent.quarantine_desired?'НЕСООТВЕТСТВИЕ':'выключен'):'неизвестно'):'не проверен')}${row('Входящих правил',inbound)}${row('Исходящих правил',outbound)}`;
  }
  function policyRow(p){
    return `<div><b>${escapeText(p.name||p.id)}</b> <small>${escapeText(p.id)}</small><br>${escapeText(p.src)} → ${escapeText(p.dst)} · ${escapeText(String(p.action||'drop').toUpperCase())} · ${escapeText(String(p.family||'ipv4').toUpperCase())} ${escapeText(String(p.proto||'').toUpperCase())}/${escapeText(portText(p))} · priority ${escapeText(p.priority??100)} · ${escapeText(p.states?'ct '+p.states:'все состояния')}${p.log_drop?' · LOG':''} · ${p.enabled?'Активно':'Выключено'}<br><small>Источник: ${escapeText(p.src_cidrs||'IP узла')} · Назначение: ${escapeText(p.dst_cidrs||'IP узла')}</small></div>`;
  }
  function edgeInfo(e,full=true){
    const rules=full?e.rules:e.rules.slice(0,2);
    const rows=rules.map(policyRow).join('');
    const extra=!full&&e.count>2?'<div>Нажмите на «…», чтобы увидеть все правила.</div>':'';
    return `<b>${e.source===e.target?'Правила внутри одного узла / группы':'Направленная связь HBF'}</b><div>Всего правил: ${e.count} · активных: ${e.active}</div><div class="topology-rule-list">${rows}${extra}</div>`;
  }
  function render(page,context){
    const model=context.model,agents=context.agents||[],summary=context.summary||{};
    const agentMap=new Map(agents.map(a=>[a.id,a]));
    if(state.mode==='auto')state.mode=model.groups.length>1?'groups':'hosts';
    const groups=[...new Set(model.nodes.map(h=>h.grp||'Без группы'))].sort();
    page.innerHTML=`<div class="content-heading"><div><h3>Topology Graph</h3><p class="muted">Объявленные политики HBF — не карта фактических сетевых соединений.</p></div><button class="btn soft" id="topReset">Сбросить фильтры</button></div>
      <div class="panel"><div class="panel-body topology-controls">
        <label>Вид<select id="topMode"><option value="groups">Группы</option><option value="hosts">Хосты</option></select></label>
        <label>Поиск хоста / IP<input id="topSearch" placeholder="Имя, IP, роль, VLAN" value="${escapeText(state.search)}"></label>
        <label>Группа<select id="topGroup"><option value="">Все</option>${groups.map(g=>`<option value="${escapeText(g)}">${escapeText(g)}</option>`).join('')}</select></label>
        <label>Протокол<select id="topProto"><option value="all">Все</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMPv4</option><option value="icmpv6">ICMPv6</option></select></label>
        <label>Правила<select id="topStatus"><option value="active">Активные</option><option value="all">Все</option><option value="disabled">Неактивные</option></select></label>
        <label>Порт<input id="topPort" placeholder="Все" type="number" min="1" max="65535" value="${escapeText(state.port)}"></label>
      </div></div>
      <div class="panel"><div class="panel-head topology-head"><h3>Схема связей</h3><div class="topology-toolbar"><span id="topCounter" class="note"></span>
        <button class="btn small" id="topZoomOut" title="Отдалить" aria-label="Отдалить граф">−</button>
        <span id="topZoomValue" class="note topology-zoom-value">100%</span>
        <button class="btn small" id="topZoomIn" title="Приблизить" aria-label="Приблизить граф">+</button>
        <button class="btn small" id="topFit" title="Вписать граф в окно">Вписать</button>
        <button class="btn small" id="topResetNodes" title="Вернуть узлы в исходные позиции">Сбросить позиции</button></div></div>
        <div class="topology-layout"><div id="topCanvas" class="topology-canvas" aria-label="Сетка графа объявленных политик HBF"></div>
        <aside id="topDetails" class="topology-details"><h3>Сведения</h3><p class="muted">Наведите курсор на узел. Перетаскивайте узлы по сетке; колесо мыши — масштаб, свободная область — перемещение схемы. Нажмите «…», чтобы раскрыть все связи.</p></aside></div>
        <div class="panel-body note">Если правил между узлами больше двух, видны две линии и «…». Нажатие на «…» показывает полный список в правой панели. Позиции хранятся только в этом браузере; политик и Deploy изменение схемы не касается.</div>
      </div>`;
    const q=id=>page.querySelector('#'+id);
    q('topMode').value=state.mode;q('topGroup').value=state.group;q('topProto').value=state.proto;q('topStatus').value=state.status;
    let canvas=q('topCanvas'),svg,world,tooltip,visible,geo,edges,reciprocal;
    function readPositions(){
      try{
        const obj=JSON.parse(localStorage.getItem('hbf-alpha-topology-positions-v2')||'{}');
        if(obj&&typeof obj==='object'&&!Array.isArray(obj)){
          for(const [id,p] of Object.entries(obj).slice(0,250)){
            if(id.length<200&&p&&Number.isFinite(p.x)&&Number.isFinite(p.y)&&Math.abs(p.x)<100000&&Math.abs(p.y)<100000)
              state.positions.set(id,{x:p.x,y:p.y});
          }
        }
      }catch(_e){ /* Private mode may deny storage; graph remains functional. */ }
    }
    function savePositions(){
      try{localStorage.setItem('hbf-alpha-topology-positions-v2',JSON.stringify(Object.fromEntries(state.positions)))}catch(_e){}
    }
    readPositions();
    function applyViewport(){
      if(!world)return;
      world.setAttribute('transform',`translate(${state.tx} ${state.ty}) scale(${state.zoom})`);
      q('topZoomValue').textContent=Math.round(state.zoom*100)+'%';
    }
    function fit(){
      const w=Math.max(1,canvas.clientWidth),h=Math.max(1,canvas.clientHeight);
      state.zoom=clamp(Math.min((w-56)/geo.width,(h-48)/geo.height,1.2),MIN_ZOOM,MAX_ZOOM);
      state.tx=(w-geo.width*state.zoom)/2;
      state.ty=(h-geo.height*state.zoom)/2;
      applyViewport();
    }
    function zoomAt(next,px,py){
      next=clamp(next,MIN_ZOOM,MAX_ZOOM);
      const rx=(px-state.tx)/state.zoom,ry=(py-state.ty)/state.zoom;
      state.zoom=next;state.tx=px-rx*next;state.ty=py-ry*next;applyViewport();
    }
    function lineMarkup(e,i){
      const a=geo.positions.get(e.source),b=geo.positions.get(e.target);
      if(!a||!b)return '';
      const slots=visibleEdgeSlots(e);
      const recur=reciprocal.has(JSON.stringify([e.target,e.source]));
      const dim=state.selected&&e.source!==state.selected&&e.target!==state.selected;
      const lanes=slots.lanes.map((lane,j)=>{
        const s=edgePath(a,b,recur,[...geo.positions.values()],lane);
        return `<g class="topology-lane" data-lane="${j}" data-slot="${lane}"><path class="topology-link" d="${s.d}" marker-end="url(#topArrow)"/><path class="topology-hit" d="${s.d}"/></g>`;
      }).join('');
      let badge='';
      if(slots.overflow){
        const center=edgePath(a,b,recur,[...geo.positions.values()],0).label;
        badge=`<g class="topology-more" data-more="${i}" role="button" tabindex="0" aria-label="Показать все ${e.count} правил"><rect x="${center.x-23}" y="${center.y-16}" width="46" height="32" rx="12"/><text x="${center.x}" y="${center.y+5}" text-anchor="middle">···</text></g>`;
      }
      return `<g class="topology-edge ${dim?'dimmed':''}" data-edge="${i}" tabindex="0" role="button" aria-label="${escapeText(e.source)} → ${escapeText(e.target)}: ${e.count} правил">${lanes}${badge}</g>`;
    }
    function nodeMarkup(n){
      const p=geo.positions.get(n.id);if(!p)return '';
      const marked=state.selected===n.id;
      const quarantine=n.kind==='host'&&agentMap.get(n.host.id)?.quarantined;
      return `<g class="topology-node ${marked?'selected':''} ${quarantine?'topology-quarantined':''}" data-node="${attrNode(n.id)}" role="button" tabindex="0" transform="translate(${p.x} ${p.y})" aria-label="${escapeText(n.kind==='host'?n.host.label:'Группа '+n.label)}">
        <circle r="${p.r}"/><text y="5" text-anchor="middle">${escapeText(n.kind==='group'?'×'+n.count:n.host.id.slice(0,14))}</text>
        <text y="${p.r+20}" class="topology-node-caption" text-anchor="middle">${quarantine?'⛔ ':''}${escapeText(n.label.slice(0,23))}</text></g>`;
    }
    function renderEdges(movedNode=null){
      for(const el of svg.querySelectorAll('[data-edge]')){
        const e=edges[Number(el.dataset.edge)];
        if(movedNode!==null&&e.source!==movedNode&&e.target!==movedNode)continue;
        const a=geo.positions.get(e.source),b=geo.positions.get(e.target);
        if(!a||!b)continue;
        const recur=reciprocal.has(JSON.stringify([e.target,e.source]));
        el.querySelectorAll('[data-lane]').forEach(l=>{
          const s=edgePath(a,b,recur,[...geo.positions.values()],Number(l.dataset.slot));
          l.querySelectorAll('path').forEach(p=>p.setAttribute('d',s.d));
        });
        const more=el.querySelector('[data-more]');
        if(more){const center=edgePath(a,b,recur,[...geo.positions.values()],0).label;
          more.querySelector('rect').setAttribute('x',center.x-23);
          more.querySelector('rect').setAttribute('y',center.y-16);
          more.querySelector('text').setAttribute('x',center.x);
          more.querySelector('text').setAttribute('y',center.y+5);
        }
      }
    }
    function show(ev,html){
      tooltip.innerHTML=html;tooltip.hidden=false;
      const rect=canvas.getBoundingClientRect(),x=ev.clientX-rect.left+15,y=ev.clientY-rect.top+15;
      const width=Math.min(340,canvas.clientWidth-16);
      tooltip.style.left=clamp(x,8,Math.max(8,canvas.clientWidth-width-10))+'px';
      tooltip.style.top=clamp(y,8,Math.max(8,canvas.clientHeight-tooltip.offsetHeight-10))+'px';
    }
    function handleHover(group,html){
      group.addEventListener('pointermove',ev=>{if(!group.classList.contains('dragging'))show(ev,html)});
      group.addEventListener('pointerleave',()=>{tooltip.hidden=true});
      group.addEventListener('focus',()=>{tooltip.innerHTML=html;tooltip.style.left='20px';tooltip.style.top='20px';tooltip.hidden=false});
      group.addEventListener('blur',()=>tooltip.hidden=true);
    }
    function showConnection(e){
      state.selected=null;
      q('topDetails').innerHTML=`<h3>Все правила связи</h3>${edgeInfo(e,true)}<p class="hint">Только объявленные политики HBF, а не измеренный трафик.</p>`;
      svg.querySelectorAll('.topology-edge').forEach(x=>x.classList.remove('dimmed'));
      svg.querySelectorAll('.topology-node').forEach(x=>x.classList.remove('selected'));
    }
    function showHost(n){
      const h=n.host,related=model.edges.filter(e=>e.source===h.id||e.target===h.id);
      const rules=related.flatMap(e=>e.rules).filter(filterPolicy).sort((a,b)=>a.id.localeCompare(b.id));
      q('topDetails').innerHTML=`<h3>${escapeText(h.label)}</h3>${nodeInfo(n,model,agentMap)}<h4>Политики (${rules.length})</h4><div class="topology-rule-list">${rules.map(policyRow).join('')||'Нет политик'}</div><p class="note">Последний Deploy: ${escapeText(summary.last_deployment?.state||'—')}</p>`;
    }
    function draw(){
      visible=graphView(model);geo=layout(visible);edges=visible.edges;
      reciprocal=new Set(edges.map(e=>JSON.stringify([e.source,e.target])));
      const lines=edges.map(lineMarkup).join(''),nodes=visible.nodes.map(nodeMarkup).join('');
      canvas.innerHTML=`<svg xmlns="http://www.w3.org/2000/svg" class="topology-svg" role="img" aria-label="Граф политик HBF на сетке">
        <defs><pattern id="topGridSmall" width="${GRID}" height="${GRID}" patternUnits="userSpaceOnUse"><path d="M ${GRID} 0 L 0 0 0 ${GRID}" fill="none" stroke="#e6eaf0" stroke-width="1"/></pattern>
        <marker id="topArrow" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 Z" fill="currentColor"/></marker></defs>
        <g id="topWorld"><rect class="topology-grid" x="-150000" y="-150000" width="300000" height="300000" fill="url(#topGridSmall)"/>
        ${geo.labels.map(x=>`<text class="topology-group-label" x="${x.x}" y="${x.y}" text-anchor="middle">${escapeText(x.text)}</text>`).join('')}
        <g id="topEdges">${lines}</g><g id="topNodes">${nodes}</g></g></svg><div id="topTooltip" class="topology-tooltip" hidden></div>`;
      svg=canvas.querySelector('svg');world=svg.querySelector('#topWorld');tooltip=q('topTooltip');
      q('topCounter').textContent=`${visible.hosts.length} хостов · ${visible.nodes.length} узлов · ${edges.length} пар · ${edges.reduce((a,e)=>a+e.count,0)} правил`;
      applyViewport();
      // Panning works only from blank grid; nodes have independent drag.
      let pan=null;
      svg.addEventListener('pointerdown',ev=>{
        if(ev.button!==0||ev.target.closest('[data-node],[data-edge]'))return;
        pan={id:ev.pointerId,x:ev.clientX,y:ev.clientY,tx:state.tx,ty:state.ty};
        svg.setPointerCapture?.(ev.pointerId);svg.classList.add('panning');tooltip.hidden=true;
      });
      svg.addEventListener('pointermove',ev=>{
        if(!pan||ev.pointerId!==pan.id)return;
        state.tx=pan.tx+ev.clientX-pan.x;state.ty=pan.ty+ev.clientY-pan.y;applyViewport();
      });
      const endPan=ev=>{if(pan&&ev.pointerId===pan.id){pan=null;svg.classList.remove('panning')}};
      svg.addEventListener('pointerup',endPan);svg.addEventListener('pointercancel',endPan);
      // Dragging nodes preserves their coordinates across filtering, regrouping
      // and subsequent page visits in this browser. Ctrl+click not required.
      for(const el of svg.querySelectorAll('[data-node]')){
        const n=visible.nodes.find(v=>v.id===el.dataset.node);if(!n)continue;
        handleHover(el,nodeInfo(n,model,agentMap));
        let drag=null,suppressClickUntil=0;
        el.addEventListener('pointerdown',ev=>{
          if(ev.button!==0)return;
          ev.stopPropagation();
          const p=geo.positions.get(n.id);
          drag={id:ev.pointerId,x:ev.clientX,y:ev.clientY,ox:p.x,oy:p.y,moved:false};
          el.setPointerCapture?.(ev.pointerId);
        });
        el.addEventListener('pointermove',ev=>{
          if(!drag||ev.pointerId!==drag.id)return;
          const dx=ev.clientX-drag.x,dy=ev.clientY-drag.y;
          if(!drag.moved&&Math.hypot(dx,dy)<5)return;
          drag.moved=true;el.classList.add('dragging');tooltip.hidden=true;
          const p=geo.positions.get(n.id);
          p.x=snap(drag.ox+dx/state.zoom);p.y=snap(drag.oy+dy/state.zoom);
          el.setAttribute('transform',`translate(${p.x} ${p.y})`);renderEdges(n.id);
        });
        const end=ev=>{
          if(!drag||ev.pointerId!==drag.id)return;
          if(drag.moved){
            const p=geo.positions.get(n.id);
            state.positions.set(n.id,{x:p.x,y:p.y});savePositions();suppressClickUntil=Date.now()+300;renderEdges();
          }
          drag=null;el.classList.remove('dragging');
        };
        el.addEventListener('pointerup',end);el.addEventListener('pointercancel',end);
        const select=()=>{
          if(Date.now()<suppressClickUntil)return;
          if(n.kind==='group'){
            if(state.expanded.has(n.group))state.expanded.delete(n.group);else state.expanded.add(n.group);
            state.selected=null;draw();
          }else{
            state.selected=state.selected===n.id?null:n.id;
            draw();
          }
        };
        el.addEventListener('click',select);
        el.addEventListener('keydown',ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();select()}});
      }
      for(const el of svg.querySelectorAll('[data-edge]')){
        const e=edges[Number(el.dataset.edge)];if(!e)continue;
        handleHover(el,edgeInfo(e,false));
        el.addEventListener('click',()=>showConnection(e));
        el.addEventListener('keydown',ev=>{if(ev.key==='Enter'){ev.preventDefault();showConnection(e)}});
      }
      for(const el of svg.querySelectorAll('[data-more]')){
        const e=edges[Number(el.dataset.more)];if(!e)continue;
        el.addEventListener('click',ev=>{ev.stopPropagation();showConnection(e)});
        el.addEventListener('keydown',ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();ev.stopPropagation();showConnection(e)}});
      }
      if(state.selected){
        const n=visible.nodes.find(x=>x.id===state.selected);
        if(n&&n.kind==='host')showHost(n);
        else q('topDetails').innerHTML='<h3>Сведения</h3><p>Выберите узел или связь.</p>';
      }
    }
    function wheel(ev){
      ev.preventDefault();
      const r=canvas.getBoundingClientRect();
      const px=ev.clientX-r.left,py=ev.clientY-r.top;
      zoomAt(state.zoom*(ev.deltaY<0?1.12:1/1.12),px,py);
    }
    for(const [id,key] of [['topMode','mode'],['topGroup','group'],['topProto','proto'],['topStatus','status']]){
      q(id).addEventListener('change',ev=>{state[key]=ev.target.value;state.selected=null;draw()});
    }
    for(const [id,key] of [['topSearch','search'],['topPort','port']]){
      q(id).addEventListener('input',ev=>{state[key]=ev.target.value.trim();state.selected=null;draw()});
    }
    q('topZoomIn').onclick=()=>zoomAt(state.zoom*1.2,canvas.clientWidth/2,canvas.clientHeight/2);
    q('topZoomOut').onclick=()=>zoomAt(state.zoom/1.2,canvas.clientWidth/2,canvas.clientHeight/2);
    q('topFit').onclick=fit;
    q('topResetNodes').onclick=()=>{state.positions.clear();savePositions();draw();fit()};
    q('topReset').onclick=()=>{state.mode=model.groups.length>1?'groups':'hosts';state.expanded.clear();state.search='';state.group='';state.proto='all';state.status='active';state.port='';state.selected=null;render(page,context)};
    canvas.addEventListener('wheel',wheel,{passive:false});
    draw();fit();
  }
  return {render,graphView,layout,edgePath,visibleEdgeSlots,state};
})();
