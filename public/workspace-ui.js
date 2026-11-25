import {STATUSES,empty,scopeKey,validateWorkspace,caseFor,updateCase,toggleWatch,targetDate,sla,metrics,filterRows,compareSnapshot,saveSnapshot,page,exportCSV,exportJSON,caseAppendix,backup,restore} from './workspace.js';
const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const download=(name,text,type)=>{const u=URL.createObjectURL(new Blob([text],{type})),a=el('a');a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);};
const filterIds=['scope','sort','case-status','vendor','tag','watched','ransom-only','forensic-only','overdue-only','unassigned-only'];
let w=empty(),key='',pageIndex=0,current=null,rerender=()=>{};
function read(k){try{const raw=localStorage.getItem('threatbrief-workspace:'+k);return raw?validateWorkspace(JSON.parse(raw)):empty();}catch{$('workflow-message').textContent='Local workspace could not be read; using an empty session.';return empty();}}
function persist(){try{localStorage.setItem('threatbrief-workspace:'+key,JSON.stringify(w));$('workflow-message').textContent='Saved locally in this browser.';}catch{$('workflow-message').textContent='Browser storage unavailable or full. Changes are in memory only; export a backup.';}}
function setOptions(node,values){const v=node.value;node.replaceChildren(new Option('All vendors',''),...values.map(s=>new Option(s,s)));node.value=values.includes(v)?v:'';}
export function initWorkspace(render){
  rerender=render;
  $('case-status').append(...STATUSES.map(s=>new Option(s,s)));
  for(const id of filterIds)$(id).addEventListener(id==='tag'?'input':'change',()=>{pageIndex=0;render();});
  for(const id of ['search','priority','window'])$(id).addEventListener(id==='search'?'input':'change',()=>{pageIndex=0;});
  $('prev-page').onclick=()=>{pageIndex--;render();};$('next-page').onclick=()=>{pageIndex++;render();};
  $('reset-filters').onclick=()=>{for(const id of ['search','priority','case-status','vendor','tag'])$(id).value='';for(const id of ['watched','ransom-only','forensic-only','overdue-only','unassigned-only'])$(id).checked=false;$('scope').value='matched';$('sort').value='score';pageIndex=0;render();};
  $('export-csv').onclick=()=>{if(current)download('ThreatBrief-'+(current.feed.demo?'demo-':'')+'queue.csv',exportCSV(current.filtered,w,current.feed),'text/csv;charset=utf-8');};
  $('export-json').onclick=()=>{if(current)download('ThreatBrief-'+(current.feed.demo?'demo-':'')+'queue.json',exportJSON(current.filtered,w,current.feed,current.profile),'application/json');};
  $('backup').onclick=()=>{if(current)download('ThreatBrief-workspace.json',backup(w,key),'application/json');};
  $('restore').onchange=async()=>{const file=$('restore').files[0];$('restore').value='';if(!file||!current)return;const scope=key;
    try{if(file.size>8000000)throw Error('Backup too large');const candidate=restore(await file.text(),scope);if(key!==scope)throw Error('Workspace changed during import');if(!confirm('Replace this local workspace with the selected backup?'))return;w=candidate;persist();render();}catch(e){$('workflow-message').textContent=e.message;}};
  $('clear-workspace').onclick=()=>{if(!current||!confirm('Delete cases, watchlist, audit and baseline for this organisation and data mode?'))return;w=empty();try{localStorage.removeItem('threatbrief-workspace:'+key);}catch{}persist();render();};
  $('baseline').onclick=()=>{if(!current||current.feed.stale)return;saveSnapshot(w,current.feed.records);persist();render();};
  $('print').onclick=()=>window.print();
}
export function workflowRender(profile,feed,matched){
  const k=scopeKey(profile,!!feed.demo);
  if(k!==key){key=k;w=read(k);pageIndex=0;}
  const scope=$('scope').value;
  const matchedById=new Map(matched.map(r=>[r.id,r]));
  const rows=scope==='catalogue'?feed.records.map(r=>matchedById.get(r.id)||{...r,matched:[],reasons:[],score:null,priority:''}):matched;
  setOptions($('vendor'),[...new Set(rows.map(r=>r.vendor))].sort());
  const f={q:$('search').value,priority:$('priority').value,status:$('case-status').value,vendor:$('vendor').value,tag:$('tag').value,sort:$('sort').value,watch:$('watched').checked,ransom:$('ransom-only').checked,forensic:$('forensic-only').checked,overdue:$('overdue-only').checked,unassigned:$('unassigned-only').checked};
  const filtered=filterRows(rows,w,f),p=page(filtered,pageIndex);pageIndex=p.current;
  current={profile,feed,filtered};
  $('page-info').textContent=filtered.length+' results · Page '+(p.current+1)+' of '+p.total;
  $('prev-page').disabled=p.current===0;$('next-page').disabled=p.current+1>=p.total;
  const m=metrics(matched,w);
  $('workflow-metrics').replaceChildren(...[['Open candidates',m.open],['Confirmed / mitigating',m.confirmed],['Closed',m.closed],['Overdue',m.overdue],['Unassigned open',m.unassigned],['Watched matches',m.watched],['EPSS coverage',m.coverage+'/'+matched.length]].map(([label,value])=>{const box=el('div',undefined,'workflow-stat');box.append(el('strong',String(value)),el('span',label));return box;}));
  $('vendor-summary').textContent=m.vendors.length?m.vendors.map(([v,n])=>v+' ('+n+')').join(' · '):'No matched vendors';
  const delta=compareSnapshot(w,feed.records);
  $('delta').textContent=delta.baseline?'Baseline '+w.snapshot.at.slice(0,10)+': '+delta.added.length+' added, '+delta.removed.length+' removed. '+(delta.added.length?'New IDs: '+delta.added.slice(0,15).join(', '):'')+(delta.removed.length?' Removed IDs: '+delta.removed.slice(0,15).join(', '):''):'Save a catalogue baseline to compare future updates.';
  $('baseline').disabled=!!feed.stale;
  $('audit-list').replaceChildren(...(w.audit.length?w.audit.slice(0,20).map(a=>el('li',a.at.slice(0,16).replace('T',' ')+' UTC · '+a.id+' · '+a.action+(a.detail?' · '+a.detail:''))):[el('li','No local activity recorded.')]));
  return p.items;
}
export function caseLabel(r){const c=caseFor(w,r.id);return c.status+' · '+sla(r,c)+(w.watch.includes(r.id)?' · Watched':'');}
export function caseEditor(r){
  const scope=key,c=caseFor(w,r.id),box=el('div',undefined,'case-editor'),form=el('form');
  box.append(el('h3','Analyst case'),el('p','Internal target: '+(targetDate(r,c)||'Not scheduled')+' · '+sla(r,c)));
  const watch=el('button',w.watch.includes(r.id)?'Remove from watchlist':'Add to watchlist');watch.type='button';watch.onclick=()=>{if(scope!==key)return;try{toggleWatch(w,r.id);persist();rerender();}catch(e){$('workflow-message').textContent=e.message;}};
  box.append(watch);
  const controls={};
  function field(name,label,tag,value,opts={}){
    const l=el('label',label),n=el(tag);for(const [k,v] of Object.entries(opts))n[k]=v;
    if(name==='status')n.append(...STATUSES.map(s=>new Option(s,s)));n.value=value;l.append(n);form.append(l);controls[name]=n;
  }
  field('status','Case status','select',c.status);field('owner','Assigned owner','input',c.owner,{maxLength:100});
  field('due','Internal target date (optional override)','input',c.due,{type:'date'});
  field('tags','Tags (comma separated)','input',c.tags.join(', '),{maxLength:410});
  field('notes','Analyst notes','textarea',c.notes,{maxLength:2000,rows:3});
  field('evidence','Supporting evidence / justification','textarea',c.evidence,{maxLength:1000,rows:2});
  const submit=el('button','Save case','primary');submit.type='submit';const msg=el('p','','hint');msg.setAttribute('role','status');form.append(submit,msg);
  form.onsubmit=e=>{e.preventDefault();if(scope!==key)return;try{const input=Object.fromEntries(Object.entries(controls).map(([k,n])=>[k,n.value]));input.tags=input.tags.split(',');updateCase(w,r.id,input);persist();rerender();}catch(err){msg.textContent=err.message;}};
  box.append(form);return box;
}
export function workflowAppendix(rows){return caseAppendix(rows,w);}
export function invalidateWorkspace(){current=null;$('workflow-metrics').replaceChildren();$('audit-list').replaceChildren();$('vendor-summary').textContent='Unavailable';$('delta').textContent='No usable snapshot';$('page-info').textContent='No usable snapshot';$('prev-page').disabled=true;$('next-page').disabled=true;}
