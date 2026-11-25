// Local-only analyst workflow. No credentials or hostnames should be stored here.
export const STATUSES=['New','Investigating','Confirmed affected','Mitigating','Resolved','Not affected','Risk accepted'];
const terminal=new Set(['Resolved','Not affected','Risk accepted']);
const ID=/^(?:CVE-\d{4}-\d{4,19}|DEMO-\d{3})$/;
const safe=(s,max)=>typeof s==='string'?s.trim().slice(0,max):'';
const day=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(s)&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString().slice(0,10)===s;
const iso=s=>typeof s==='string'&&s.length<=40&&Number.isFinite(Date.parse(s));
const own=(o,k)=>Object.hasOwn(o,k)?o[k]:undefined;
export const scopeKey=(p,demo)=>JSON.stringify([demo?'demo':'live',safe(p.name,100).toLowerCase(),safe(p.industry,100).toLowerCase()]);
export function empty(){return {version:1,cases:{},watch:[],audit:[],snapshot:null};}
export function cleanCase(c={}){
  if(!c||typeof c!=='object')c={};
  const requiresEvidence=['Resolved','Not affected','Risk accepted','Confirmed affected'].includes(c.status);
  return {status:STATUSES.includes(c.status)&&(!requiresEvidence||safe(c.evidence,1000))?c.status:'New',owner:safe(c.owner,100),notes:safe(c.notes,2000),evidence:safe(c.evidence,1000),tags:Array.isArray(c.tags)?[...new Set(c.tags.map(t=>safe(t,40)).filter(Boolean))].slice(0,10):[],due:day(c.due)?c.due:'',created:iso(c.created)?c.created:'',updated:iso(c.updated)?c.updated:''};
}
export function validateWorkspace(x){
  if(!x||x.version!==1||typeof x.cases!=='object'||!x.cases||Array.isArray(x.cases)||!Array.isArray(x.watch)||!Array.isArray(x.audit))throw Error('Invalid workspace format');
  const out=empty();
  for(const [id,c] of Object.entries(x.cases).slice(0,5000))if(ID.test(id))out.cases[id]=cleanCase(c);
  out.watch=[...new Set(x.watch.filter(id=>typeof id==='string'&&ID.test(id)))].slice(0,5000);
  out.audit=x.audit.filter(a=>a&&typeof a.id==='string'&&ID.test(a.id)&&iso(a.at)&&['case updated','watch added','watch removed'].includes(a.action)).slice(0,300).map(a=>({id:a.id,at:a.at,action:a.action,detail:safe(a.detail,200)}));
  const s=x.snapshot;
  if(s&&iso(s.at)&&Array.isArray(s.ids))out.snapshot={at:s.at,ids:[...new Set(s.ids.filter(id=>typeof id==='string'&&ID.test(id)))].slice(0,20000)};
  return out;
}
export const caseFor=(w,id)=>cleanCase(own(w.cases,id));
export const isClosed=c=>terminal.has(c.status);
export function updateCase(w,id,input,now=new Date().toISOString()){
  if(!ID.test(id)||!STATUSES.includes(input.status))throw Error('Invalid case');
  if(!own(w.cases,id)&&Object.keys(w.cases).length>=5000)throw Error('Case capacity reached');
  const previous=caseFor(w,id);
  const proposed={...previous,...input,created:previous.created||now,updated:now};
  if(['Resolved','Not affected','Risk accepted','Confirmed affected'].includes(proposed.status)&&!safe(proposed.evidence,1000))throw Error('Record supporting evidence or decision justification before selecting this status');
  const next=cleanCase(proposed);
  if(input.due&&!day(input.due))throw Error('Invalid target date');
  w.cases[id]=next;
  w.audit.unshift({id,at:now,action:'case updated',detail:previous.status+' → '+next.status});w.audit=w.audit.slice(0,300);
  return next;
}
export function toggleWatch(w,id,now=new Date().toISOString()){
  if(!ID.test(id))throw Error('Invalid record ID');
  const exists=w.watch.includes(id);
  if(!exists&&w.watch.length>=5000)throw Error('Watchlist capacity reached');
  w.watch=exists?w.watch.filter(x=>x!==id):[...w.watch,id];
  w.audit.unshift({id,at:now,action:exists?'watch removed':'watch added',detail:''});w.audit=w.audit.slice(0,300);
  return !exists;
}
export function targetDate(row,c){
  if(c.due)return c.due;
  if(!c.created||!row.priority)return '';
  const days={Critical:3,High:14,Review:30}[row.priority];
  if(!days)return '';
  return new Date(Date.parse(c.created)+days*86400000).toISOString().slice(0,10);
}
export function sla(row,c,today=new Date().toISOString().slice(0,10)){
  if(isClosed(c))return 'Closed';
  const due=targetDate(row,c);
  if(!due)return 'Unscheduled';
  return due<today?'Overdue':due===today?'Due today':'On track';
}
export function metrics(rows,w,today){
  const result={open:0,confirmed:0,closed:0,overdue:0,unassigned:0,watched:0,coverage:0,vendors:[]};
  const vendors=new Map();
  for(const r of rows){const c=caseFor(w,r.id);if(isClosed(c))result.closed++;else {result.open++;if(!c.owner)result.unassigned++;if(sla(r,c,today)==='Overdue')result.overdue++;}
    if(c.status==='Confirmed affected'||c.status==='Mitigating')result.confirmed++;
    if(w.watch.includes(r.id))result.watched++;if(r.epss!==null&&r.epss!==undefined)result.coverage++;
    vendors.set(r.vendor,(vendors.get(r.vendor)||0)+1);
  }
  result.vendors=[...vendors.entries()].sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0])).slice(0,5);return result;
}
export function filterRows(rows,w,f={},today){
  const query=safe(f.q,200).toLowerCase();
  const filtered=rows.filter(r=>{
    const c=caseFor(w,r.id);
    return (!query||[r.id,r.title,r.product,r.vendor,c.owner,...c.tags].join(' ').toLowerCase().includes(query))&&(!f.priority||r.priority===f.priority)&&(!f.status||c.status===f.status)&&(!f.vendor||r.vendor===f.vendor)&&(!f.watch||w.watch.includes(r.id))&&(!f.ransom||r.ransomware)&&(!f.forensic||r.forensicTriage===true)&&(!f.overdue||sla(r,c,today)==='Overdue')&&(!f.unassigned||(!c.owner&&!isClosed(c)))&&(!f.tag||c.tags.some(t=>t.toLowerCase()===f.tag.toLowerCase()));
  });
  const cmp={score:(a,b)=>(b.score??-1)-(a.score??-1),newest:(a,b)=>b.added.localeCompare(a.added),epss:(a,b)=>(b.epss?.score??-1)-(a.epss?.score??-1),due:(a,b)=>(targetDate(a,caseFor(w,a.id))||'9999').localeCompare(targetDate(b,caseFor(w,b.id))||'9999'),vendor:(a,b)=>a.vendor.localeCompare(b.vendor)}[f.sort]||((a,b)=>(b.score??-1)-(a.score??-1));
  return filtered.sort((a,b)=>cmp(a,b)||b.added.localeCompare(a.added)||a.id.localeCompare(b.id));
}
export function compareSnapshot(w,records){
  if(!w.snapshot)return {baseline:false,added:[],removed:[]};
  const old=new Set(w.snapshot.ids),current=new Set(records.map(r=>r.id));
  return {baseline:true,added:[...current].filter(id=>!old.has(id)),removed:[...old].filter(id=>!current.has(id))};
}
export function saveSnapshot(w,records,now=new Date().toISOString()){
  w.snapshot={at:now,ids:[...new Set(records.map(r=>r.id).filter(id=>ID.test(id)))].slice(0,20000)};
}
export function page(rows,index,size=25){
  const total=Math.max(1,Math.ceil(rows.length/size)),current=Math.max(0,Math.min(total-1,index));
  return {current,total,items:rows.slice(current*size,(current+1)*size)};
}
export function csvCell(v){
  let s=String(v??'').replace(/\u0000/g,'');
  if(/^[\s\u0000-\u001f]*[=+\-@]/.test(s)||/^[\t\r\n]/.test(s))s="'"+s;
  return '"'+s.replace(/"/g,'""')+'"';
}
export function exportCSV(rows,w,feed){
  const headers=['Data mode','CVE','Vendor','Product','Priority','Score','EPSS probability','Ransomware known','Status','Owner','Target date (internal)','SLA','Tags','Notes','Evidence','Source'];
  return [headers,...rows.map(r=>{const c=caseFor(w,r.id);return [feed.demo?'SYNTHETIC':feed.stale?'STALE':'LIVE',r.id,r.vendor,r.product,r.priority||'',r.score??'',r.epss?.score??'',r.ransomware?'Yes':'Unknown',c.status,c.owner,targetDate(r,c),sla(r,c),c.tags.join(' | '),c.notes,c.evidence,feed.source];})].map(a=>a.map(csvCell).join(',')).join('\r\n')+'\r\n';
}
export function exportJSON(rows,w,feed,profile){
  return JSON.stringify({schema:1,generated:new Date().toISOString(),mode:feed.demo?'synthetic':feed.stale?'stale':'live',source:feed.source,retrieved:feed.fetchedAt,organisation:profile.name,industry:profile.industry,records:rows.map(r=>({...r,case:caseFor(w,r.id),target:targetDate(r,caseFor(w,r.id)),sla:sla(r,caseFor(w,r.id))}))},null,2);
}
export function caseAppendix(rows,w){
  const esc=s=>String(s??'').replace(/[\u0000-\u001f\u007f]+/g,' ').replace(/[\\\x60*_{}\[\]()<>#!|~]/g,m=>'\\'+m);
  return ['','## Local analyst workflow','Internal target dates are policy defaults (3/14/30 days after case creation), not CISA deadlines. Case status is analyst-entered, not independently verified.',...rows.flatMap(r=>{const c=caseFor(w,r.id);return ['- '+r.id+': '+c.status+' | Owner: '+esc(c.owner||'Unassigned')+' | Target: '+(targetDate(r,c)||'Unscheduled')+' | '+sla(r,c),...(c.evidence?['  Evidence: '+esc(c.evidence)]:[]),...(c.notes?['  Notes: '+esc(c.notes)]:[])];})].join('\n');
}
export function backup(w,scope){return JSON.stringify({schema:1,scope,workspace:w},null,2);}
export function restore(text,scope){
  if(typeof text!=='string'||text.length>8_000_000)throw Error('Backup exceeds size limit');
  const x=JSON.parse(text);
  if(!x||x.schema!==1||x.scope!==scope)throw Error('Backup belongs to a different organisation or data mode');
  return validateWorkspace(x.workspace);
}
