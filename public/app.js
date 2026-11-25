import {parseInventory,rank,briefing} from './engine.js';
import {demo} from './demo.js';
import {initWorkspace,workflowRender,caseLabel,caseEditor,workflowAppendix,invalidateWorkspace} from './workspace-ui.js';
const $=id=>document.getElementById(id);
const sample={name:'Example Insurance',industry:'Insurance',inventory:'Microsoft Exchange | internet | critical\nFortinet FortiOS | internet | critical\nApache Tomcat | critical'};
let profile={name:'',industry:'Financial services',inventory:''},feed=null,rows=[],request=0;
try{const saved=JSON.parse(localStorage.getItem('threatbrief-profile')||'null');if(saved&&typeof saved.inventory==='string'&&typeof saved.name==='string'&&typeof saved.industry==='string')profile=saved;}catch{}
function fill(){for(const k of ['name','industry','inventory'])$(k).value=profile[k];}
function save(){try{localStorage.setItem('threatbrief-profile',JSON.stringify(profile));}catch{}}
function el(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;}
function render(){
  if(!feed)return;
  const days=Number($('window').value);
  rows=rank(feed.records,parseInventory(profile.inventory),days);
  const critical=rows.filter(r=>r.priority==='Critical').length;
  $('total').textContent=feed.records.length.toLocaleString();$('matches').textContent=rows.length;$('critical').textContent=critical;$('ransom').textContent=rows.filter(r=>r.ransomware).length;
  $('headline').textContent=critical?critical+' critical-priority candidate'+(critical===1?'':'s'):rows.length?rows.length+' candidate matches':'No candidate matches';
  $('summary').textContent=(profile.name||'Your organisation')+': '+(rows.length?'Validate affected versions and exposure, assign remediation owners and review vendor guidance.':'No matches in the selected scope. Confirm inventory coverage and consider a wider date range.');
  $('export').disabled=false;
  const filtered=workflowRender(profile,feed,rows);
  $('queue').replaceChildren();
  if(!filtered.length){$('queue').append(el('div','No records match the selected scope.','empty'));return;}
  for(const r of filtered){
    const d=el('details'),s=el('summary'),left=el('div'),right=el('span',r.priority?r.priority+' · '+r.score:'Catalogue only','pill '+r.priority);
    left.append(el('small',r.id+' / '+r.added),el('b',r.title||r.product),el('small',r.vendor+' · '+r.product),el('small',caseLabel(r)));s.append(left,right);d.append(s);
    const body=el('div',undefined,'detail');
    const section=(title,value)=>body.append(el('h3',title),el('p',value));
    section('Threat description',r.description);section('Inventory candidates',r.matched.map(a=>a.product).join(', ')||'No inventory candidate in this date scope');
    body.append(el('h3','Priority evidence'));const ul=el('ul');for(const [reason,points] of r.reasons)ul.append(el('li',reason+' +'+points));body.append(ul);
    section('EPSS (separate probability)',r.epss?(r.epss.score*100).toFixed(2)+'% · '+r.epss.date:'Unavailable for this record');
    section('CISA remediation guidance',r.action||'Consult vendor advisory');section('CISA federal deadline',r.due||'Not supplied');section('CISA forensic triage',r.forensicTriage===true?'Yes: review applicable directive and incident procedures':r.forensicTriage===false?'No':'Not supplied');section('Recommended analyst action','Verify installed version and configuration, confirm exposure, assign an owner and validate patch or mitigation. Do not treat a product match as a confirmed incident.');
    if(!feed.demo&&/^CVE-\d{4}-\d{4,19}$/.test(r.id)){const a=el('a','View NVD record ↗');a.href='https://nvd.nist.gov/vuln/detail/'+r.id;a.target='_blank';a.rel='noopener noreferrer';body.append(a);}
    body.append(caseEditor(r));d.append(body);$('queue').append(d);
  }
}
function show(data){feed=data;$('mode').textContent=data.demo?'Synthetic demo':data.stale?'Stale snapshot':'Live intelligence';$('notice').textContent=data.demo?'DEMO: Fictional records and scores. Do not use for operational decisions.':(data.stale?'Stale intelligence snapshot. Verify source freshness. ':'Live CISA KEV catalogue loaded. ')+'EPSS enrichment: '+data.epssStatus;$('kevstate').textContent=data.demo?'Demo':data.stale?'Stale':'Available';$('epssstate').textContent=data.epssStatus;$('freshness').textContent='Catalogue: '+data.version+' · Retrieved '+new Date(data.fetchedAt).toLocaleString();render();}
async function load(){
  const id=++request;$('refresh').disabled=true;$('notice').textContent='Refreshing public intelligence…';
  try{const r=await fetch('/api/intelligence',{signal:AbortSignal.timeout(30000)});if(!r.ok)throw new Error('Unavailable');const data=await r.json();if(!Array.isArray(data.records))throw new Error('Invalid feed');if(id===request)show(data);}
  catch{if(id===request){if(feed&&!feed.demo&&Date.now()-Date.parse(feed.fetchedAt)<=86400000)show({...feed,stale:true});else {if(feed&&!feed.demo){feed=null;rows=[];invalidateWorkspace();$('export').disabled=true;$('queue').replaceChildren();for(const k of ['total','matches','critical','ransom'])$(k).textContent='—';$('headline').textContent='Intelligence unavailable';$('summary').textContent='No usable snapshot remains.';}$('mode').textContent=feed?'Synthetic demo':'Feed unavailable';$('notice').textContent='Live intelligence unavailable. Retry or select the synthetic demo.';if(!feed){$('kevstate').textContent='Unavailable';$('epssstate').textContent='Unavailable';}}}}
  finally{if(id===request)$('refresh').disabled=false;}
}
$('profile').addEventListener('submit',e=>{e.preventDefault();for(const k of ['name','industry','inventory'])profile[k]=$(k).value.trim();save();render();});
$('sample').onclick=()=>{profile={...sample};fill();save();render();};
$('demo').onclick=()=>{request++;$('refresh').disabled=false;if(!profile.inventory){profile={...sample};fill();save();}show(demo);};
$('refresh').onclick=load;
initWorkspace(render);
for(const k of ['window','search','priority'])$(k).addEventListener(k==='search'?'input':'change',render);
$('export').onclick=()=>{if(!feed)return;const blob=new Blob([briefing(profile,feed,rows,Number($('window').value))+workflowAppendix(rows)],{type:'text/markdown;charset=utf-8'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='ThreatBrief-'+new Date().toISOString().slice(0,10)+'.md';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
$('clear').onclick=()=>{if(!confirm('Clear this browser’s organisation profile?'))return;profile={name:'',industry:'Financial services',inventory:''};try{localStorage.removeItem('threatbrief-profile');}catch{}fill();render();};
fill();load();
