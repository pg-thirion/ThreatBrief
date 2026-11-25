export const KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const MIRROR = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
const EPSS = 'https://api.first.org/data/v1/epss';
const valid = /^CVE-\d{4}-\d{4,19}$/;
let cache, pending;
async function json(url) {
  const r = await fetch(url, {signal: AbortSignal.timeout(8000), redirect:'error', headers:{accept:'application/json'}});
  if (!r.ok) throw new Error('Upstream HTTP '+r.status);
  const data = await r.text();
  if(data.length>15_000_000) throw new Error('Feed too large');
  return JSON.parse(data);
}
function clean(v) {
  return {id:v.cveID,vendor:String(v.vendorProject||''),product:String(v.product||''),title:String(v.vulnerabilityName||''),description:String(v.shortDescription||''),action:String(v.requiredAction||''),added:String(v.dateAdded||''),due:String(v.dueDate||''),ransomware:v.knownRansomwareCampaignUse==='Known',epss:null};
}
async function refresh() {
  let feed, source;
  for(const url of [KEV,MIRROR]) {
    try {
      const candidate=await json(url);
      if(!Array.isArray(candidate.vulnerabilities)||!candidate.vulnerabilities.length) throw new Error('Invalid catalogue');
      feed=candidate; source=url; break;
    } catch {}
  }
  if(!feed) throw new Error('CISA KEV is unavailable');
  const records=[...new Map(feed.vulnerabilities.filter(v=>v&&valid.test(v.cveID)).map(v=>[v.cveID,clean(v)])).values()].sort((a,b)=>b.added.localeCompare(a.added));
  if(!records.length) throw new Error('Empty validated catalogue');
  let epssStatus='unavailable';
  try {
    const ids=records.slice(0,40).map(v=>v.id);
    const p=await json(EPSS+'?cve='+encodeURIComponent(ids.join(',')));
    if(!Array.isArray(p.data)) throw new Error('Invalid EPSS');
    const values=new Map(p.data.filter(v=>v.epss!==null&&v.epss!==''&&Number.isFinite(Number(v.epss))&&Number(v.epss)>=0&&Number(v.epss)<=1).map(v=>[v.cve,{score:Number(v.epss),date:String(v.date||'')}]));
    for(const v of records) if(values.has(v.id)) v.epss=values.get(v.id);
    epssStatus='available (newest 40 CVEs requested)';
  } catch {}
  return {records,source,version:String(feed.catalogVersion||''),released:String(feed.dateReleased||''),fetchedAt:new Date().toISOString(),epssStatus,stale:false};
}
export async function getIntelligence() {
  if(cache && Date.now()-Date.parse(cache.fetchedAt)<900_000) return cache;
  if(!pending) pending=refresh().then(v=>{cache=v;return v;}).catch(e=>{if(cache)return {...cache,stale:true};throw e;}).finally(()=>{pending=null;});
  return pending;
}
