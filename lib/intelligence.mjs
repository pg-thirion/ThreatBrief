export const KEV='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const MIRROR='https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
const EPSS='https://api.first.org/data/v1/epss';
const CVE=/^CVE-\d{4}-\d{4,19}$/;
const MAX=16*1024*1024, TTL=900000, MAX_STALE=86400000, BACKOFF=60000;
const day=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(s)&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString().slice(0,10)===s;
const str=(s,n)=>typeof s==='string'&&s.trim().length>0&&s.length<=n;
export async function readJSON(response,max=MAX){
  if(!response.ok)throw Error('Upstream HTTP '+response.status);
  if(Number(response.headers.get('content-length'))>max){await response.body?.cancel();throw Error('Response exceeds limit');}
  if(!response.body)throw Error('Missing body');
  const reader=response.body.getReader(),decoder=new TextDecoder('utf-8',{fatal:true});
  let size=0;const parts=[];
  try{
    while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>max)throw Error('Response exceeds limit');parts.push(decoder.decode(value,{stream:true}));}
    parts.push(decoder.decode());return JSON.parse(parts.join(''));
  }catch(e){await reader.cancel().catch(()=>{});throw e;}finally{reader.releaseLock();}
}
export function validateCatalogue(feed,now=Date.now()){
  if(!feed||!str(feed.catalogVersion,100)||typeof feed.dateReleased!=='string'||!Number.isFinite(Date.parse(feed.dateReleased))||Date.parse(feed.dateReleased)>now+86400000||!Array.isArray(feed.vulnerabilities)||feed.vulnerabilities.length<1||feed.vulnerabilities.length>20000||feed.count!==feed.vulnerabilities.length)throw Error('Invalid catalogue envelope');
  const seen=new Set();
  return feed.vulnerabilities.map(v=>{
    if(!v||typeof v.cveID!=='string'||!CVE.test(v.cveID)||seen.has(v.cveID)||!str(v.vendorProject,300)||!str(v.product,500)||!str(v.vulnerabilityName,1000)||!str(v.shortDescription,10000)||!str(v.requiredAction,10000)||!day(v.dateAdded)||Date.parse(v.dateAdded)>now+86400000||!day(v.dueDate)||!['Known','Unknown'].includes(v.knownRansomwareCampaignUse))throw Error('Invalid or duplicate KEV record');
    seen.add(v.cveID);
    return {id:v.cveID,vendor:v.vendorProject,product:v.product,title:v.vulnerabilityName,description:v.shortDescription,action:v.requiredAction,added:v.dateAdded,due:v.dueDate,ransomware:v.knownRansomwareCampaignUse==='Known',forensicTriage:v.forensicTriage==='Yes'?true:v.forensicTriage==='No'?false:null,epss:null};
  }).sort((a,b)=>b.added.localeCompare(a.added)||a.id.localeCompare(b.id));
}
export function parseEPSS(payload,ids){
  if(!payload||!Array.isArray(payload.data))throw Error('Invalid EPSS envelope');
  const allowed=new Set(ids),out=new Map();
  for(const v of payload.data){
    if(!v||!allowed.has(v.cve)||!day(v.date)||!(typeof v.epss==='number'||typeof v.epss==='string'&&/^(?:0(?:\.\d+)?|1(?:\.0+)?)$/.test(v.epss)))continue;
    const score=Number(v.epss);if(Number.isFinite(score)&&score>=0&&score<=1)out.set(v.cve,{score,date:v.date});
  }
  return out;
}
export function createIntelligenceService({fetcher=globalThis.fetch,clock=Date.now,timeout=7000}={}){
  let cache,pending,retryAt=0;
  async function get(url,max=MAX){return readJSON(await fetcher(url,{signal:AbortSignal.timeout(timeout),redirect:'error',headers:{accept:'application/json'}}),max);}
  function fallback(now){if(cache&&now-Date.parse(cache.fetchedAt)<=MAX_STALE)return {...cache,stale:true};throw Error('No usable intelligence snapshot');}
  async function refresh(){
    let feed,records,source;
    for(const url of [KEV,MIRROR]){
      try{const candidate=await get(url);const validated=validateCatalogue(candidate,clock());if(cache&&Date.parse(candidate.dateReleased)<Date.parse(cache.released))throw Error('Catalogue rollback');feed=candidate;records=validated;source=url;break;}catch{}
    }
    if(!feed)throw Error('Both KEV sources unavailable');
    const ids=records.slice(0,40).map(v=>v.id);let epssStatus='unavailable';
    try{const values=parseEPSS(await get(EPSS+'?cve='+encodeURIComponent(ids.join(',')),256*1024),ids);for(const v of records)if(values.has(v.id))v.epss=values.get(v.id);epssStatus=values.size+' of '+ids.length+' newest CVEs enriched';}catch{}
    const now=clock();
    return {records,source,version:feed.catalogVersion,released:feed.dateReleased,fetchedAt:new Date(now).toISOString(),epssStatus,stale:now-Date.parse(feed.dateReleased)>7*86400000};
  }
  return {async get(){const now=clock();if(cache&&now-Date.parse(cache.fetchedAt)<TTL)return cache;if(now<retryAt)return fallback(now);if(!pending)pending=refresh().then(v=>{cache=v;retryAt=0;return v;}).catch(()=>{retryAt=clock()+BACKOFF;return fallback(clock());}).finally(()=>{pending=null;});return pending;}};
}
const service=createIntelligenceService();
export const getIntelligence=()=>service.get();
