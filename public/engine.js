const normal=s=>String(s||'').toLowerCase().replace(/[^a-z0-9]+/g,' ').trim();
const contains=(whole,part)=>(' '+whole+' ').includes(' '+part+' ');
export function parseInventory(text){
  return text.split(/\r?\n/).map(line=>{
    const [product,...flags]=line.split('|').map(s=>s.trim());
    return {product,internet:flags.some(x=>normal(x)==='internet'),critical:flags.some(x=>normal(x)==='critical')};
  }).filter(a=>normal(a.product).length>=3).slice(0,200);
}
export function rank(records,assets,days=90,now=Date.now()){
  return records.flatMap(r=>{
    const age=Math.floor((now-Date.parse(r.added+'T00:00:00Z'))/86400000);
    if(!Number.isFinite(age)||age<0||(days!==0&&age>=days))return [];
    const product=normal(r.product),full=normal(r.vendor+' '+r.product);
    if(!product)return [];
    const matched=assets.filter(a=>{
      const needle=normal(a.product);
      if(!needle||needle===normal(r.vendor))return false;
      return needle===product||needle===full||contains(needle,full);
    });
    if(!matched.length)return [];
    const reasons=[['Known exploitation',45]];
    const strongest=[...matched].sort((a,b)=>(Number(b.internet)*25+Number(b.critical)*15)-(Number(a.internet)*25+Number(a.critical)*15))[0];
    if(strongest.internet)reasons.push(['Declared internet-facing',25]);
    if(strongest.critical)reasons.push(['Declared business-critical',15]);
    if(r.ransomware)reasons.push(['Known ransomware use',10]);
    if(age<30)reasons.push(['Added within 30 days',5]);
    const score=reasons.reduce((s,x)=>s+x[1],0);
    return [{...r,score,reasons,matched,priority:score>=85?'Critical':score>=65?'High':'Review'}];
  }).sort((a,b)=>b.score-a.score||b.added.localeCompare(a.added)||a.id.localeCompare(b.id));
}
export function briefing(profile,feed,rows,days){
  const line=s=>String(s??'').replace(/[\u0000-\u001f\u007f]+/g,' ').replace(/[\\\x60*_{}\[\]()<>#!|~]/g,m=>'\\'+m).slice(0,10000);
  const n=rows.filter(x=>x.priority==='Critical').length;
  return ['# ThreatBrief: '+line(profile.name||'Organisation'),'Generated: '+new Date().toISOString(),'Industry: '+line(profile.industry),'Source: '+line(feed.source),'Data mode: '+(feed.demo?'SYNTHETIC DEMO':feed.stale?'STALE LIVE SNAPSHOT':'Live snapshot'),'Catalogue release: '+line(feed.released),'Retrieved: '+line(feed.fetchedAt),'Window: '+(days||'All catalogue history')+(days?' days':''),'','## Executive assessment',rows.length+' potential product matches, '+n+' critical priority. These are not confirmed affected assets or incidents.',rows.length?'Validate installed versions and exposure, then assign owners and patch according to verified vendor guidance.':'No matches found in this scope. Review inventory and use complementary intelligence sources.','','## Analyst actions',...rows.flatMap(r=>['### '+r.id+' | '+line(r.title),r.priority+' ('+r.score+'/100 heuristic priority)','Matched products: '+r.matched.map(a=>line(a.product)).join(', '),'Evidence: '+r.reasons.map(x=>x[0]+' +'+x[1]).join('; '),'EPSS: '+(r.epss?(r.epss.score*100).toFixed(2)+'% ('+line(r.epss.date)+')':'Unavailable'),'CISA guidance: '+line(r.action),'CISA federal due date: '+line(r.due),'CISA ransomware status: '+(r.ransomware?'Known':'Unknown / not confirmed'),'CISA forensic triage: '+(r.forensicTriage===true?'Yes; review applicable directive and incident procedures':r.forensicTriage===false?'No':'Not supplied'),'Next step: Confirm affected versions, exposure and patch availability. Assign an owner and verify remediation.',...(feed.demo?[]:['Reference: https://nvd.nist.gov/vuln/detail/'+r.id]),'']),'## Limitations','Product-name correlation only. No version or compromise verification. EPSS is a separate exploitation probability, not the priority score. CISA deadlines are federal deadlines. Human review required.'].join('\n');
}
