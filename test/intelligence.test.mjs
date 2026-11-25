import test from 'node:test';
import assert from 'node:assert/strict';
import {validateCatalogue,parseEPSS,readJSON,createIntelligenceService,KEV,MIRROR} from '../lib/intelligence.mjs';
const now=Date.parse('2026-11-26T00:00:00Z');
const record={cveID:'CVE-2026-1234',vendorProject:'Microsoft',product:'Exchange',vulnerabilityName:'Example',shortDescription:'Example description',requiredAction:'Patch',dateAdded:'2026-11-25',dueDate:'2026-12-01',knownRansomwareCampaignUse:'Unknown',forensicTriage:'Yes'};
const fixture={catalogVersion:'2026.11.25',dateReleased:'2026-11-25T00:00:00Z',count:1,vulnerabilities:[record]};
const response=v=>new Response(JSON.stringify(v),{status:200});
test('validates full catalogue and preserves forensic fields',()=>assert.equal(validateCatalogue(fixture,now)[0].forensicTriage,true));
test('rejects duplicates, invalid counts, dates and ransomware values',()=>{
  for(const v of [{...fixture,count:2},{...fixture,count:2,vulnerabilities:[record,record]},{...fixture,vulnerabilities:[{...record,dateAdded:'2026-02-31'}]},{...fixture,vulnerabilities:[{...record,knownRansomwareCampaignUse:'False'}]}])assert.throws(()=>validateCatalogue(v,now));
});
test('EPSS ignores invalid and unrelated scores',()=>{
  assert.equal(parseEPSS({data:[{cve:record.cveID,epss:null,date:'2026-11-25'},{cve:record.cveID,epss:'1.2',date:'2026-11-25'},{cve:'CVE-2026-9999',epss:0.8,date:'2026-11-25'}]},[record.cveID]).size,0);
  assert.equal(parseEPSS({data:[{cve:record.cveID,epss:'0.0',date:'2026-11-25'}]},[record.cveID]).get(record.cveID).score,0);
});
test('bounded body rejects excess bytes',async()=>{await assert.rejects(readJSON(new Response('{"long":"abcdef"}'),5),/limit/);});
test('mirror, single flight, stale fallback, backoff and expiry',async()=>{
  let time=now,calls=0,down=false;
  const service=createIntelligenceService({clock:()=>time,fetcher:async url=>{calls++;if(down||url===KEV)throw Error('offline');if(url===MIRROR)return response(fixture);return response({data:[]});}});
  const [a,b]=await Promise.all([service.get(),service.get()]);assert.equal(a,b);assert.equal(a.source,MIRROR);assert.equal(calls,3);
  await service.get();assert.equal(calls,3);time+=16*60000;down=true;
  assert.equal((await service.get()).stale,true);assert.equal(calls,5);
  assert.equal((await service.get()).stale,true);assert.equal(calls,5);
  time+=25*3600000;await assert.rejects(service.get(),/No usable/);
});
test('cold failure never fabricates data',async()=>{await assert.rejects(createIntelligenceService({fetcher:async()=>{throw Error('offline');}}).get());});
