import {readFile,writeFile,rename,unlink} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {getIntelligence} from '../lib/intelligence.mjs';
import {parseInventory,rank,briefing} from '../public/engine.js';
async function main(){
  const [profilePath,output,window='0']=process.argv.slice(2);
  if(!profilePath||!output||!['0','30','90','365'].includes(window))throw Error('Usage: npm run brief -- profile.json briefing.md [0|30|90|365]');
  const raw=await readFile(profilePath,'utf8');if(raw.length>16000)throw Error('Profile too large');
  const p=JSON.parse(raw);
  if(!p||typeof p.name!=='string'||!p.name.trim()||p.name.length>100||typeof p.industry!=='string'||p.industry.length>100||typeof p.inventory!=='string'||p.inventory.length>12000)throw Error('Invalid profile');
  const assets=parseInventory(p.inventory);if(!assets.length)throw Error('Inventory is empty');
  const feed=await getIntelligence();if(feed.stale)throw Error('Stale intelligence; refusing scheduled report');
  const rows=rank(feed.records,assets,Number(window)),tmp=output+'.'+randomUUID()+'.tmp';
  try{await writeFile(tmp,briefing(p,feed,rows,Number(window)),{encoding:'utf8',mode:0o600,flag:'wx'});await rename(tmp,output);}
  finally{await unlink(tmp).catch(()=>{});}
  console.log('Briefing generated: '+rows.length+' potential matches.');
}
main().catch(e=>{console.error(e.message);process.exitCode=1;});
