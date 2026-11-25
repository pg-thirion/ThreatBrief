import test from 'node:test';
import assert from 'node:assert/strict';
import {makeServer} from '../server.mjs';
import {once} from 'node:events';
test('HTTP routes, methods, headers, outage and traversal handling',async t=>{
  const server=makeServer({getFeed:async()=>{throw Error('offline');}});
  server.listen(0,'127.0.0.1');await once(server,'listening');
  t.after(()=>{server.closeAllConnections();return new Promise(resolve=>server.close(resolve));});
  const base='http://127.0.0.1:'+server.address().port;
  const home=await fetch(base);assert.equal(home.status,200);assert.match(home.headers.get('content-security-policy'),/frame-ancestors 'none'/);assert.match(await home.text(),/ThreatBrief/);
  assert.deepEqual(await (await fetch(base+'/healthz')).json(),{status:'ok'});
  const outage=await fetch(base+'/api/intelligence');assert.equal(outage.status,503);assert.equal(outage.headers.get('retry-after'),'60');
  assert.equal((await fetch(base+'/api/intelligence',{method:'POST'})).status,405);
  assert.equal((await fetch(base+'/package.json')).status,404);
  assert.equal((await fetch(base+'/..%2fpackage.json')).status,404);
  assert.equal(await (await fetch(base+'/',{method:'HEAD'})).text(),'');
});
