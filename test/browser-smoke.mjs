import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {once} from 'node:events';
import {makeServer} from '../server.mjs';
import {demo} from '../public/demo.js';
const server=makeServer({getFeed:async()=>({...demo,demo:false,source:'Offline browser fixture'})});
const wait=ms=>new Promise(r=>setTimeout(r,ms));
const dir=await mkdtemp(join(tmpdir(),'threatbrief-browser-'));
let browser,socket;
try{
  server.listen(0,'127.0.0.1');await once(server,'listening');
  const origin='http://127.0.0.1:'+server.address().port;
  browser=spawn(process.env.CHROME_BIN||'google-chrome',['--headless','--disable-gpu','--disable-dev-shm-usage','--no-sandbox','--remote-debugging-port=0','--user-data-dir='+dir,'about:blank'],{stdio:['ignore','ignore','pipe']});
  const endpoint=await new Promise((resolve,reject)=>{
    const timeout=setTimeout(()=>reject(Error('Chrome startup timeout')),20000);
    browser.once('error',e=>{clearTimeout(timeout);reject(e);});
    browser.once('exit',()=>{clearTimeout(timeout);reject(Error('Chrome exited'));});
    let log='';browser.stderr.on('data',chunk=>{log+=chunk.toString();const m=log.match(/DevTools listening on (ws:\/\/[^\s]+)/);if(m){clearTimeout(timeout);resolve(m[1]);}});
  });
  const port=new URL(endpoint).port;
  const tabs=await (await fetch('http://127.0.0.1:'+port+'/json/list')).json();
  socket=new WebSocket(tabs.find(t=>t.type==='page').webSocketDebuggerUrl);
  await once(socket,'open');
  let sequence=0;const pending=new Map(),errors=[];
  socket.addEventListener('message',event=>{const m=JSON.parse(event.data);if(m.method==='Runtime.exceptionThrown')errors.push(m.params.exceptionDetails.text);if(m.id&&pending.has(m.id)){const {resolve,reject}=pending.get(m.id);pending.delete(m.id);m.error?reject(Error(m.error.message)):resolve(m.result);}});
  const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});
  const evalJS=async expression=>{const v=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(v.exceptionDetails)throw Error(v.exceptionDetails.text);return v.result.value;};
  async function until(expression){for(let i=0;i<100;i++){if(await evalJS(expression))return;await wait(100);}throw Error('Timed out: '+expression);}
  await call('Runtime.enable');await call('Page.enable');await call('Page.navigate',{url:origin});
  await until("document.getElementById('demo') && document.getElementById('mode').textContent==='Live intelligence'");
  await evalJS("document.getElementById('demo').click()");
  await until("document.getElementById('matches').textContent==='3'");
  assert.equal(await evalJS("document.querySelectorAll('#queue details').length"),3);
  await evalJS("document.querySelector('#queue details').open=true;document.querySelector('.case-editor button').click()");
  await until("document.querySelector('#queue summary').textContent.includes('Watched')");
  await evalJS("document.querySelector('#queue details').open=true;{const form=document.querySelector('.case-editor form');form.querySelector('select').value='Confirmed affected';form.querySelector('input').value='Analyst';form.querySelectorAll('textarea')[1].value='Fixture evidence';form.requestSubmit()}");
  await until("document.querySelector('#queue summary').textContent.includes('Confirmed affected')");
  await evalJS("document.getElementById('scope').value='catalogue';document.getElementById('scope').dispatchEvent(new Event('change'))");
  assert.equal(await evalJS("document.querySelectorAll('#queue details').length"),4);
  await evalJS("document.getElementById('watched').checked=true;document.getElementById('watched').dispatchEvent(new Event('change'))");
  assert.equal(await evalJS("document.querySelectorAll('#queue details').length"),1);
  await evalJS("document.getElementById('reset-filters').click()");
  assert.equal(await evalJS("document.querySelectorAll('#queue details').length"),3);
  await evalJS("document.getElementById('baseline').click()");
  assert.match(await evalJS("document.getElementById('delta').textContent"),/0 added, 0 removed/);
  await call('Page.reload');await until("document.getElementById('mode').textContent==='Live intelligence'");
  await evalJS("document.getElementById('demo').click()");
  await until("document.querySelector('#queue summary').textContent.includes('Confirmed affected')");
  assert.deepEqual(errors,[]);
  console.log('Browser smoke: demo, matching, watchlist, case editing, filters, baseline and persistence passed.');
}finally{
  socket?.close();if(browser&&!browser.killed){browser.kill();await Promise.race([once(browser,'exit'),wait(3000)]);}
  server.closeAllConnections();await new Promise(r=>server.close(r));await rm(dir,{recursive:true,force:true,maxRetries:3,retryDelay:200});
}
