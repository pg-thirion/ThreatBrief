import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {getIntelligence} from './lib/intelligence.mjs';
import {securityHeaders} from './lib/security.mjs';
const files={'/':'index.html','/index.html':'index.html','/app.js':'app.js','/engine.js':'engine.js','/workspace.js':'workspace.js','/workspace-ui.js':'workspace-ui.js','/style.css':'style.css','/demo.js':'demo.js','/favicon.svg':'favicon.svg'};
const types={html:'text/html; charset=utf-8',js:'text/javascript; charset=utf-8',css:'text/css; charset=utf-8',svg:'image/svg+xml'};
export function makeServer({getFeed=getIntelligence}={}){
  const server=createServer(async(req,res)=>{
    for(const [k,v] of Object.entries(securityHeaders))res.setHeader(k,v);
    res.setHeader('Cache-Control','no-store');
    if(req.method!=='GET'&&req.method!=='HEAD'){res.writeHead(405,{Allow:'GET, HEAD'});return res.end();}
    const end=body=>res.end(req.method==='HEAD'?undefined:body);
    let path;try{path=new URL(req.url,'http://localhost').pathname;}catch{res.statusCode=400;return end('Invalid request');}
    if(path==='/healthz'){res.setHeader('Content-Type','application/json');return end('{"status":"ok"}');}
    if(path==='/api/intelligence'){
      res.setHeader('Content-Type','application/json');
      try{return end(JSON.stringify(await getFeed()));}catch{res.statusCode=503;res.setHeader('Retry-After','60');return end(JSON.stringify({error:'Live intelligence unavailable'}));}
    }
    if(!Object.hasOwn(files,path)){res.statusCode=404;return end('Not found');}
    try{const file=files[path];res.setHeader('Content-Type',types[file.split('.').pop()]);return end(await readFile(new URL('./public/'+file,import.meta.url)));}catch{res.statusCode=500;return end('Unavailable');}
  });
  server.requestTimeout=15000;server.headersTimeout=10000;server.keepAliveTimeout=5000;
  return server;
}
if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
  const server=makeServer();
  server.listen(Number(process.env.PORT||3000),process.env.HOST||'127.0.0.1',()=>console.log('ThreatBrief listening'));
  for(const event of ['SIGTERM','SIGINT'])process.once(event,()=>{server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),10000).unref();});
}
