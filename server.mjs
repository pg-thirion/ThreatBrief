import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {getIntelligence} from './lib/intelligence.mjs';
const files={'/':'index.html','/index.html':'index.html','/app.js':'app.js','/engine.js':'engine.js','/style.css':'style.css','/demo.js':'demo.js','/favicon.svg':'favicon.svg'};
const types={html:'text/html; charset=utf-8',js:'text/javascript; charset=utf-8',css:'text/css; charset=utf-8',svg:'image/svg+xml'};
createServer(async(req,res)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  if(req.method!=='GET'){res.writeHead(405,{Allow:'GET'});return res.end();}
  const path=new URL(req.url,'http://localhost').pathname;
  if(path==='/api/intelligence'){
    res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');
    try{return res.end(JSON.stringify(await getIntelligence()));}catch{res.statusCode=503;return res.end(JSON.stringify({error:'Live intelligence unavailable'}));}
  }
  if(!Object.hasOwn(files,path)){res.statusCode=404;return res.end('Not found');}
  try{const file=files[path];res.setHeader('Content-Type',types[file.split('.').pop()]);res.end(await readFile(new URL('./public/'+file,import.meta.url)));}catch{res.statusCode=500;res.end('Unavailable');}
}).listen(Number(process.env.PORT||3000),()=>console.log('ThreatBrief listening'));
