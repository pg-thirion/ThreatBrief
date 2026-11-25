import {getIntelligence} from '../lib/intelligence.mjs';
import {securityHeaders} from '../lib/security.mjs';
export default async function handler(req,res) {
  for(const [k,v] of Object.entries(securityHeaders))res.setHeader(k,v);
  res.setHeader('Cache-Control','no-store');
  if(req.method!=='GET'){res.setHeader('Allow','GET');return res.status(405).json({error:'Method not allowed'});}
  try{return res.status(200).json(await getIntelligence());}
  catch{res.setHeader('Retry-After','60');return res.status(503).json({error:'Live intelligence unavailable. Try again later or use synthetic demo data.'});}
}
