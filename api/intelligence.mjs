import {getIntelligence} from '../lib/intelligence.mjs';
export default async function handler(req,res) {
  res.setHeader('Cache-Control','no-store');
  if(req.method!=='GET'){res.setHeader('Allow','GET');return res.status(405).json({error:'Method not allowed'});}
  try{return res.status(200).json(await getIntelligence());}
  catch{return res.status(503).json({error:'Live intelligence unavailable. Try again later or use synthetic demo data.'});}
}
