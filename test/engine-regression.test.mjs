import test from 'node:test';
import assert from 'node:assert/strict';
import {parseInventory,rank,briefing} from '../public/engine.js';
const now=Date.parse('2026-11-26');
const r={id:'CVE-2026-1234',vendor:'Microsoft',product:'Exchange',title:'Example',added:'2026-11-25',ransomware:false};
test('does not combine separate assets into inflated score',()=>assert.equal(rank([r],parseInventory('Exchange | internet\nMicrosoft Exchange | critical'),0,now)[0].score,75));
test('generic fragments do not match',()=>assert.equal(rank([{...r,product:'Exchange Server'}],parseInventory('Server'),0,now).length,0));
test('untrusted Markdown is escaped',()=>assert.ok(briefing({name:'[click](https://evil.example)',industry:'Insurance'},{source:'test'},[],0).includes('\\[click\\]\\(https://evil.example\\)')));
