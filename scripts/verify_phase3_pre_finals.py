#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'backend'))
from app.security.signing import verify_payload
P=ROOT/'competition/phase3/PRE_GRAND_FINALE_FREEZE_MANIFEST.json'
def sha(p:Path)->str:
 h=hashlib.sha256();
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
 return h.hexdigest()
def main()->int:
 if not P.is_file(): print('Pre-Grand-Finale freeze manifest not found'); return 1
 s=json.loads(P.read_text()); p=s.get('payload',{}); signer=p.get('signer',{})
 if p.get('schema')!='veilgraph.pre-grand-finale-freeze.v1' or p.get('status')!='PRE_GRAND_FINALE_COMPLETE_AND_FROZEN': print('Invalid Phase-3 status/schema'); return 1
 if not verify_payload(p,s.get('signature_b64',''),signer.get('public_key_b64','')): print('Ed25519 signature INVALID'); return 1
 bad=[]
 for group in ('phase3_surface_sha256','phase3_evidence_sha256'):
  for rel,expected in p.get(group,{}).items():
   f=ROOT/rel
   if not f.is_file() or sha(f)!=expected: bad.append(rel)
 if bad: print('Pre-Grand-Finale freeze INVALID:',bad); return 1
 print(f"Pre-Grand-Finale freeze VALID: {len(p.get('phase3_surface_sha256',{}))} surface files + {len(p.get('phase3_evidence_sha256',{}))} evidence files byte-identical")
 print('Ed25519 signature VALID; Stage-2 private NTRO dataset is the only recorded external pending item.'); return 0
if __name__=='__main__': raise SystemExit(main())
