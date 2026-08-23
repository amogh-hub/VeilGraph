#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; BACKEND=ROOT/'backend'; sys.path.insert(0,str(BACKEND))
from app.security.signing import public_key_b64, sign_payload, signer_fingerprint, verify_payload
P1=ROOT/'competition/phase1'; P3=ROOT/'competition/phase3'
EXPECTED_P1='2e4c1e5a863f648013a96e8c8f3b61c9c9e8688065c223bb3dc0d09f67539bf3'
EXPECTED_P2='8d106cc14331f11d20da54b1aa6c11bf8c00cd476c9c5177bfb983fdd9a6eac7'

def sha(p:Path)->str:
 h=hashlib.sha256();
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
 return h.hexdigest()
def req(rel:str)->Path:
 p=ROOT/rel
 if not p.is_file(): raise SystemExit(f'Missing required Phase-3 artifact: {rel}')
 return p
def load(rel:str)->dict:
 v=json.loads(req(rel).read_text(encoding='utf-8'))
 if not isinstance(v,dict): raise SystemExit(f'Expected object: {rel}')
 return v

def main()->int:
 subprocess.run([sys.executable,str(ROOT/'scripts/verify_broad_pii_v5_freeze.py')],cwd=ROOT,check=True)
 if sha(req('competition/phase1/PHASE_1_FREEZE_MANIFEST.json'))!=EXPECTED_P1: raise SystemExit('Phase-1 authoritative manifest hash changed')
 parent=load('competition/phase3/PHASE2_PARENT_ACCEPTANCE.json')
 if parent.get('phase2_freeze_manifest_sha256')!=EXPECTED_P2 or not parent.get('verified_before_phase3_apply'): raise SystemExit('Phase-2 authoritative parent was not verified before Phase-3 changes')
 if sha(req('competition/phase2/PHASE_2_FREEZE_MANIFEST.json'))!=EXPECTED_P2: raise SystemExit('Active Phase-2 authoritative manifest hash changed')
 subprocess.run([sys.executable,str(ROOT/'scripts/verify_phase2_freeze.py')],cwd=ROOT,check=True)
 grad=load('competition/phase3/GRADATION_CALIBRATION_RESULTS.json'); learn=load('competition/phase3/MODEL_LEARNING_EVIDENCE.json'); online=load('competition/phase3/SECURE_ONLINE_ACCEPTANCE.json'); cots=load('competition/phase3/COTS_QUANTITATIVE_RESULTS.json'); reg=load('competition/phase3/PHASE3_FULL_REGRESSION.json')
 if not grad.get('all_passed'): raise SystemExit('Gradation calibration is not green')
 if not all(learn.get('checks',{}).values()): raise SystemExit('Controlled-learning evidence is not green')
 if not online.get('all_passed'): raise SystemExit('Secure-online TLS acceptance is not green')
 if not cots.get('literal_ntro_cots_requirement_closed'): raise SystemExit('Literal NTRO COTS benchmark remains open: execute at least one commercial COTS system under the frozen protocol')
 if not reg.get('all_passed'): raise SystemExit('Full Mac regression/TypeScript/Vite closure is not green')
 surface=[
 'backend/app/api/routes.py','backend/app/transformation/synthetic_export.py','backend/app/verification/red_team.py',
 'frontend/src/api/client.ts','frontend/src/App.tsx','frontend/src/styles.css','frontend/src/api/schema.d.ts',
 'scripts/run_gradation_calibration.py','scripts/run_model_learning_evidence.py','scripts/run_secure_online_acceptance.py',
 'scripts/run_cots_benchmark.py','scripts/setup_cots_benchmark.sh','scripts/record_phase3_regression.py',
 'scripts/run_phase3_pre_finals.sh','scripts/finalize_phase3_pre_finals.py','scripts/verify_phase3_pre_finals.py',
 'deployment/online/README.md'
 ]
 docs=['competition/phase3/CONTROLLED_MODEL_LEARNING_LIFECYCLE.md','competition/phase3/COTS_QUANTITATIVE_PROTOCOL.md','competition/phase3/SIH260381_FINAL_TRACEABILITY.md']
 evidence=['competition/phase3/GRADATION_CALIBRATION_RESULTS.json','competition/phase3/GRADATION_CALIBRATION_REPORT.md','competition/phase3/MODEL_LEARNING_EVIDENCE.json','competition/phase3/SECURE_ONLINE_ACCEPTANCE.json','competition/phase3/COTS_QUANTITATIVE_RESULTS.json','competition/phase3/COTS_QUANTITATIVE_REPORT.md','competition/phase3/PHASE3_FULL_REGRESSION.json','competition/phase3/PHASE3_FULL_REGRESSION.log','competition/phase3/PHASE2_PARENT_ACCEPTANCE.json']
 surf={r:sha(req(r)) for r in surface}; ev={r:sha(req(r)) for r in docs+evidence}
 payload={'schema':'veilgraph.pre-grand-finale-freeze.v1','status':'PRE_GRAND_FINALE_COMPLETE_AND_FROZEN','closed_at_utc':datetime.now(timezone.utc).isoformat(),'sih_problem_id':'SIH260381','problem_owner':'NTRO','phase1_freeze_manifest_sha256':EXPECTED_P1,'phase2_parent_freeze_manifest_sha256':EXPECTED_P2,'phase3_surface_sha256':surf,'phase3_evidence_sha256':ev,'closure':{'l5_verified_synthetic_exports':['csv','json','xlsx','docx','pdf'],'gradation_calibration':True,'controlled_model_learning':True,'secure_online_tls_acceptance':True,'commercial_cots_quantitative_benchmark':True,'full_regression':reg},'only_external_pending_item':{'requirement':'NTRO Stage-2 private Grand Finale dataset evaluation','status':'PENDING_EXTERNAL_DATA','reason':'Dataset is supplied by NTRO only at Grand Finale; no pre-finale implementation can execute it.'},'signer':{'algorithm':'Ed25519','public_key_b64':public_key_b64(),'public_key_sha256':signer_fingerprint()}}
 signed={'payload':payload,'signature_algorithm':'Ed25519','signature_b64':sign_payload(payload)}
 if not verify_payload(payload,signed['signature_b64'],payload['signer']['public_key_b64']): raise SystemExit('Signature self-check failed')
 out=P3/'PRE_GRAND_FINALE_FREEZE_MANIFEST.json'; out.write_text(json.dumps(signed,indent=2,sort_keys=True)+'\n',encoding='utf-8')
 (P3/'PRE_GRAND_FINALE_COMPLETE.md').write_text('# VeilGraph — Pre-Grand-Finale Completion\n\n**Every implementable SIH260381 requirement is closed and frozen.**\n\nThe only pending item is execution on the NTRO Stage-2 private dataset, which is external and Grand-Finale-only.\n',encoding='utf-8')
 print(f'Wrote {out.relative_to(ROOT)}'); print(f'Freeze manifest SHA-256: {sha(out)}'); print('PRE-GRAND-FINALE ACCEPTANCE: PASS — COMPLETE & FROZEN'); return 0
if __name__=='__main__': raise SystemExit(main())
