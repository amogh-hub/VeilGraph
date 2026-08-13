#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, re, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'competition/phase3/PHASE3_FULL_REGRESSION.json'

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument('log', type=Path); p.add_argument('--exit-code',type=int,required=True); a=p.parse_args()
    text=a.log.read_text(encoding='utf-8', errors='replace') if a.log.is_file() else ''
    m=re.search(r'(?m)(\d+) passed(?:, (\d+) failed)?(?:, (\d+) warnings?)?', text)
    passed=int(m.group(1)) if m else 0; failed=int(m.group(2) or 0) if m else -1; warnings=int(m.group(3) or 0) if m else 0
    openapi=('Wrote backend/openapi.json' in text) or ('Wrote ' in text and 'openapi.json' in text)
    ts=('typecheck' in text and ('tsc -b --pretty false' in text or '> tsc -b' in text))
    vite=('built in ' in text and 'vite v' in text)
    all_passed=(a.exit_code==0 and m is not None and failed==0 and passed>0 and openapi and ts and vite)
    payload={'schema':'veilgraph.phase3-full-regression.v1','generated_at_unix':int(time.time()),'run_checks_exit_code':a.exit_code,'pytest_passed':passed,'pytest_failed':failed,'warnings':warnings,'openapi_written':openapi,'typescript_typecheck':ts,'vite_production_build':vite,'all_passed':all_passed}
    OUT.parent.mkdir(parents=True,exist_ok=True); OUT.write_text(json.dumps(payload,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(payload,indent=2,sort_keys=True)); return 0 if all_passed else 1
if __name__=='__main__': raise SystemExit(main())
