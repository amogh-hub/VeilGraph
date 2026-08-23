#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/backend"
source .venv/bin/activate
PYTHONPATH=. pytest -q tests/test_semantic_ner_v1.py
PYTHONPATH=. python - <<'PY'
from pathlib import Path
from app.benchmark.veilbench import benchmark_curated
result = benchmark_curated(Path('benchmark_corpus/veilbench_curated_v1.json'))
print('Frozen VeilBench v1:')
print(f"  cases={result['case_count']} exact={result['exact_case_passes']}")
print(f"  precision={result['overall']['precision']:.6f}")
print(f"  recall={result['overall']['recall']:.6f}")
print(f"  f1={result['overall']['f1']:.6f}")
print(f"  fp={result['overall']['fp']} fn={result['overall']['fn']}")
PY
