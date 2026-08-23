#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$ROOT/.cots-benchmark-venv"
MODEL_URL="https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl"

# Prefer Python 3.13 when already available because current Presidio documentation
# lists 3.10-3.13 as its supported range. Do not mutate the host merely to install it.
if command -v python3.13 >/dev/null 2>&1; then
  BASE_PY="$(command -v python3.13)"
else
  BASE_PY="$(command -v python3)"
fi

# Recreate the benchmark-only venv if it exists but was built with another Python
# minor than the selected interpreter. This never changes VeilGraph's production venv.
SELECTED_MM="$($BASE_PY -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ -x "$VENV/bin/python" ]]; then
  EXISTING_MM="$($VENV/bin/python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)"
  if [[ "$EXISTING_MM" != "$SELECTED_MM" ]]; then
    echo "Recreating benchmark-only venv: Python $EXISTING_MM -> $SELECTED_MM"
    rm -rf "$VENV"
  fi
fi

"$BASE_PY" -m venv "$VENV"
"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install -r "$ROOT/backend/requirements.txt"

# spaCy 3.8.13 is the current 3.8 release available for CPython 3.14 on PyPI.
# Avoid `python -m spacy download` entirely; install the compatible official model
# wheel directly, as recommended by spaCy for reproducible/automated installs.
"$VENV/bin/python" -m pip install \
  'presidio-analyzer==2.2.364' \
  'spacy==3.8.13' \
  'boto3>=1.35,<2' \
  'azure-ai-textanalytics>=5.3,<6'
"$VENV/bin/python" -m pip install "$MODEL_URL"

"$VENV/bin/python" - <<'PY'
import sys
import spacy
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

assert spacy.__version__ == "3.8.13", spacy.__version__
nlp = spacy.load("en_core_web_sm")
doc = nlp("Alice works in Bengaluru.")
assert doc is not None

configuration = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
}
provider = NlpEngineProvider(nlp_configuration=configuration)
nlp_engine = provider.create_engine()
engine = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
results = engine.analyze(text="Email alice@example.com", language="en")
assert isinstance(results, list)
assert any(r.start < r.end for r in results), results
print("Python:", sys.version.split()[0])
print("spaCy:", spacy.__version__)
print("en_core_web_sm: 3.8.0 LOAD PASS")
print("Presidio AnalyzerEngine (explicit en_core_web_sm): SMOKE PASS")
PY

cat <<EOF2
COTS benchmark environment ready at:
  $VENV

This environment is benchmark-only.
VeilGraph runtime dependencies remain unchanged.
EOF2
