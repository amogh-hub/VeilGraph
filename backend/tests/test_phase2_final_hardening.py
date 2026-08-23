from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _load_regression_module():
    path = ROOT / "scripts/record_phase2_regression.py"
    spec = importlib.util.spec_from_file_location("phase2_regression_recorder", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _good_log() -> str:
    return """
249 passed, 5 warnings in 60.00s
Wrote backend/openapi.json
> veilgraph-slice-e-frontend@0.5.0 typecheck
> tsc -b --pretty false
> veilgraph-slice-e-frontend@0.5.0 build
vite v5.4.10 building for production...
✓ built in 220ms
VEILGRAPH_RUN_CHECKS_EXIT=0
"""


def test_regression_closure_requires_observed_success_marker_and_frontend_gates():
    module = _load_regression_module()
    payload = module.parse_regression_log(_good_log())
    assert payload["all_passed"] is True
    assert payload["pytest_passed"] == 249
    assert payload["pytest_failed"] == 0
    assert payload["run_checks_exit_zero"] is True
    assert payload["openapi_written"] is True
    assert payload["typescript_typecheck"] is True
    assert payload["vite_production_build"] is True


def test_regression_closure_fails_without_shell_success_marker():
    module = _load_regression_module()
    payload = module.parse_regression_log(_good_log().replace("VEILGRAPH_RUN_CHECKS_EXIT=0\n", ""))
    assert payload["all_passed"] is False


def test_regression_closure_fails_when_pytest_failure_is_present():
    module = _load_regression_module()
    text = _good_log().replace("249 passed, 5 warnings", "1 failed, 248 passed, 5 warnings")
    payload = module.parse_regression_log(text)
    assert payload["pytest_failed"] == 1
    assert payload["all_passed"] is False
