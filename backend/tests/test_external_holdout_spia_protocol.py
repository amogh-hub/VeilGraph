from __future__ import annotations
import importlib.util
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('spia_eval', ROOT/'scripts/run_external_holdout_spia.py')
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

def test_spia_protocol_maps_only_explicit_overlap_taxonomy():
    assert mod.TAG_TO_VEILGRAPH['NAME']==('PERSON_NAME',)
    assert 'RELATIONSHIP' not in mod.TAG_TO_VEILGRAPH
    assert mod.EXPECTED_DOCUMENTS==151

def test_spia_protocol_excludes_inference_only_keyword():
    row={'text':'Alex joined the meeting.', 'subjects':[{'PIIs':[{'tag':'NAME','keyword':'Alex'},{'tag':'AGE','keyword':'31'}]}]}
    gold, excluded, inference=mod._record_gold(row)
    assert ('NAME','alex') in gold
    assert inference['AGE']==1
    assert not excluded

def test_spia_protocol_scores_supported_surface_entities_without_network():
    rows=[{'text':'Name: Aarav Menon\nEmail: aarav.menon@example.org\nAge: 29', 'subjects':[{'PIIs':[{'tag':'NAME','keyword':'Aarav Menon'},{'tag':'EMAIL_ADDRESS','keyword':'aarav.menon@example.org'},{'tag':'AGE','keyword':'29'}]}]}]
    result=mod.evaluate_records(rows)
    assert result['surface_visible_gold']==3
    assert result['tp']==3
    assert result['fn']==0
    assert result['recall']==1.0

def test_spia_holdout_url_is_external_and_raw_data_is_not_repo_payload():
    assert mod.SOURCE_REPO=='spia-bench/SPIA-benchmark'
    assert mod.SOURCE_FILE.endswith('.jsonl')
    assert not (ROOT/'competition/phase1'/mod.SOURCE_FILE).exists()
