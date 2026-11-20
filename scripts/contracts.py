"""Shape tests for the future scan result contract, not fabricated scan evidence."""
from pathlib import Path
from copy import deepcopy
import json
from jsonschema import Draft202012Validator, FormatChecker

root = Path(__file__).resolve().parents[1]
for path in (root / 'schemas').glob('*.schema.json'):
    Draft202012Validator.check_schema(json.loads(path.read_text()))
schema = json.loads((root / 'schemas/scan-result-v1.schema.json').read_text())
validator = Draft202012Validator(schema, format_checker=FormatChecker())
# This is a hand-authored synthetic contract example. No collection happened.
evidence = dict(evidence_id='ev-demo', host_id='host-demo', scan_id='scan-demo',
    attempt_id='attempt-demo', collected_at='2026-11-20T00:00:00Z', received_at='2026-11-20T00:00:01Z',
    module='process_inventory', collector_version='fixture-only', category='process',
    raw_summary='synthetic shape fixture', raw_ref=None, normalized_data={},
    sha256=None, normalized_sha256=None, collection_status='failed',
    integrity_status='unavailable', completeness='unavailable', warnings=['not collected'])
result = dict(schema_version='1.0', scan_id='scan-demo', host_id='host-demo',profile='quick',
    status='PARTIAL', started_at='2026-11-20T00:00:00Z', completed_at='2026-11-20T00:00:01Z',
    collector_version='fixture-only', policy_version='fixture-only',rule_bundle_version='fixture-only',
    collection_summary=dict(total_modules=1,succeeded=0,failed=1,skipped=0,coverage=0),
    evidence=[evidence],rule_results=[dict(rule_id='PROC-001',rule_version='1',scan_id='scan-demo',
    host_id='host-demo',outcome='UNKNOWN',evidence_refs=[],missing_evidence=['process'],reason_code='NOT_COLLECTED',baseline_ref=None)],
    findings=[],ai_status='disabled',ai_assessment=None,limitations=['synthetic contract fixture'],
    human_review=dict(status='pending',notes=[]))
validator.validate(result)
cases=[]
a=deepcopy(result);a['rule_results'][0]['outcome']='PASS';cases.append(('missing evidence cannot PASS',a))
a=deepcopy(result);a['evidence'][0]['integrity_status']='verified';cases.append(('null hash cannot be verified',a))
a=deepcopy(result);a['evidence'][0]['collection_status']='success';cases.append(('failed payload cannot success',a))
a=deepcopy(result);a['ai_status']='success';cases.append(('AI success requires assessment',a))
a=deepcopy(result);a['unexpected']=True;cases.append(('unknown field',a))
for name,value in cases:
    assert list(validator.iter_errors(value)), name
finding_schema={'$schema':schema['$schema'],**schema['$defs']['finding']}
finding_validator=Draft202012Validator(finding_schema)
finding=dict(finding_id='finding-demo',scan_id='scan-demo',host_id='host-demo',rule_id='PROC-001',rule_version='1',category='process',severity='high',confidence=70,title='synthetic',description='shape fixture',evidence_refs=['ev-demo'],remediation_guidance=[],requires_human_review=True,review_status='new')
finding_validator.validate(finding)
finding['evidence_refs']=[]
assert list(finding_validator.iter_errors(finding)), 'Finding must contain evidence IDs'
print('PASS: schema shape positives and 6 negatives; provenance/reference membership/runtime still PLANNED')
