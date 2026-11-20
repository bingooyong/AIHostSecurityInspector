"""Execute the built CLI, validate actual JSON and reject unsafe requests."""
from pathlib import Path
from copy import deepcopy
import json
import subprocess
import tempfile
from jsonschema import Draft202012Validator, FormatChecker

root = Path(__file__).resolve().parents[1]
binary = root / 'build/hostsec'
count=0

def run(args, code=0):
    global count
    p=subprocess.run([str(binary),*args],cwd=root,capture_output=True,text=True,timeout=10)
    assert p.returncode==code,(args,p.returncode,p.stdout,p.stderr)
    if code==2:
        assert not p.stdout,(args,'rejection returned result')
        error=json.loads(p.stderr)
        assert error['level']=='error'
        assert 'CANARY_SECRET' not in p.stderr
    elif code==0:
        assert not p.stderr,(args,p.stderr)
    count+=1
    return p

def validate(name,value):
    schema=json.loads((root/'schemas'/name).read_text())
    Draft202012Validator(schema,format_checker=FormatChecker()).validate(value)

run(['--help'])
version=json.loads(run(['version','--json']).stdout)
assert version['version']
run(['assets','validate','--file','examples/hosts.yaml','--json'])
assets=json.loads(run(['assets','list','--file','examples/hosts.yaml','--json']).stdout)
validate('assets-v1.schema.json',assets)
assert len(assets['hosts'])==1 and all(h['authorized'] for h in assets['hosts'])
for profile in ('quick','standard','deep','incident-response'):
    plan=json.loads(run(['plan','--file','examples/hosts.yaml','--targets','group:pilot','--profile',profile,'--dry-run','--json']).stdout)
    validate('plan-v1.schema.json',plan)
    assert plan['dry_run'] and plan['mode']=='READ_ONLY'
    assert not plan['execution_ready'] and not plan['limits']['enforced']
    assert plan['approval_required']==(profile in ('deep','incident-response'))
    assert plan['hosts'][0]['host_id']=='linux-test-001'
    ip_plan=deepcopy(plan);ip_plan['hosts'][0]['host_id']='192.0.2.10'
    try: validate('plan-v1.schema.json',ip_plan)
    except Exception: pass
    else: raise AssertionError('plan schema accepts IP identity')
    changed=deepcopy(plan);changed['execution_ready']=True
    try: validate('plan-v1.schema.json',changed)
    except Exception: pass
    else: raise AssertionError('schema accepts execution-ready offline plan')
doctor=json.loads(run(['doctor','--json'],1).stdout)
validate('doctor-v1.schema.json',doctor)
assert not doctor['collector_available'] and not doctor['scan_ready']
for args in (
    ['scan','--host','linux-test-001'],['mcp','serve'],['version','--exec','CANARY_SECRET'],
    ['plan','--file','examples/hosts.yaml','--targets','group:mixed','--dry-run','--json'],
    ['plan','--file','examples/hosts.yaml','--host','linux-denied-001','--dry-run'],
    ['plan','--file','examples/hosts.yaml','--host','unknown','--dry-run'],
    ['plan','--file','examples/hosts.yaml','--targets','192.0.2.0/24','--dry-run'],
    ['plan','--file','examples/hosts.yaml','--host','linux-test-001;touch CANARY_SECRET','--dry-run'],
    ['plan','--file','examples/hosts.yaml','--host','linux-test-001','--profile','root','--dry-run'],
    ['plan','--file','examples/hosts.yaml','--host','linux-test-001'],
    ['plan','--file','examples/hosts.yaml','--host','linux-test-001','--targets','group:pilot','--dry-run'],
    ['plan','--file','examples/hosts.yaml','--host','linux-test-001','--dry-run','--approval-id','CANARY_SECRET'],
):run(args,2)
with tempfile.TemporaryDirectory(prefix='hostsec-contract-') as directory:
    path=Path(directory)/'hosts.json'
    path.write_text(json.dumps(assets))
    run(['assets','validate','--file',str(path),'--json'])
    for name,mutate in (
        ('missing authorization',lambda v:v['hosts'][0].pop('authorized')),
        ('host key bypass',lambda v:v['hosts'][0]['connection'].update(host_key_policy='insecure')),
        ('raw secret',lambda v:v['hosts'][0]['connection'].update(password='CANARY_SECRET')),
        ('unauthorized profile',lambda v:v['hosts'][0].update(allowed_profiles=['quick'])),
    ):
        value=deepcopy(assets);mutate(value);path.write_text(json.dumps(value))
        if name=='unauthorized profile':
            run(['plan','--file',str(path),'--host','linux-test-001','--profile','deep','--dry-run'],2)
        else:
            try:validate('assets-v1.schema.json',value)
            except Exception:pass
            else:raise AssertionError('schema accepts '+name)
            run(['assets','validate','--file',str(path),'--json'],2)
    # Duplicate JSON keys must not silently override authorization.
    path.write_text(json.dumps(assets).replace('"authorized": true','"authorized": true, "authorized": false',1))
    run(['assets','validate','--file',str(path),'--json'],2)
print(f'PASS: {count} real CLI processes; asset/plan/doctor schemas; authorization, profile, injection, and JSON rejection')
