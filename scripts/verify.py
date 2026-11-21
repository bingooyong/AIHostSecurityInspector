"""Run monorepo gates and persist exact results without rewriting old evidence."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
import subprocess
import time

root = Path(__file__).resolve().parents[1]
backend = root / "backend"
requested = Path(os.environ.get("HOSTSEC_EVIDENCE_DIR", "docs/05-testing/evidence/ci-local"))
out = requested if requested.is_absolute() else root / requested
if out.resolve() == (root / "docs/05-testing/evidence/layout-migration").resolve():
    raise SystemExit("refusing to overwrite layout-migration historical evidence; set HOSTSEC_EVIDENCE_DIR")
out.mkdir(parents=True, exist_ok=True)
(root / "build").mkdir(exist_ok=True)
commands = [
    ("layout-structure", ["python3", "scripts/check_layout.py", "--structure-only"], root),
    ("format", ["gofmt", "-l", "cmd", "internal", "tools"], backend),
    ("module-verify", ["go", "mod", "verify"], backend),
    ("vet", ["go", "vet", "./..."], backend),
    ("unit-race", ["go", "test", "-race", "-count=1", "./..."], backend),
    ("lint", ["golangci-lint", "run", "./..."], backend),
    ("boundaries", ["go", "run", "./tools/check-boundaries"], backend),
    ("build-local", ["go", "build", "-trimpath", "-o", str(root / "build/hostsec"), "./cmd/hostsec"], backend),
    ("layout-behavior", ["python3", "scripts/check_layout.py"], root),
    ("integration-schema", ["python3", "scripts/integration.py"], root),
    ("frontend-install", ["npm", "ci"], root / "frontend"),
    ("frontend-lint", ["npm", "run", "lint"], root / "frontend"),
    ("frontend-typecheck", ["npm", "run", "typecheck"], root / "frontend"),
    ("frontend-test", ["npm", "run", "test"], root / "frontend"),
    ("frontend-build", ["npm", "run", "build"], root / "frontend"),
    ("future-contract", ["python3", "scripts/contracts.py"], root),
    ("baseline", ["python3", "scripts/validate_baseline.py"], root),
    ("vulnerability", ["govulncheck", "-show", "verbose", "./..."], backend),
    ("sbom", ["cyclonedx-gomod", "mod", "-json", "-output", str(root / "build/sbom.cdx.json")], backend),
    ("cross-build", ["python3", "scripts/build_release.py"], root),
    ("whitespace", ["git", "diff", "--check"], root),
]
tool_env = dict(os.environ)
tool_env["PATH"] = str(root / "build/tools") + os.pathsep + tool_env.get("PATH", "")
results = []
for name, command, cwd in commands:
    started = datetime.now(timezone.utc).isoformat()
    clock = time.monotonic()
    relative_cwd = str(cwd.relative_to(root))
    try:
        process = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=240, env=tool_env)
        stdout, stderr, code = process.stdout, process.stderr, process.returncode
    except (OSError, subprocess.TimeoutExpired) as error:
        stdout, stderr, code = "", str(error), 124
    ok = code == 0 and (name != "format" or not stdout.strip())
    log = out / (name + ".log")
    log.write_text("cwd=" + relative_cwd + "\n$ " + " ".join(command) + "\nexit=" + str(code) + "\nstdout:\n" + stdout + "\nstderr:\n" + stderr)
    results.append({"gate": name, "command": command, "cwd": relative_cwd, "started_at": started, "elapsed_seconds": round(time.monotonic() - clock, 3), "exit_code": code, "status": "PASS" if ok else "FAIL", "log": str(log.relative_to(root))})
    print(name, results[-1]["status"], flush=True)
    if not ok:
        print((stdout + stderr)[-4000:], flush=True)
        break
passed = len(results) == len(commands) and all(row["status"] == "PASS" for row in results)
if passed:
    for filename in ("sbom.cdx.json", "build-manifest.json"):
        source = root / "build" / filename
        (out / filename).write_bytes(source.read_bytes())
    sbom = json.loads((out / "sbom.cdx.json").read_text())
    assert sbom.get("bomFormat") == "CycloneDX" and sbom.get("components"), "missing SBOM components"
    source_files = sorted(
        list(backend.rglob("*.go"))
        + list((root / "scripts").rglob("*.py"))
        + list((root / "schemas").glob("*.json"))
        + [backend / "go.mod", backend / "go.sum", backend / ".golangci.yml", root / "Makefile", root / ".github/workflows/ci.yml"]
    )
    hashes = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_files}
    (out / "verified-files.json").write_text(json.dumps(hashes, indent=2) + "\n")
summary = {"executed_at": datetime.now(timezone.utc).isoformat(), "scope": "current local quality gates; does not overwrite layout-migration historical evidence; no Linux collector runtime or remote CI acceptance", "status": "PASS" if passed else "FAIL", "evidence_dir": str(out.relative_to(root)), "results": results}
(out / "results.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
raise SystemExit(0 if passed else 1)
