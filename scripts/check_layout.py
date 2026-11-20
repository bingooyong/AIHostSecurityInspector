"""Guard the backend module boundary and preserve the approved CLI behavior."""
from pathlib import Path
import argparse
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
MODULE = "github.com/bingooyong/AIHostSecurityInspector/backend"
BASELINE = ROOT / "docs/05-testing/evidence/layout-migration/before-cli.json"


def check_structure():
    for name in ("go.mod", "go.sum", "go.work", "go.work.sum", ".golangci.yml", "cmd", "internal", "pkg"):
        assert not (ROOT / name).exists(), f"Go project path belongs under backend/: {name}"
    for name in ("go.mod", "go.sum", ".golangci.yml", "cmd/hostsec/main.go", "tools/check-boundaries/main.go"):
        assert (BACKEND / name).is_file(), f"missing backend file: {name}"
    module_text = (BACKEND / "go.mod").read_text()
    assert re.search(r"^module\s+" + re.escape(MODULE) + r"\s*$", module_text, re.MULTILINE), "wrong nested module path"
    assert not re.search(r"^replace\s", module_text, re.MULTILINE), "unexpected replace directive"
    sources = []
    for path in ROOT.rglob("*.go"):
        relative = path.relative_to(ROOT)
        if any(part in {".git", "build", ".venv", "node_modules"} for part in relative.parts):
            continue
        assert relative.parts[0] == "backend", f"Go source outside backend/: {relative}"
        sources.append(path)
        assert '"github.com/bingooyong/AIHostSecurityInspector/internal/' not in path.read_text(), f"stale import: {relative}"
    assert sources, "backend contains no Go sources"
    result = subprocess.run(["go", "list", "-m"], cwd=BACKEND, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0 and result.stdout.strip() == MODULE, "backend module does not resolve independently"
    print(f"PASS: {len(sources)} Go source files isolated in backend; root has no Go module/workspace")


def check_behavior():
    rows = json.loads(BASELINE.read_text())
    assert len(rows) == 11, "unexpected frozen CLI behavior case count"
    binary = ROOT / "build/hostsec"
    assert binary.is_file(), "build the current CLI before behavior comparison"
    environment_result = subprocess.run(["go", "env", "-json", "GOOS", "GOARCH", "GOVERSION"], cwd=BACKEND, capture_output=True, text=True, timeout=30)
    assert environment_result.returncode == 0, "cannot resolve current Go platform"
    environment = json.loads(environment_result.stdout)
    environment_adjusted = False
    for index, row in enumerate(rows, 1):
        result = subprocess.run([str(binary), *row["args"]], cwd=ROOT, capture_output=True, text=True, timeout=10)
        actual = {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        expected = {key: row[key] for key in actual}
        # The committed migration fixture was captured on the original workstation.
        # On CI, adapt only values defined by the Go platform/toolchain; all other
        # command output and every exit/stderr must remain identical.
        if row["args"] == ["version", "--json"]:
            payload = json.loads(expected["stdout"])
            if payload["go_version"] != environment["GOVERSION"]:
                payload["go_version"] = environment["GOVERSION"]
                expected["stdout"] = json.dumps(payload, indent=2) + "\n"
                environment_adjusted = True
        elif row["args"] == ["doctor", "--json"]:
            payload = json.loads(expected["stdout"])
            platform_values = {"os": environment["GOOS"], "architecture": environment["GOARCH"], "linux_platform_supported": environment["GOOS"] == "linux" and environment["GOARCH"] in ("amd64", "arm64")}
            if any(payload[key] != value for key, value in platform_values.items()):
                payload.update(platform_values)
                expected["stdout"] = json.dumps(payload, indent=2) + "\n"
                environment_adjusted = True
        assert actual == expected, f"CLI behavior changed in frozen case {index}: {row['args']}"
    if environment_adjusted:
        print("PASS: 11 frozen CLI cases match with only documented OS/arch/Go-version fields adapted to this environment")
    else:
        print("PASS: 11 frozen CLI stdout/stderr/exit results match before migration byte for byte")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--structure-only", action="store_true")
    args = parser.parse_args()
    check_structure()
    if not args.structure_only:
        check_behavior()
