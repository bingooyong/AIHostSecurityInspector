"""Cross-builds prove compilation only, never Linux runtime acceptance."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
version = os.environ.get("VERSION", "0.1.0-dev")
if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[A-Za-z0-9.-]+)?", version):
    raise SystemExit("invalid VERSION")
pkg = "github.com/bingooyong/AIHostSecurityInspector/backend/internal/cli"
ldflags = f"-buildid= -X {pkg}.Version={version}"
out = root / "build"
out.mkdir(exist_ok=True)
rows = []
for arch in ("amd64", "arm64"):
    binary = out / ("hostsec-linux-" + arch)
    env = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0")
    subprocess.run(["go", "build", "-trimpath", "-ldflags", ldflags, "-o", str(binary), "./cmd/hostsec"], cwd=root / "backend", env=env, check=True)
    data = binary.read_bytes()
    assert data[:4] == b"\x7fELF", "not an ELF artifact"
    expected_machine = {"amd64": 62, "arm64": 183}[arch]
    assert int.from_bytes(data[18:20], "little") == expected_machine, "wrong ELF architecture"
    rows.append({"goos": "linux", "goarch": arch, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "path": str(binary.relative_to(root)), "validation": "CROSS_BUILD_ONLY", "version": version})

repro_env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0")
hashes = []
with tempfile.TemporaryDirectory(prefix="hostsec-repro-") as first, tempfile.TemporaryDirectory(prefix="hostsec-repro-") as second:
    for directory in (first, second):
        target = Path(directory) / "hostsec"
        subprocess.run(["go", "build", "-trimpath", "-ldflags", ldflags, "-o", str(target), "./cmd/hostsec"], cwd=root / "backend", env=repro_env, check=True)
        hashes.append(hashlib.sha256(target.read_bytes()).hexdigest())
assert hashes[0] == hashes[1], "reproducible build hash mismatch"

dirty = subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, check=True)
toolchain = subprocess.run(["go", "env", "GOVERSION"], cwd=root / "backend", capture_output=True, text=True, check=True)
manifest = {
    "version": version,
    "go_version": toolchain.stdout.strip(),
    "ldflags": ldflags,
    "cgo": False,
    "workspace_dirty": bool(dirty.stdout.strip()),
    "reproducible_linux_amd64_sha256": hashes[0],
    "artifacts": rows,
    "validation": "CROSS_BUILD_ONLY",
}
(out / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest, indent=2))
