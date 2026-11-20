"""Cross-builds prove compilation only, never Linux runtime acceptance."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

root = Path(__file__).resolve().parents[1]
out = root / "build"
out.mkdir(exist_ok=True)
rows = []
for arch in ("amd64", "arm64"):
    binary = out / ("hostsec-linux-" + arch)
    env = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0")
    subprocess.run(["go", "build", "-trimpath", "-o", str(binary), "./cmd/hostsec"], cwd=root / "backend", env=env, check=True)
    data = binary.read_bytes()
    assert data[:4] == b"\x7fELF", "not an ELF artifact"
    expected_machine = {"amd64": 62, "arm64": 183}[arch]
    assert int.from_bytes(data[18:20], "little") == expected_machine, "wrong ELF architecture"
    rows.append({"goos": "linux", "goarch": arch, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "path": str(binary.relative_to(root)), "validation": "CROSS_BUILD_ONLY"})
(out / "build-manifest.json").write_text(json.dumps(rows, indent=2) + "\n")
print(json.dumps(rows, indent=2))
