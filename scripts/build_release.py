"""Cross-builds prove compilation only, never Linux runtime acceptance."""
from pathlib import Path
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PKG = "github.com/bingooyong/AIHostSecurityInspector/backend/internal/cli"
VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[A-Za-z0-9.-]+)?")
SCHEMA_VERSION = "build-manifest-v1"
BINARY_NAME = "hostsec"


def fail(message):
    raise SystemExit(message)


def parse_version(raw):
    if raw is None:
        raw = "0.1.0-dev"
    if not VERSION_RE.fullmatch(raw):
        fail("invalid VERSION")
    return raw


def git_output(*args):
    proc = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True)
    return proc.stdout.strip()


def source_identity():
    commit = git_output("rev-parse", "HEAD")
    existing = subprocess.run(["git", "cat-file", "-e", commit + "^{commit}"], cwd=ROOT, capture_output=True, text=True)
    if existing.returncode != 0:
        fail("source_commit does not exist")
    dirty_listing = git_output("status", "--porcelain")
    return commit, bool(dirty_listing), source_tree_hash()


def source_tree_hash():
    listing = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
    names = sorted(name.decode() for name in listing.stdout.split(b"\0") if name)
    digest = hashlib.sha256()
    for name in names:
        path = ROOT / name
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            payload = b"link " + name.encode() + b"\0" + os.readlink(path).encode()
        else:
            payload = f"file {info.st_mode & 0o777:o} ".encode() + name.encode() + b"\0" + path.read_bytes()
        digest.update(len(payload).to_bytes(8, "little"))
        digest.update(payload)
    return digest.hexdigest()


def build_binary(out_dir, version, goos, goarch):
    ldflags = f"-buildid= -X {PKG}.Version={version}"
    binary = out_dir / f"{BINARY_NAME}-{goos}-{goarch}"
    env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0")
    env.pop("HOSTSEC_BUILD_DIR", None)
    subprocess.run(
        ["go", "build", "-trimpath", "-ldflags", ldflags, "-o", str(binary), "./cmd/hostsec"],
        cwd=ROOT / "backend",
        env=env,
        check=True,
    )
    data = binary.read_bytes()
    if data[:4] != b"\x7fELF":
        fail("not an ELF artifact")
    expected_machine = {"amd64": 62, "arm64": 183}[goarch]
    if int.from_bytes(data[18:20], "little") != expected_machine:
        fail("wrong ELF architecture")
    return binary, data, ldflags


def native_goarch():
    proc = subprocess.run(["go", "env", "GOARCH"], cwd=ROOT / "backend", capture_output=True, text=True, check=True)
    return proc.stdout.strip()


def read_binary_version(binary):
    proc = subprocess.run([str(binary), "version", "--json"], cwd=ROOT, capture_output=True, text=True, timeout=20)
    if proc.returncode != 0 or proc.stderr.strip():
        fail(f"version command failed: {proc.returncode} {proc.stderr}")
    payload = json.loads(proc.stdout)
    version = payload.get("version")
    if not version:
        fail("version command returned empty version")
    return version


def write_manifest(path, manifest):
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(manifest, indent=2) + "\n")
    tmp.replace(path)


def build_release(out_dir, version, official=True):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "build-manifest.json"
    commit, dirty, tree_hash = source_identity()
    toolchain = subprocess.run(["go", "env", "GOVERSION"], cwd=ROOT / "backend", capture_output=True, text=True, check=True)
    ldflags = f"-buildid= -X {PKG}.Version={version}"
    rows = []
    native_arch = native_goarch()
    for arch in ("amd64", "arm64"):
        binary, data, _ = build_binary(out_dir, version, "linux", arch)
        check = "CROSS_BUILD_ONLY"
        if official and arch == native_arch:
            reported = read_binary_version(binary)
            if reported != version:
                fail(f"manifest/binary version mismatch: binary={reported} expected={version}")
            check = "NATIVE_VERSION_CHECK"
        rel = str(binary.relative_to(ROOT)) if official and ROOT in binary.resolve().parents else binary.name
        if official and not rel.startswith("build/"):
            # Keep published artifacts repo-relative; tests may use a temp dir.
            try:
                rel = str(binary.relative_to(ROOT))
            except ValueError:
                rel = binary.name
        rows.append({
            "binary_name": BINARY_NAME,
            "goos": "linux",
            "goarch": arch,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "path": rel if official else binary.name,
            "validation": "CROSS_BUILD_ONLY",
            "validation_level": "CROSS_BUILD_ONLY",
            "runtime_version_check": check,
            "version": version,
        })

    hashes = []
    with tempfile.TemporaryDirectory(prefix="hostsec-repro-") as first, tempfile.TemporaryDirectory(prefix="hostsec-repro-") as second:
        for directory in (first, second):
            target = Path(directory) / BINARY_NAME
            env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0")
            subprocess.run(
                ["go", "build", "-trimpath", "-ldflags", ldflags, "-o", str(target), "./cmd/hostsec"],
                cwd=ROOT / "backend",
                env=env,
                check=True,
            )
            hashes.append(hashlib.sha256(target.read_bytes()).hexdigest())
    if hashes[0] != hashes[1]:
        fail("reproducible build hash mismatch")
    official_amd64 = next(row for row in rows if row["goarch"] == "amd64")
    if official_amd64["sha256"] != hashes[0]:
        fail("release amd64 hash does not match reproducible build")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "binary_name": BINARY_NAME,
        "version": version,
        "source_commit": commit,
        "source_tree_hash": tree_hash,
        "dirty": dirty,
        "workspace_dirty": dirty,
        "go_version": toolchain.stdout.strip(),
        "cgo": False,
        "cgo_enabled": False,
        "build_flags": ["-trimpath", "-ldflags", ldflags],
        "ldflags": ldflags,
        "reproducible_linux_amd64_sha256": hashes[0],
        "artifacts": rows,
        "validation": "CROSS_BUILD_ONLY",
        "validation_level": "CROSS_BUILD_ONLY",
    }
    if official:
        write_manifest(manifest_path, manifest)
    return manifest


def run_negative_version_cases():
    script = Path(__file__).resolve()
    for bad in ("", "latest", "v1.2.3", "1"):
        with tempfile.TemporaryDirectory(prefix="hostsec-badver-") as directory:
            env = dict(os.environ, VERSION=bad, HOSTSEC_BUILD_DIR=directory, HOSTSEC_RELEASE_SELFTEST="0")
            proc = subprocess.run([sys.executable, str(script)], cwd=ROOT, env=env, capture_output=True, text=True)
            if proc.returncode == 0:
                fail(f"invalid VERSION {bad!r} was accepted")
            if (Path(directory) / "build-manifest.json").exists():
                fail(f"invalid VERSION {bad!r} wrote a success manifest")


def run_explicit_version_case():
    version = "1.2.3-test"
    arch = native_goarch()
    with tempfile.TemporaryDirectory(prefix="hostsec-explver-") as directory:
        out_dir = Path(directory)
        binary, _, _ = build_binary(out_dir, version, "linux", arch)
        reported = read_binary_version(binary)
        if reported != version:
            fail(f"explicit VERSION not injected: got {reported}")


def main():
    version = parse_version(os.environ.get("VERSION", "0.1.0-dev"))
    out_dir = Path(os.environ.get("HOSTSEC_BUILD_DIR", str(ROOT / "build")))
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir
    manifest = build_release(out_dir, version, official=True)
    if os.environ.get("HOSTSEC_RELEASE_SELFTEST", "1") == "1":
        run_negative_version_cases()
        run_explicit_version_case()
        default_native = next(row for row in manifest["artifacts"] if row["runtime_version_check"] == "NATIVE_VERSION_CHECK")
        if default_native["version"] != version:
            fail("default version artifact mismatch")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
