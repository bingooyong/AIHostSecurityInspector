"""Validate dependency, status, context, source and local documentation contracts."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]

def main():
    dag = json.loads((ROOT / "docs/implementation/task-dag.json").read_text())
    nodes = {n["id"]: n for n in dag["nodes"]}
    assert len(nodes) == len(dag["nodes"]), "duplicate DAG ID"
    assert len(nodes) == 48, "roadmap node count changed; review the contract"
    done, active = set(), set()
    def visit(key):
        assert key in nodes, f"missing dependency {key}"
        if key in done:
            return
        assert key not in active, f"cycle at {key}"
        active.add(key)
        for dep in nodes[key]["depends_on"]:
            visit(dep)
        active.remove(key)
        done.add(key)
    required = {"input_documents", "deliverables", "scope", "acceptance_criteria", "automated_tests", "risks", "parallel_allowed", "parallel_condition", "completion_evidence"}
    for key, node in nodes.items():
        visit(key)
        assert required <= node.keys(), key
        assert node["status"] in dag["status_vocabulary"], key
        task_dir = ROOT / node["task_path"]
        meta = json.loads((task_dir / "task.json").read_text())
        assert meta["parent"] == "11-20-hostsec-master", key
        assert meta["meta"]["delivery_status"] == node["status"], key
        for field in ("input_documents", "completion_evidence"):
            for filename in node[field]:
                assert (ROOT / filename).is_file(), f"{key} missing {field}: {filename}"
        for artifact in ("prd.md", "design.md", "implement.md"):
            assert (task_dir / artifact).stat().st_size > 80, (key, artifact)
        for action in ("implement", "check"):
            records = [json.loads(line) for line in (task_dir / (action + ".jsonl")).read_text().splitlines() if line.strip()]
            assert records, (key, action)
            for record in records:
                assert (ROOT / record["file"]).is_file(), record
        if node["status"] == "IMPLEMENTED":
            assert node["completion_evidence"], f"{key} no completion evidence"
            for filename in node["deliverables"]:
                assert (ROOT / filename).exists(), (key, filename)
    manifest = json.loads((ROOT / "docs/implementation/v1-source-manifest.json").read_text())
    assert len(manifest["files"]) == 22
    for entry in manifest["files"]:
        data = (ROOT / entry["path"]).read_bytes()
        assert len(data) == entry["bytes"] and hashlib.sha256(data).hexdigest() == entry["sha256"], entry["path"]
    # Register only engineering packages that actually exist; package/layer discovery
    # must keep working after directory migrations.
    import subprocess
    info = subprocess.run(["python3", ".trellis/scripts/get_context.py", "--mode", "packages", "--json"], cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert info.returncode == 0, info.stderr
    context = json.loads(info.stdout)
    assert context["mode"] == "monorepo" and context["defaultPackage"] == "backend"
    backend = next(pkg for pkg in context["packages"] if pkg["name"] == "backend")
    assert backend["path"] == "backend" and "go" in backend["specLayers"]
    assert (ROOT / backend["path"] / "go.mod").is_file()
    agents = (ROOT / "AGENTS.md").read_text()
    for marker in ("<!-- TRELLIS:START -->", "<!-- TRELLIS:END -->", "<!-- AUTONOMY DIRECTIVE — DO NOT REMOVE -->", "<!-- END AUTONOMY DIRECTIVE -->"):
        assert agents.count(marker) == 1, ("instruction marker missing or duplicated", marker)
    assert agents.index("<!-- TRELLIS:START -->") < agents.index("<!-- TRELLIS:END -->")
    managed_before = (ROOT / "docs/05-testing/evidence/layout-migration/agents-managed-block-before.txt").read_text()
    managed_start = agents.index("<!-- TRELLIS:START -->")
    managed_end = agents.index("<!-- TRELLIS:END -->") + len("<!-- TRELLIS:END -->")
    assert agents[managed_start:managed_end] == managed_before, "Trellis managed instruction block changed"
    for required in (".trellis/spec/backend/go/index.md", "docs/02-architecture/REPOSITORY-LAYOUT.md", "docs/07-decisions/ADR/ADR-008.md"):
        assert required in agents and (ROOT / required).is_file(), required
    # Bootstrap execution evidence is historical input, never rewritten by migration.
    history = ROOT / "docs/05-testing/evidence/layout-migration/historical-evidence-hashes.json"
    for filename, expected in json.loads(history.read_text()).items():
        assert hashlib.sha256((ROOT / filename).read_bytes()).hexdigest() == expected, ("historical evidence changed", filename)
    docs = [ROOT / "README.md", ROOT / "AGENTS.md"] + list((ROOT / "docs").rglob("*.md")) + list((ROOT / ".trellis/spec").rglob("*.md"))
    count = 0
    for document in docs:
        if "AI-Host-Security-Inspector-V1.0" in document.parts or document.name == "SKILL.md":
            continue
        body = document.read_text()
        assert body.count("```") % 2 == 0, f"unclosed fence: {document}"
        for link in re.findall(r"\[[^\]]*\]\(([^)]+)\)", body):
            if "://" in link or link.startswith("#") or link.startswith("mailto:"):
                continue
            filename = link.split("#", 1)[0]
            assert (document.parent / filename).exists(), f"broken link {document}: {link}"
            count += 1
    print(f"PASS: {len(nodes)} acyclic task contracts, 22 unchanged source files, {count} local document links")

if __name__ == "__main__":
    main()
