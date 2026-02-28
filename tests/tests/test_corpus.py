import json
from pathlib import Path

from scanner import scan_directory


CORPUS_ROOT = Path("tests/dir/corpus/projects")
MANIFEST_PATH = Path("tests/dir/corpus/manifest.json")


def test_corpus_manifest_exists_and_size():
    assert MANIFEST_PATH.exists()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert len(manifest) >= 20


def test_corpus_projects_exist_and_nested_structure_present():
    projects = [p for p in CORPUS_ROOT.iterdir() if p.is_dir()]
    assert len(projects) >= 20
    assert (CORPUS_ROOT / "mixed_vuln_large" / "backend" / "config" / ".env").exists()
    assert (CORPUS_ROOT / "py_vuln_nested" / "src" / "core" / "auth.py").exists()
    assert (CORPUS_ROOT / "ts_vuln_nested" / "src" / "services" / "client.ts").exists()


def test_vulnerable_projects_have_findings_and_clean_projects_are_quiet():
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    vulnerable = [entry["name"] for entry in manifest if entry["vulnerable"]]
    clean = [entry["name"] for entry in manifest if not entry["vulnerable"]]

    vulnerable_detected = 0
    for project_name in vulnerable:
        findings = scan_directory(str(CORPUS_ROOT / project_name))
        if findings:
            vulnerable_detected += 1

    clean_without_findings = 0
    for project_name in clean:
        findings = scan_directory(str(CORPUS_ROOT / project_name))
        if not findings:
            clean_without_findings += 1

    assert vulnerable_detected >= max(8, len(vulnerable) - 2)
    assert clean_without_findings >= max(8, len(clean) - 2)
