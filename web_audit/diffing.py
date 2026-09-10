from __future__ import annotations

import json
from pathlib import Path

from .reports import _atomic_write


def load_report(path: Path) -> dict:
    with path.open(encoding="utf-8") as file:
        payload = json.load(file)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("invalid Web Audit Pro JSON report")
    return payload


def compare_reports(previous: dict, current: dict) -> dict:
    def findings_map(report):
        mapping = {}
        for result in report["results"]:
            url = result.get("url", "")
            findings = mapping.setdefault(url, set())
            findings.update(
                (f.get("rule_id"), f.get("severity")) for f in result.get("findings", [])
            )
        return mapping

    before = findings_map(previous)
    after = findings_map(current)
    urls = sorted(set(before) | set(after))
    added, removed = [], []
    for url in urls:
        for rule, severity in sorted(after.get(url, set()) - before.get(url, set())):
            added.append({"url": url, "rule_id": rule, "severity": severity})
        for rule, severity in sorted(before.get(url, set()) - after.get(url, set())):
            removed.append({"url": url, "rule_id": rule, "severity": severity})
    return {
        "previous_target": previous.get("target", ""),
        "current_target": current.get("target", ""),
        "added": added,
        "removed": removed,
        "added_count": len(added),
        "removed_count": len(removed),
    }


def save_diff(diff: dict, path: Path) -> None:
    def write(file) -> None:
        json.dump(diff, file, ensure_ascii=False, indent=2)
        file.write("\n")

    _atomic_write(path, write)
