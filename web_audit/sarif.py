from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .models import CheckResult
from . import __version__
from .reports import _atomic_write

_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}


def save_sarif(results: list[CheckResult], path: Path) -> None:
    rules: dict[str, dict] = {}
    sarif_results = []
    for item in results:
        for finding in item.findings:
            rules.setdefault(finding.rule_id, {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.recommendation},
                "defaultConfiguration": {"level": _LEVEL[finding.severity]},
                "properties": {"category": finding.category, "confidence": finding.confidence},
            })
            sarif_results.append({
                "ruleId": finding.rule_id,
                "level": _LEVEL[finding.severity],
                "message": {"text": f"{finding.evidence} Recommendation: {finding.recommendation}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.url}}}],
            })
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Web Audit Pro",
                "semanticVersion": __version__,
                "rules": list(rules.values()),
            }},
            "invocations": [{"executionSuccessful": True,
                             "endTimeUtc": (
                                 datetime.now(UTC)
                                 .isoformat()
                                 .replace("+00:00", "Z")
                             )}],
            "results": sarif_results,
        }],
    }
    def write(file) -> None:
        json.dump(payload, file, ensure_ascii=False, indent=2)
        file.write("\n")

    _atomic_write(path, write)
