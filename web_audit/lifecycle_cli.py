from __future__ import annotations

_STATE_LABELS = (
    ("new", "NEW"),
    ("present", "PRESENT"),
    ("fixed", "FIXED"),
    ("changed", "CHANGED"),
    ("regressed", "REGRESSED"),
    ("unverified", "UNVERIFIED"),
)


def render_lifecycle_summary(summary: dict) -> str:
    """Render a lifecycle summary for CLI output."""
    lines = [
        "Security changes",
        "-----------------",
    ]

    for key, label in _STATE_LABELS:
        lines.append(f"{label:<12}{summary.get(f'{key}_count', 0)}")

    has_changes = False

    for key, label in _STATE_LABELS:
        items = summary.get(key, [])
        if not items:
            continue

        has_changes = True
        lines.append("")
        lines.append(label)

        for item in items:
            rule_id = item["rule_id"]
            url = item["url"]

            if key == "changed":
                lines.append(
                    f"  [{label}] {rule_id} ({item['previous_severity']} -> {item['severity']})"
                )
            else:
                lines.append(f"  [{label}] {rule_id}")

            lines.append(f"    {url}")
            if key == "unverified":
                lines.append(f"    {item.get('reason', 'A successful recheck is required.')}")

    if not has_changes:
        lines.append("")
        lines.append("No lifecycle changes.")

    return "\n".join(lines)
