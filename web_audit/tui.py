from __future__ import annotations

from collections.abc import Callable

try:
    from rich.console import Console
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )
except ImportError:  # pragma: no cover
    Console = None
    Progress = None


def _emit_alert(console: object, result: object) -> None:
    findings = getattr(result, "findings", ())
    url = getattr(result, "url", "")
    for finding in findings:
        severity = getattr(finding, "severity", "")
        if severity == "high":
            console.print(
                f"[bold red]HIGH[/bold red] {getattr(finding, 'title', 'Finding')} "
                f"[{getattr(finding, 'rule_id', '')}] — {url}"
            )


def run_with_progress(
    scan_fn: Callable[[Callable[[object], None]], object],
    total: int,
    *,
    title: str = "Scanning",
):
    if Progress is None:
        return scan_fn(lambda _result: None)
    console = Console()
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(title, total=total)

        def callback(result: object) -> None:
            progress.advance(task)
            _emit_alert(progress.console, result)

        return scan_fn(callback)
