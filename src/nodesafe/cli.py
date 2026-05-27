"""Command-line interface."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from nodesafe import __version__
from nodesafe.config import load_config
from nodesafe.report import VerdictLabel
from nodesafe.scanner import Scanner

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.version_option(version=__version__, prog_name="nodesafe")
def main() -> None:
    """nodesafe — security scanner for node-based workflow plugins."""


@main.command()
@click.argument(
    "target", type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path)
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "markdown"], case_sensitive=False),
    default="markdown",
    help="Output format (json or markdown). SARIF coming in v0.5.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["none", "suspicious", "malicious"], case_sensitive=False),
    default="suspicious",
    help="Exit non-zero if verdict reaches this severity.",
)
@click.option(
    "--layers",
    default=None,
    help="Comma-separated layer IDs (e.g., '0,1'). Default uses config.",
)
@click.option(
    "--no-llm",
    is_flag=True,
    help="Disable Layer 8 (LLM) for this run. No-op until L8 ships.",
)
@click.option(
    "--batch",
    is_flag=True,
    help="Treat TARGET as a parent directory; scan each first-level subdirectory "
    "as a separate node and emit a per-subdirectory verdict.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to a custom config TOML.",
)
def scan(
    target: Path,
    output_format: str,
    fail_on: str,
    layers: str | None,
    no_llm: bool,
    batch: bool,
    config_path: Path | None,
) -> None:
    """Scan a plugin/node directory for malicious code."""
    cfg = load_config(config_path)
    if layers:
        cfg.scanner.default_layers = layers
    if no_llm:
        cfg.llm.enabled = False

    scanner = Scanner(config=cfg)

    if batch:
        _run_batch(scanner, target, output_format, fail_on)
        return

    try:
        report = scanner.scan(target)
    except FileNotFoundError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        sys.exit(3)

    if output_format == "json":
        # Print JSON to stdout for piping; nothing else on stdout.
        click.echo(report.to_json())
    else:
        _emit_markdown(report.to_markdown())

    # Exit code policy
    label = report.verdict.label
    if fail_on == "malicious" and label == VerdictLabel.MALICIOUS:
        sys.exit(2)
    if fail_on == "suspicious" and label in {VerdictLabel.SUSPICIOUS, VerdictLabel.MALICIOUS}:
        sys.exit(2 if label == VerdictLabel.MALICIOUS else 1)


def _run_batch(
    scanner: Scanner,
    target: Path,
    output_format: str,
    fail_on: str,
) -> None:
    """Scan every first-level subdirectory of `target` independently.

    For each subdir we run a full scan and emit one summary line per node;
    at the end we print an aggregate table (markdown) or a JSON array (json)
    and exit with the worst severity across all subdirectories.
    """
    import json

    if not target.exists() or not target.is_dir():
        err_console.print(f"[red]Error:[/red] {target} is not a directory")
        sys.exit(3)

    subdirs = sorted(p for p in target.iterdir() if p.is_dir() and not p.name.startswith("."))
    if not subdirs:
        err_console.print(f"[yellow]Warning:[/yellow] no subdirectories found in {target}")
        sys.exit(0)

    reports = []
    worst_label: VerdictLabel = VerdictLabel.CLEAN
    severity_order = {
        VerdictLabel.CLEAN: 0,
        VerdictLabel.SUSPICIOUS: 1,
        VerdictLabel.MALICIOUS: 2,
        VerdictLabel.ERROR: 1,
    }

    for subdir in subdirs:
        try:
            r = scanner.scan(subdir)
            reports.append((subdir.name, r))
            if severity_order[r.verdict.label] > severity_order[worst_label]:
                worst_label = r.verdict.label
        except FileNotFoundError:
            continue

    if output_format == "json":
        payload = [
            {
                "node": name,
                "verdict": r.verdict.model_dump(mode="json"),
                "recommendation": r.recommendation,
                "findings_count": len(r.findings),
            }
            for name, r in reports
        ]
        click.echo(json.dumps(payload, indent=2))
    else:
        lines = [
            f"# nodesafe batch scan — {target} ({len(reports)} nodes)",
            "",
            "| Node | Verdict | Score | Recommendation | Findings |",
            "|------|---------|-------|----------------|----------|",
        ]
        emoji = {
            VerdictLabel.CLEAN: "[green]clean[/green]",
            VerdictLabel.SUSPICIOUS: "[yellow]suspicious[/yellow]",
            VerdictLabel.MALICIOUS: "[red]malicious[/red]",
            VerdictLabel.ERROR: "[red]error[/red]",
        }
        for name, r in reports:
            lines.append(
                f"| `{name}` | {emoji[r.verdict.label]} | "
                f"{r.verdict.score:.2f} | `{r.recommendation}` | {len(r.findings)} |"
            )
        lines.append("")
        lines.append(f"Worst verdict across batch: **{worst_label.value}**")
        _emit_markdown("\n".join(lines))

    # Exit code policy applied to the worst verdict.
    if fail_on == "malicious" and worst_label == VerdictLabel.MALICIOUS:
        sys.exit(2)
    if fail_on == "suspicious" and worst_label in {VerdictLabel.SUSPICIOUS, VerdictLabel.MALICIOUS}:
        sys.exit(2 if worst_label == VerdictLabel.MALICIOUS else 1)


def _emit_markdown(markdown: str) -> None:
    """Emit markdown to stdout, using UTF-8 bytes when stdout is not a TTY.

    Rich's `console.print` works great in an interactive terminal but on
    Windows it falls back to a legacy renderer that re-encodes the buffer
    in cp1252, which crashes on emoji like the verdict marker. When stdout
    is redirected to a file or pipe we don't need Rich at all; the raw
    markdown is the right output, and writing it as UTF-8 bytes bypasses
    whatever encoding the OS picked for the destination file.
    """
    if sys.stdout.isatty():
        console.print(markdown)
        return
    try:
        sys.stdout.buffer.write(markdown.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()
    except (AttributeError, ValueError):
        # Some test runners replace sys.stdout with a StringIO that has no
        # `.buffer`. Fall back to a plain write; Rich's emoji rendering can
        # still upset cp1252 there, but Click's runner captures Unicode fine.
        sys.stdout.write(markdown + "\n")
        sys.stdout.flush()


@main.command()
def update() -> None:
    """Update signature databases and ML models. (Stub in v0.1.)"""
    console.print("[yellow]Update functionality coming in v0.2.[/yellow]")
    console.print(
        "For now, signatures are bundled with the package; pip upgrade to get the latest."
    )


@main.command()
def doctor() -> None:
    """Verify installation and signature integrity."""
    from nodesafe.data.signatures import load_hash_signatures, load_malicious_urls

    console.print(f"[bold]nodesafe[/bold] v{__version__}")
    console.print(f"  Python: {sys.version.split()[0]}")

    sigs = load_hash_signatures()
    console.print(f"  Hash signatures loaded: {len(sigs)}")

    urls = load_malicious_urls()
    console.print(f"  Malicious URLs loaded: {len(urls)}")

    if sigs or urls:
        console.print("[green]Installation looks healthy.[/green]")
    else:
        console.print(
            "[yellow]Warning:[/yellow] no signatures loaded. "
            "The bundled signatures directory may be missing."
        )


if __name__ == "__main__":  # pragma: no cover
    main()
