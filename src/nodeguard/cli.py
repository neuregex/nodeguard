"""Command-line interface."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from nodeguard import __version__
from nodeguard.config import load_config
from nodeguard.report import VerdictLabel
from nodeguard.scanner import Scanner

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.version_option(version=__version__, prog_name="nodeguard")
def main() -> None:
    """nodeguard — security scanner for node-based workflow plugins."""


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
    help="Disable Layer 8 (LLM) for this run. No-op in v0.1 (LLM not yet implemented).",
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
    config_path: Path | None,
) -> None:
    """Scan a plugin/node directory for malicious code."""
    cfg = load_config(config_path)
    if layers:
        cfg.scanner.default_layers = layers
    if no_llm:
        cfg.llm.enabled = False

    scanner = Scanner(config=cfg)

    try:
        report = scanner.scan(target)
    except FileNotFoundError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        sys.exit(3)

    if output_format == "json":
        # Print JSON to stdout for piping; nothing else on stdout.
        click.echo(report.to_json())
    else:
        console.print(report.to_markdown())

    # Exit code policy
    label = report.verdict.label
    if fail_on == "malicious" and label == VerdictLabel.MALICIOUS:
        sys.exit(2)
    if fail_on == "suspicious" and label in {VerdictLabel.SUSPICIOUS, VerdictLabel.MALICIOUS}:
        sys.exit(2 if label == VerdictLabel.MALICIOUS else 1)


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
    from nodeguard.data.signatures import load_hash_signatures, load_malicious_urls

    console.print(f"[bold]nodeguard[/bold] v{__version__}")
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
