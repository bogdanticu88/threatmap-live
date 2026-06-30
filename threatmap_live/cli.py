"""
threatmap-live CLI.

`scan-live` collects deployed cloud resources (under your own SSO session) and
runs them through threatmap's existing STRIDE/MITRE/PASTA engine and reporters —
the engine cannot tell a live resource from one parsed out of a .tf file.
"""
from __future__ import annotations

import sys
from typing import Optional

import click
from rich.console import Console

from threatmap.analyzers import engine
from threatmap.reporters import html_reporter, json_reporter, markdown, sarif_reporter

from threatmap_live import __version__
from threatmap_live.live.aws import AwsCollector
from threatmap_live.live.azure import AzureCollector
from threatmap_live.live.base import BaseCollector, CollectorError

_err = Console(stderr=True)

_REPORTERS = {
    "markdown": markdown.build_report,
    "json": json_reporter.build_report,
    "sarif": sarif_reporter.build_report,
    "html": html_reporter.build_report,
}

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _force_utf8_output() -> None:
    """Same Windows-console safeguard threatmap applies (emoji/arrows/em-dashes)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass


def _build_collector(provider: str, subscription, resource_group, profile, region) -> BaseCollector:
    if provider == "azure":
        return AzureCollector(subscription=subscription, resource_group=resource_group)
    if provider == "aws":
        return AwsCollector(profile=profile, region=region)
    raise click.BadParameter(f"unknown provider: {provider}")


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@click.version_option(__version__)
def cli() -> None:
    """threatmap-live — live cloud threat modeling on top of threatmap."""


@cli.command("scan-live")
@click.option("--provider", type=click.Choice(["azure", "aws"]), required=True, help="Cloud provider to collect from.")
@click.option("--subscription", default=None, help="Azure subscription ID (defaults to the az CLI's active subscription).")
@click.option("--resource-group", default=None, help="Limit Azure collection to a single resource group.")
@click.option("--profile", default=None, help="AWS profile (AWS provider).")
@click.option("--region", default=None, help="AWS region (AWS provider).")
@click.option("--framework", type=click.Choice(["stride", "mitre", "pasta"]), default="stride", show_default=True)
@click.option("--format", "output_format", type=click.Choice(list(_REPORTERS)), default="markdown", show_default=True)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write the report to this file (default: stdout).")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM"]), default=None,
              help="Exit 1 if any threat at or above this severity is found (CI gate).")
def scan_live(provider, subscription, resource_group, profile, region, framework, output_format, output, fail_on):
    """Collect live cloud resources and produce a threat model report."""
    collector = _build_collector(provider, subscription, resource_group, profile, region)

    if provider == "azure":
        scope = subscription or "active subscription"
    else:
        scope = region or "default region"
    _err.print(f"[bold]Collecting live {provider} resources[/bold] ([dim]{scope}[/dim]) via '{collector.cli_name}'…")

    try:
        collection = collector.collect()
    except CollectorError as exc:
        _err.print(f"[red]Collection failed:[/red] {exc}")
        sys.exit(2)

    for w in collection.warnings:
        _err.print(f"[yellow]warning:[/yellow] {w}")

    resources = collection.resources
    if not resources:
        _err.print("[yellow]No resources collected.[/yellow] Check your login, subscription, and permissions.")
        sys.exit(0)
    _err.print(f"Collected [bold]{len(resources)}[/bold] resources.")

    threats = engine.run(resources, framework=framework)
    counts = {s: sum(1 for t in threats if t.severity.value == s) for s in _SEVERITY_ORDER}
    _err.print(
        f"Identified [bold]{len(threats)}[/bold] threats — "
        + "  ".join(f"{s}: {counts[s]}" for s in _SEVERITY_ORDER if counts[s] > 0)
    )

    source_label = f"{provider} live: {scope}"
    report = _REPORTERS[output_format](resources, threats, source_label)

    if output:
        with open(output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report)
        _err.print(f"Report written to [bold]{output}[/bold]")
    else:
        click.echo(report)

    if fail_on:
        threshold = _SEVERITY_ORDER.index(fail_on)
        if any(counts[s] > 0 for s in _SEVERITY_ORDER[: threshold + 1]):
            _err.print(f"[red]CI gate:[/red] threat at or above {fail_on} found.")
            sys.exit(1)

    sys.exit(0)


def main() -> None:
    _force_utf8_output()
    cli()


if __name__ == "__main__":
    main()
