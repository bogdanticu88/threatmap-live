"""End-to-end CLI tests with the fake az runner injected into the collector."""
import json

from click.testing import CliRunner

from threatmap_live import cli as cli_mod
from threatmap_live.live.aws import AwsCollector
from threatmap_live.live.azure import AzureCollector
from tests.conftest import fake_aws_runner, fake_az_runner


def _patch_collector(monkeypatch):
    def make(**kwargs):
        return AzureCollector(
            subscription=kwargs.get("subscription"),
            resource_group=kwargs.get("resource_group"),
            runner=fake_az_runner,
        )
    monkeypatch.setattr(cli_mod, "AzureCollector", make)


def _patch_aws_collector(monkeypatch):
    def make(**kwargs):
        return AwsCollector(profile=kwargs.get("profile"), region=kwargs.get("region"), runner=fake_aws_runner)
    monkeypatch.setattr(cli_mod, "AwsCollector", make)


def test_scan_live_markdown_to_stdout(monkeypatch):
    _patch_collector(monkeypatch)
    result = CliRunner().invoke(cli_mod.cli, ["scan-live", "--provider", "azure", "--subscription", "sub-1"])
    assert result.exit_code == 0
    assert "Threat Model Report" in result.output
    assert "allows public blob access" in result.output


def test_scan_live_json_to_file(monkeypatch, tmp_path):
    _patch_collector(monkeypatch)
    out = tmp_path / "report.json"
    result = CliRunner().invoke(
        cli_mod.cli,
        ["scan-live", "--provider", "azure", "--subscription", "sub-1", "--format", "json", "-o", str(out)],
    )
    assert result.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["meta"]["tool"] == "threatmap"
    assert len(data["threats"]) > 0


def test_fail_on_critical_exits_1(monkeypatch):
    _patch_collector(monkeypatch)
    result = CliRunner().invoke(
        cli_mod.cli,
        ["scan-live", "--provider", "azure", "--subscription", "sub-1", "--fail-on", "CRITICAL"],
    )
    # Fixtures include CRITICAL findings (public blob, SSH-open NSG), so the gate trips.
    assert result.exit_code == 1


def test_scan_live_aws_markdown_to_stdout(monkeypatch):
    _patch_aws_collector(monkeypatch)
    result = CliRunner().invoke(cli_mod.cli, ["scan-live", "--provider", "aws", "--region", "us-east-1"])
    assert result.exit_code == 0
    assert "Threat Model Report" in result.output
    assert "exposes SSH/RDP" in result.output
