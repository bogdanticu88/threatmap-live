"""Tests for the scan store (the shared folder the CLI writes and the viewer reads)."""
import json
import os
from datetime import datetime, timezone

from threatmap.analyzers import engine

from threatmap_live import store
from threatmap_live.live.azure import AzureCollector
from threatmap_live.live.aws import AwsCollector
from tests.conftest import fake_az_runner, fake_aws_runner


def _azure_scan():
    res = AzureCollector(subscription="sub-prod", runner=fake_az_runner).collect().resources
    return res, engine.run(res, "stride")


def _aws_scan():
    res = AwsCollector(region="eu-west-1", runner=fake_aws_runner).collect().resources
    return res, engine.run(res, "stride")


def test_write_scan_creates_record_and_manifest(tmp_path):
    res, threats = _azure_scan()
    path = store.write_scan(str(tmp_path), "azure", "sub-prod", "stride", res, threats,
                            when=datetime(2026, 7, 1, 9, 0, 0, tzinfo=timezone.utc))
    assert os.path.exists(path)
    record = json.loads(open(path, encoding="utf-8").read())
    assert record["provider"] == "azure"
    assert record["scope"] == "sub-prod"
    assert record["summary"]["total"] == len(threats)
    assert record["summary"]["CRITICAL"] >= 1
    assert len(record["threats"]) == len(threats)

    manifest = json.loads(open(tmp_path / "index.json", encoding="utf-8").read())
    assert len(manifest) == 1
    assert manifest[0]["id"] == record["id"]


def test_records_sorted_newest_first(tmp_path):
    az_res, az_threats = _azure_scan()
    aws_res, aws_threats = _aws_scan()
    store.write_scan(str(tmp_path), "azure", "sub-prod", "stride", az_res, az_threats,
                     when=datetime(2026, 7, 1, 9, 0, 0, tzinfo=timezone.utc))
    store.write_scan(str(tmp_path), "aws", "eu-west-1", "stride", aws_res, aws_threats,
                     when=datetime(2026, 7, 1, 11, 30, 0, tzinfo=timezone.utc))

    records = store.load_records(str(tmp_path))
    assert [r["provider"] for r in records] == ["aws", "azure"]  # newest (11:30) first


def test_scope_is_slugged_into_id(tmp_path):
    res, threats = _azure_scan()
    path = store.write_scan(str(tmp_path), "azure", "Prod / West Europe", "stride", res, threats,
                            when=datetime(2026, 7, 1, 9, 0, 0, tzinfo=timezone.utc))
    assert "Prod-West-Europe" in os.path.basename(path)
