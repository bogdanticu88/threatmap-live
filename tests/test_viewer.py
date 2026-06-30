"""Tests for the self-contained viewer generator."""
import json
from datetime import datetime, timezone

from threatmap.analyzers import engine

from threatmap_live import store, viewer
from threatmap_live.live.azure import AzureCollector
from tests.conftest import fake_az_runner


def _seed_store(tmp_path):
    res = AzureCollector(subscription="sub-prod", runner=fake_az_runner).collect().resources
    threats = engine.run(res, "stride")
    store.write_scan(str(tmp_path), "azure", "sub-prod", "stride", res, threats,
                     when=datetime(2026, 7, 1, 9, 0, 0, tzinfo=timezone.utc))
    return threats


def test_build_viewer_is_self_contained(tmp_path):
    _seed_store(tmp_path)
    html = viewer.build_viewer(str(tmp_path))
    # Branding + self-containment
    assert "threatmap-live" in html
    assert "data:image/jpeg;base64," in html      # logo embedded
    assert "#EE7F00" in html                       # NN orange in the palette
    assert "sub-prod" in html                      # scan rendered
    # No external resource references (truly offline)
    assert "http://" not in html and "https://" not in html
    assert "src=\"http" not in html


def test_embedded_data_is_valid_json(tmp_path):
    threats = _seed_store(tmp_path)
    html = viewer.build_viewer(str(tmp_path))
    start = html.index('id="scan-data" type="application/json">') + len('id="scan-data" type="application/json">')
    end = html.index("</script>", start)
    blob = html[start:end].replace("<\\/", "</")
    data = json.loads(blob)
    assert len(data) == 1
    assert data[0]["scope"] == "sub-prod"
    assert len(data[0]["threats"]) == len(threats)


def test_build_viewer_writes_file(tmp_path):
    _seed_store(tmp_path)
    out = tmp_path / "viewer" / "index.html"
    viewer.build_viewer(str(tmp_path), output_path=str(out))
    assert out.exists()
    assert out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_empty_store_renders_without_error(tmp_path):
    html = viewer.build_viewer(str(tmp_path))   # no scans written
    assert "No scans yet" in html
    assert "data:image/jpeg;base64," in html
