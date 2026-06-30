"""
The scan store ("the shop").

Each scan is written as one timestamped JSON record into a store directory, and a
lightweight `index.json` manifest lists them newest-first. The CLI (operator door)
writes here; the viewer (consumer door) reads here. They never talk to each other —
they only share this folder.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from threatmap.models.resource import Resource
from threatmap.models.threat import Severity, Threat

MANIFEST = "index.json"
_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _slug(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip()).strip("-")
    return s or "scan"


def _summary(threats: List[Threat], resource_count: int) -> Dict[str, int]:
    counts = {s: 0 for s in _SEVERITIES}
    for t in threats:
        counts[t.severity.value] = counts.get(t.severity.value, 0) + 1
    counts["total"] = len(threats)
    counts["resources"] = resource_count
    return counts


def build_record(
    provider: str,
    scope: str,
    framework: str,
    resources: List[Resource],
    threats: List[Threat],
    when: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Assemble the JSON record for a single scan."""
    when = when or datetime.now(timezone.utc)
    stamp = when.strftime("%Y-%m-%dT%H-%M-%SZ")
    scan_id = f"{stamp}_{_slug(provider)}_{_slug(scope)}"
    return {
        "id": scan_id,
        "generated": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "provider": provider,
        "scope": scope,
        "framework": framework,
        "summary": _summary(threats, len(resources)),
        "threats": [t.to_dict() for t in threats],
        "resources": [
            {
                "name": r.name,
                "type": r.resource_type,
                "provider": r.provider,
                "exposure": r.exposure,
            }
            for r in resources
        ],
    }


def write_scan(
    store_dir: str,
    provider: str,
    scope: str,
    framework: str,
    resources: List[Resource],
    threats: List[Threat],
    when: Optional[datetime] = None,
) -> str:
    """Write a scan record into the store and refresh the manifest. Returns the file path."""
    os.makedirs(store_dir, exist_ok=True)
    record = build_record(provider, scope, framework, resources, threats, when)
    path = os.path.join(store_dir, f"{record['id']}.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(record, fh, indent=2)
    _rebuild_manifest(store_dir)
    return path


def load_records(store_dir: str) -> List[Dict[str, Any]]:
    """Load all full scan records from the store, newest-first."""
    if not os.path.isdir(store_dir):
        return []
    records = []
    for fname in os.listdir(store_dir):
        if fname == MANIFEST or not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(store_dir, fname), "r", encoding="utf-8") as fh:
                records.append(json.load(fh))
        except (json.JSONDecodeError, OSError):
            continue
    records.sort(key=lambda r: r.get("generated", ""), reverse=True)
    return records


def _rebuild_manifest(store_dir: str) -> None:
    records = load_records(store_dir)
    manifest = [
        {
            "id": r["id"],
            "generated": r.get("generated"),
            "provider": r.get("provider"),
            "scope": r.get("scope"),
            "framework": r.get("framework"),
            "summary": r.get("summary", {}),
        }
        for r in records
    ]
    with open(os.path.join(store_dir, MANIFEST), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2)
