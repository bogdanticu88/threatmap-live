"""
AWS live collector — placeholder.

Structured to mirror AzureCollector: it will shell out to read-only `aws ...
describe/list` commands under the operator's ambient credentials and map the
results into threatmap's `Resource` model using the Terraform `aws_*` type names
and property keys the AWS analyzer expects (threatmap/analyzers/aws.py).

Not yet implemented — see the Azure collector for the pattern to follow.
"""
from __future__ import annotations

from typing import Optional

from threatmap_live.live.base import BaseCollector, CollectionResult, CollectorError


class AwsCollector(BaseCollector):
    cli_name = "aws"

    def __init__(self, profile: Optional[str] = None, region: Optional[str] = None, runner=None):
        if runner is not None:
            super().__init__(runner)
        else:
            super().__init__()
        self.profile = profile
        self.region = region

    def collect(self) -> CollectionResult:
        raise CollectorError(
            "The AWS live collector is not implemented yet. "
            "Use '--provider azure' for now; AWS is the next collector to land."
        )
