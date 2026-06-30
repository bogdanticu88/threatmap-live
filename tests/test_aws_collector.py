"""
Tests for the AWS live collector.

As with Azure, the contract is with threatmap: mapped resources must drive the
unchanged engine's existing AWS-### rules. We assert both mapping shape and the
resulting findings, including the multi-call enrichment paths (S3, EKS, KMS, EC2
root-volume encryption).
"""
from threatmap.analyzers import engine

from threatmap_live.live.aws import AwsCollector
from tests.conftest import fake_aws_runner


def _collect():
    return AwsCollector(region="us-east-1", runner=fake_aws_runner).collect()


def test_collects_all_service_types():
    result = _collect()
    types = {r.resource_type for r in result.resources}
    assert {
        "aws_security_group",
        "aws_db_instance",
        "aws_instance",
        "aws_cloudtrail",
        "aws_lambda_function",
        "aws_iam_role",
        "aws_s3_bucket",
        "aws_eks_cluster",
        "aws_kms_key",
    }.issubset(types)
    assert not result.warnings


def test_service_linked_role_is_skipped():
    result = _collect()
    roles = [r for r in result.resources if r.resource_type == "aws_iam_role"]
    names = {r.name for r in roles}
    assert "role1" in names
    assert "AWSServiceRoleForX" not in names  # /aws-service-role/ excluded


def test_kms_skips_aws_managed_keys():
    result = _collect()
    kms = [r for r in result.resources if r.resource_type == "aws_kms_key"]
    assert [r.name for r in kms] == ["cust-1"]  # awsmanaged-1 filtered out


def test_security_group_ingress_mapping():
    result = _collect()
    sg = next(r for r in result.resources if r.resource_type == "aws_security_group")
    ingress = sg.properties["ingress"]
    assert ingress[0]["cidr_blocks"] == ["0.0.0.0/0"]
    assert ingress[0]["from_port"] == 22 and ingress[0]["to_port"] == 22


def test_ec2_root_volume_encryption_resolved():
    # vol-1 is unencrypted -> root_block_device.encrypted == False (drives AWS-021)
    result = _collect()
    ec2 = next(r for r in result.resources if r.resource_type == "aws_instance")
    assert ec2.properties["root_block_device"]["encrypted"] is False
    assert ec2.properties["metadata_options"]["http_tokens"] == "optional"


def test_engine_fires_expected_rules_on_live_resources():
    result = _collect()
    threats = engine.run(result.resources, framework="stride")
    desc = " ".join(t.description for t in threats)

    assert "exposes SSH/RDP" in desc                      # AWS-006 security group
    assert "publicly accessible from the internet" in desc  # AWS-010 rds
    assert "IMDSv1" in desc                                # AWS-022 ec2
    assert "multi-region trail" in desc                   # AWS-016 cloudtrail
    assert "not running inside a VPC" in desc             # AWS-019 lambda
    assert "any entity can assume this role" in desc      # AWS-009 iam role
    assert "no public access block" in desc               # AWS-001 s3
    assert "Kubernetes API is publicly accessible" in desc  # AWS-014 eks
    assert "key rotation" in desc                         # AWS-018 kms

    assert any(t.severity.value == "CRITICAL" for t in threats)


def test_one_failing_service_does_not_abort_scan():
    from threatmap_live.live.base import CollectorError

    def flaky(args):
        if "describe-db-instances" in args:
            raise CollectorError("AccessDenied: rds:DescribeDBInstances")
        return fake_aws_runner(args)

    result = AwsCollector(region="us-east-1", runner=flaky).collect()
    assert any("rds instances" in w for w in result.warnings)
    assert any(r.resource_type == "aws_security_group" for r in result.resources)
