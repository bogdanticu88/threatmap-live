"""
AWS live collector.

Mirrors the Azure collector: runs read-only `aws ... describe/list` commands under
the operator's ambient credentials and maps the results into threatmap's `Resource`
model using the Terraform `aws_*` type names and property keys the AWS analyzer
expects (see threatmap/analyzers/aws.py). The unchanged engine then fires its
existing AWS-### rules against live infrastructure.

Some services need a list call plus per-item enrichment (S3 bucket sub-settings,
EKS describe-cluster, KMS rotation status, EC2 root-volume encryption). Those
enrichment calls are best-effort: a single forbidden/missing sub-resource degrades
one finding rather than aborting the scan.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Optional, Sequence

from threatmap.models.resource import Resource

from threatmap_live.live.base import BaseCollector, CollectionResult, CollectorError


def _as_policy(value: Any) -> Any:
    """IAM policy docs arrive as a dict or a URL-encoded JSON string; normalize to dict."""
    if isinstance(value, str):
        try:
            return json.loads(urllib.parse.unquote(value))
        except Exception:  # noqa: BLE001 - leave as-is; the analyzer also tolerates strings
            return value
    return value


class AwsCollector(BaseCollector):
    cli_name = "aws"

    def __init__(self, profile: Optional[str] = None, region: Optional[str] = None, runner=None):
        if runner is not None:
            super().__init__(runner)
        else:
            super().__init__()
        self.profile = profile
        self.region = region

    # ------------------------------------------------------------------ helpers

    def _aws(self, args: Sequence[str], optional: bool = False) -> Any:
        argv = ["aws", *args]
        if self.region:
            argv += ["--region", self.region]
        if self.profile:
            argv += ["--profile", self.profile]
        argv += ["--output", "json"]
        try:
            return self._json(argv)
        except CollectorError:
            if optional:
                return None
            raise

    @staticmethod
    def _res(name: str, tf_type: str, props: Dict[str, Any], arn: str = "") -> Resource:
        return Resource(
            provider="aws",
            resource_type=tf_type,
            name=name or "<unnamed>",
            properties=props,
            source_format="aws-live",
            source_file=arn,
            exposure="unknown",
        )

    # ------------------------------------------------------------------ services

    def _security_groups(self) -> List[Resource]:
        data = self._aws(["ec2", "describe-security-groups"]) or {}
        out: List[Resource] = []
        for sg in data.get("SecurityGroups", []):
            ingress: List[Dict[str, Any]] = []
            for perm in sg.get("IpPermissions", []):
                cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", []) if r.get("CidrIp")]
                cidrs += [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6")]
                proto = perm.get("IpProtocol")
                if proto == "-1":  # all traffic; analyzer's AWS-007 keys on 0-0
                    from_port, to_port = 0, 0
                else:
                    from_port = perm.get("FromPort", -1)
                    to_port = perm.get("ToPort", -1)
                ingress.append({"cidr_blocks": cidrs, "from_port": from_port, "to_port": to_port})
            out.append(self._res(
                sg.get("GroupName") or sg.get("GroupId"),
                "aws_security_group",
                {"ingress": ingress},
                sg.get("GroupId", ""),
            ))
        return out

    def _rds(self) -> List[Resource]:
        data = self._aws(["rds", "describe-db-instances"]) or {}
        out: List[Resource] = []
        for db in data.get("DBInstances", []):
            out.append(self._res(
                db.get("DBInstanceIdentifier"),
                "aws_db_instance",
                {
                    "publicly_accessible": db.get("PubliclyAccessible"),
                    "storage_encrypted": db.get("StorageEncrypted"),
                    "deletion_protection": db.get("DeletionProtection"),
                    "backup_retention_period": db.get("BackupRetentionPeriod", 0),
                },
                db.get("DBInstanceArn", ""),
            ))
        return out

    def _ec2_instances(self) -> List[Resource]:
        data = self._aws(["ec2", "describe-instances"]) or {}
        # One extra call to resolve root-volume encryption (avoids AWS-021 false positives).
        vols = self._aws(["ec2", "describe-volumes"], optional=True) or {}
        vol_enc = {v.get("VolumeId"): v.get("Encrypted") for v in vols.get("Volumes", [])}

        out: List[Resource] = []
        for resv in data.get("Reservations", []):
            for inst in resv.get("Instances", []):
                root_name = inst.get("RootDeviceName")
                encrypted = None
                for bdm in inst.get("BlockDeviceMappings", []):
                    if bdm.get("DeviceName") == root_name:
                        encrypted = vol_enc.get(bdm.get("Ebs", {}).get("VolumeId"))
                        break
                props: Dict[str, Any] = {}
                if encrypted is not None:
                    props["root_block_device"] = {"encrypted": encrypted}
                meta = inst.get("MetadataOptions")
                if isinstance(meta, dict):
                    props["metadata_options"] = {"http_tokens": meta.get("HttpTokens", "optional")}
                out.append(self._res(inst.get("InstanceId"), "aws_instance", props, inst.get("InstanceId", "")))
        return out

    def _cloudtrail(self) -> List[Resource]:
        data = self._aws(["cloudtrail", "describe-trails"]) or {}
        out: List[Resource] = []
        for trail in data.get("trailList", []):
            out.append(self._res(
                trail.get("Name"),
                "aws_cloudtrail",
                {
                    "is_multi_region_trail": trail.get("IsMultiRegionTrail"),
                    "enable_log_file_validation": trail.get("LogFileValidationEnabled"),
                },
                trail.get("TrailARN", ""),
            ))
        return out

    def _lambda(self) -> List[Resource]:
        data = self._aws(["lambda", "list-functions"]) or {}
        out: List[Resource] = []
        for fn in data.get("Functions", []):
            vpc = fn.get("VpcConfig")
            # Lambda always returns a VpcConfig key; it's only "in a VPC" if a VpcId is set.
            vpc_config = vpc if isinstance(vpc, dict) and vpc.get("VpcId") else None
            out.append(self._res(
                fn.get("FunctionName"),
                "aws_lambda_function",
                {"vpc_config": vpc_config},
                fn.get("FunctionArn", ""),
            ))
        return out

    def _iam_roles(self) -> List[Resource]:
        data = self._aws(["iam", "list-roles"]) or {}
        out: List[Resource] = []
        for role in data.get("Roles", []):
            # Skip AWS service-linked roles: their trust policy is service-scoped by design.
            if (role.get("Path") or "").startswith("/aws-service-role/"):
                continue
            out.append(self._res(
                role.get("RoleName"),
                "aws_iam_role",
                {"assume_role_policy": _as_policy(role.get("AssumeRolePolicyDocument"))},
                role.get("Arn", ""),
            ))
        return out

    def _s3(self) -> List[Resource]:
        data = self._aws(["s3api", "list-buckets"]) or {}
        out: List[Resource] = []
        for bucket in data.get("Buckets", []):
            name = bucket.get("Name")
            if not name:
                continue
            props: Dict[str, Any] = {}

            pab = self._aws(["s3api", "get-public-access-block", "--bucket", name], optional=True)
            if pab:
                cfg = pab.get("PublicAccessBlockConfiguration", {})
                props["block_public_acls"] = cfg.get("BlockPublicAcls")

            enc = self._aws(["s3api", "get-bucket-encryption", "--bucket", name], optional=True)
            if enc and enc.get("ServerSideEncryptionConfiguration"):
                props["server_side_encryption_configuration"] = enc["ServerSideEncryptionConfiguration"]

            ver = self._aws(["s3api", "get-bucket-versioning", "--bucket", name], optional=True) or {}
            props["versioning"] = {
                "enabled": str(ver.get("Status")).lower() == "enabled",
                "mfa_delete": str(ver.get("MFADelete")).lower() == "enabled",
            }

            log = self._aws(["s3api", "get-bucket-logging", "--bucket", name], optional=True) or {}
            if log.get("LoggingEnabled"):
                props["logging"] = log["LoggingEnabled"]

            out.append(self._res(name, "aws_s3_bucket", props))
        return out

    def _eks(self) -> List[Resource]:
        data = self._aws(["eks", "list-clusters"]) or {}
        out: List[Resource] = []
        for cname in data.get("clusters", []):
            desc = self._aws(["eks", "describe-cluster", "--name", cname], optional=True)
            if not desc:
                continue
            cl = desc.get("cluster", {})
            vpc = cl.get("resourcesVpcConfig", {})
            out.append(self._res(
                cname,
                "aws_eks_cluster",
                {
                    "vpc_config": {
                        "endpoint_public_access": vpc.get("endpointPublicAccess", True),
                        "public_access_cidrs": vpc.get("publicAccessCidrs", ["0.0.0.0/0"]),
                    },
                    "encryption_config": cl.get("encryptionConfig"),
                },
                cl.get("arn", ""),
            ))
        return out

    def _kms(self) -> List[Resource]:
        data = self._aws(["kms", "list-keys"]) or {}
        out: List[Resource] = []
        for key in data.get("Keys", []):
            key_id = key.get("KeyId")
            if not key_id:
                continue
            desc = self._aws(["kms", "describe-key", "--key-id", key_id], optional=True)
            meta = (desc or {}).get("KeyMetadata", {})
            # Only customer-managed keys have a rotation setting worth flagging.
            if meta.get("KeyManager") != "CUSTOMER":
                continue
            rot = self._aws(["kms", "get-key-rotation-status", "--key-id", key_id], optional=True) or {}
            out.append(self._res(
                key_id,
                "aws_kms_key",
                {"enable_key_rotation": rot.get("KeyRotationEnabled")},
                meta.get("Arn", ""),
            ))
        return out

    _SERVICES = [
        ("security groups", _security_groups),
        ("rds instances", _rds),
        ("ec2 instances", _ec2_instances),
        ("cloudtrail trails", _cloudtrail),
        ("lambda functions", _lambda),
        ("iam roles", _iam_roles),
        ("s3 buckets", _s3),
        ("eks clusters", _eks),
        ("kms keys", _kms),
    ]

    def collect(self) -> CollectionResult:
        result = CollectionResult()
        for name, method in self._SERVICES:
            try:
                result.resources.extend(method(self))
            except CollectorError as exc:
                result.warnings.append(f"{name}: {exc}")
            except Exception as exc:  # noqa: BLE001 - one bad service must not kill the run
                result.warnings.append(f"{name}: unexpected error: {exc}")
        return result
