"""
Shared test helpers: a fake `az` runner driven by realistic CLI JSON fixtures.

The fixtures intentionally mirror the *flattened camelCase* shape the real `az`
CLI emits (which differs from the raw ARM `properties.*` shape) so the mapper is
tested against what it will actually receive.
"""
import json
from typing import Dict, List, Sequence

# Keyed by a stable slice of the az argv (the service verb path).
_FIXTURES: Dict[str, List[dict]] = {
    "storage account list": [
        {
            "name": "insecurestg",
            "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/insecurestg",
            "type": "Microsoft.Storage/storageAccounts",
            "allowBlobPublicAccess": True,           # -> AZ-001 CRITICAL
            "minimumTlsVersion": "TLS1_0",            # -> AZ-002 HIGH
            "enableHttpsTrafficOnly": False,          # -> AZ-003 HIGH
            "networkRuleSet": {"defaultAction": "Allow"},  # -> AZ-004 MEDIUM
        },
        {
            "name": "securestg",
            "id": "/subscriptions/sub-1/.../storageAccounts/securestg",
            "type": "Microsoft.Storage/storageAccounts",
            "allowBlobPublicAccess": False,
            "minimumTlsVersion": "TLS1_2",
            "enableHttpsTrafficOnly": True,
            "networkRuleSet": {"defaultAction": "Deny"},  # clean -> no findings
        },
    ],
    "keyvault list": [
        {
            "name": "kv-open",
            "id": "/subscriptions/sub-1/.../vaults/kv-open",
            "type": "Microsoft.KeyVault/vaults",
            "properties": {                            # keyvault nests under properties
                "enablePurgeProtection": None,         # -> AZ-005 HIGH
                "networkAcls": {"defaultAction": "Allow"},  # -> AZ-006 MEDIUM
            },
        },
    ],
    "network nsg list": [
        {
            "name": "nsg-ssh-open",
            "id": "/subscriptions/sub-1/.../networkSecurityGroups/nsg-ssh-open",
            "type": "Microsoft.Network/networkSecurityGroups",
            "securityRules": [
                {
                    "name": "AllowSSH",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "*",         # -> AZ-007 HIGH
                    "destinationPortRange": "22",       # -> AZ-008 CRITICAL
                }
            ],
        },
    ],
    "role assignment list --all": [
        {
            "principalName": "alice@contoso.com",
            "roleDefinitionName": "Owner",              # -> AZ-009 CRITICAL
            "scope": "/subscriptions/sub-1",            # -> AZ-010 HIGH (subscription scope)
        },
    ],
    "acr list": [
        {
            "name": "acradmin",
            "id": "/subscriptions/sub-1/.../registries/acradmin",
            "type": "Microsoft.ContainerRegistry/registries",
            "adminUserEnabled": True,                   # -> AZ-015 HIGH
        },
    ],
    "sql server list": [
        {
            "name": "sql-public",
            "id": "/subscriptions/sub-1/.../servers/sql-public",
            "type": "Microsoft.Sql/servers",
            "publicNetworkAccess": "Enabled",           # -> AZ-016 HIGH
        },
    ],
    "aks list": [
        {
            "name": "aks-open",
            "id": "/subscriptions/sub-1/.../managedClusters/aks-open",
            "type": "Microsoft.ContainerService/managedClusters",
            "enableRbac": False,                        # -> AZ-013 CRITICAL
            "apiServerAccessProfile": {"authorizedIpRanges": []},  # -> AZ-014 HIGH
        },
    ],
    "webapp list": [
        {
            "name": "web-nohttps",
            "id": "/subscriptions/sub-1/.../sites/web-nohttps",
            "type": "Microsoft.Web/sites",
            "kind": "app,linux",
            "httpsOnly": False,                         # -> AZ-011 HIGH
            "identity": None,                            # -> AZ-012 MEDIUM (linux only)
        },
    ],
    "vm list": [
        {
            "name": "vm-linux-pwd",
            "id": "/subscriptions/sub-1/.../virtualMachines/vm-linux-pwd",
            "type": "Microsoft.Compute/virtualMachines",
            "storageProfile": {"osDisk": {"osType": "Linux"}},
            "osProfile": {"linuxConfiguration": {"disablePasswordAuthentication": False}},  # -> AZ-018 HIGH
        },
    ],
}


def _key_for(args: Sequence[str]) -> str:
    """Derive a fixture key from an az argv, ignoring global flags/values."""
    skip_next = False
    parts: List[str] = []
    for tok in args[1:]:  # drop 'az'
        if skip_next:
            skip_next = False
            continue
        if tok in ("--subscription", "--resource-group", "--output", "-o"):
            skip_next = True
            continue
        if tok.startswith("-") and tok != "--all":
            continue
        parts.append(tok)
    return " ".join(parts)


def fake_az_runner(args: Sequence[str]) -> str:
    """Stand-in for base.default_runner: returns fixture JSON for known az commands."""
    key = _key_for(args)
    return json.dumps(_FIXTURES.get(key, []))


# --------------------------------------------------------------------------- AWS

from threatmap_live.live.base import CollectorError  # noqa: E402

_AWS_SG = {"SecurityGroups": [
    {"GroupId": "sg-1", "GroupName": "web",
     "IpPermissions": [
         {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},  # AWS-005/006
     ]},
]}

_AWS_RDS = {"DBInstances": [
    {"DBInstanceIdentifier": "db1", "DBInstanceArn": "arn:db1",
     "PubliclyAccessible": True,    # AWS-010
     "StorageEncrypted": False,     # AWS-011
     "DeletionProtection": False,   # AWS-012
     "BackupRetentionPeriod": 0},   # AWS-013
]}

_AWS_EC2 = {"Reservations": [{"Instances": [
    {"InstanceId": "i-1", "RootDeviceName": "/dev/xvda",
     "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-1"}}],
     "MetadataOptions": {"HttpTokens": "optional"}},  # AWS-022 (and AWS-021 via unencrypted vol-1)
]}]}
_AWS_VOLS = {"Volumes": [{"VolumeId": "vol-1", "Encrypted": False}]}

_AWS_TRAILS = {"trailList": [
    {"Name": "trail1", "TrailARN": "arn:trail1",
     "IsMultiRegionTrail": False,        # AWS-016
     "LogFileValidationEnabled": False}, # AWS-017
]}

_AWS_LAMBDA = {"Functions": [
    {"FunctionName": "fn1", "FunctionArn": "arn:fn1", "VpcConfig": {"SubnetIds": [], "VpcId": ""}},  # AWS-019
]}

_AWS_ROLES = {"Roles": [
    {"RoleName": "role1", "Path": "/", "Arn": "arn:role1",
     "AssumeRolePolicyDocument": {
         "Version": "2012-10-17",
         "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}],
     }},  # AWS-009
    # Service-linked role must be skipped (its trust policy is service-scoped by design).
    {"RoleName": "AWSServiceRoleForX", "Path": "/aws-service-role/", "Arn": "arn:slr",
     "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"Service": "x"}}]}},
]}

_AWS_BUCKETS = {"Buckets": [{"Name": "open-bucket"}]}

_AWS_EKS = {"cluster": {
    "name": "demo", "arn": "arn:eks",
    "resourcesVpcConfig": {"endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"]},  # AWS-014
    "encryptionConfig": None,  # AWS-015
}}


def _arg_after(args: Sequence[str], flag: str):
    for i, a in enumerate(args):
        if a == flag and i + 1 < len(args):
            return args[i + 1]
    return None


def fake_aws_runner(args: Sequence[str]) -> str:
    """Stand-in for base.default_runner for `aws` commands.

    Raises CollectorError for the optional sub-calls that the real CLI errors on
    when a setting is absent (e.g. no public-access-block), so the best-effort
    enrichment paths are exercised too.
    """
    a = list(args)
    if "describe-security-groups" in a:
        return json.dumps(_AWS_SG)
    if "describe-db-instances" in a:
        return json.dumps(_AWS_RDS)
    if "describe-instances" in a:
        return json.dumps(_AWS_EC2)
    if "describe-volumes" in a:
        return json.dumps(_AWS_VOLS)
    if "describe-trails" in a:
        return json.dumps(_AWS_TRAILS)
    if "list-functions" in a:
        return json.dumps(_AWS_LAMBDA)
    if "list-roles" in a:
        return json.dumps(_AWS_ROLES)
    if "list-buckets" in a:
        return json.dumps(_AWS_BUCKETS)
    if "get-public-access-block" in a:
        raise CollectorError("NoSuchPublicAccessBlockConfiguration")
    if "get-bucket-encryption" in a:
        raise CollectorError("ServerSideEncryptionConfigurationNotFoundError")
    if "get-bucket-versioning" in a or "get-bucket-logging" in a:
        return "{}"
    if "list-clusters" in a:
        return json.dumps({"clusters": ["demo"]})
    if "describe-cluster" in a:
        return json.dumps(_AWS_EKS)
    if "list-keys" in a:
        return json.dumps({"Keys": [{"KeyId": "cust-1"}, {"KeyId": "awsmanaged-1"}]})
    if "describe-key" in a:
        kid = _arg_after(a, "--key-id")
        if kid == "cust-1":
            return json.dumps({"KeyMetadata": {"KeyManager": "CUSTOMER", "Arn": "arn:cust-1"}})
        return json.dumps({"KeyMetadata": {"KeyManager": "AWS"}})
    if "get-key-rotation-status" in a:
        return json.dumps({"KeyRotationEnabled": False})
    return "{}"
