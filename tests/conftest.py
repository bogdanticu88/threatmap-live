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
