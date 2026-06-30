"""
Azure live collector.

Runs read-only `az ... list` commands (under the operator's existing `az login`
session) and maps the results into threatmap's `Resource` model using the SAME
Terraform `azurerm_*` type names and property keys the Azure analyzer expects
(see threatmap/analyzers/azure.py). This is what lets the unchanged engine fire
its existing AZ-### rules against live deployed infrastructure.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence

from threatmap.models.resource import Resource

from threatmap_live.live.base import BaseCollector, CollectionResult, CollectorError
from threatmap_live.live._util import deep, first_str, pick

Mapper = Callable[[Dict[str, Any]], Optional[Resource]]


def _resource(elem: Dict[str, Any], tf_type: str, props: Dict[str, Any]) -> Resource:
    return Resource(
        provider="azure",
        resource_type=tf_type,
        name=elem.get("name") or elem.get("id") or "<unnamed>",
        properties=props,
        source_format="azure-live",
        source_file=elem.get("id", ""),
        exposure="unknown",
    )


def _net_block(raw: Any) -> Optional[Dict[str, Any]]:
    """Map an ARM networkAcls/networkRuleSet object to the terraform-shaped block."""
    if not isinstance(raw, dict):
        return None
    return {"default_action": raw.get("defaultAction") or raw.get("default_action")}


# --------------------------------------------------------------------------- mappers

def map_storage_account(e: Dict[str, Any]) -> Optional[Resource]:
    return _resource(e, "azurerm_storage_account", {
        "allow_blob_public_access": pick(e, "allowBlobPublicAccess", "allowNestedItemsToBePublic"),
        "min_tls_version": pick(e, "minimumTlsVersion"),
        "enable_https_traffic_only": pick(e, "enableHttpsTrafficOnly", "supportsHttpsTrafficOnly"),
        "network_rules": _net_block(pick(e, "networkRuleSet", "networkAcls")),
    })


def map_key_vault(e: Dict[str, Any]) -> Optional[Resource]:
    return _resource(e, "azurerm_key_vault", {
        "purge_protection_enabled": pick(e, "enablePurgeProtection"),
        "network_acls": _net_block(pick(e, "networkAcls")),
    })


def map_nsg(e: Dict[str, Any]) -> Optional[Resource]:
    rules_raw = pick(e, "securityRules", default=[]) or []
    rules: List[Dict[str, Any]] = []
    for r in rules_raw:
        if not isinstance(r, dict):
            continue
        rules.append({
            "direction": pick(r, "direction"),
            "access": pick(r, "access"),
            "source_address_prefix": pick(r, "sourceAddressPrefix")
            or first_str(r, "sourceAddressPrefix", "sourceAddressPrefixes", default=""),
            "destination_port_range": first_str(r, "destinationPortRange", "destinationPortRanges"),
        })
    return _resource(e, "azurerm_network_security_group", {"security_rule": rules})


def map_role_assignment(e: Dict[str, Any]) -> Optional[Resource]:
    res = _resource(e, "azurerm_role_assignment", {
        "role_definition_name": e.get("roleDefinitionName"),
        "scope": e.get("scope"),
    })
    # Role assignments have GUID names; prefer the principal for a readable label.
    res.name = e.get("principalName") or e.get("roleDefinitionName") or res.name
    return res


def map_acr(e: Dict[str, Any]) -> Optional[Resource]:
    return _resource(e, "azurerm_container_registry", {
        "admin_enabled": pick(e, "adminUserEnabled"),
    })


def map_sql_server(e: Dict[str, Any]) -> Optional[Resource]:
    pna = pick(e, "publicNetworkAccess")
    # Analyzer compares against the string "false"; translate the ARM enum.
    if isinstance(pna, str):
        enabled: Any = False if pna.lower() == "disabled" else True
    else:
        enabled = pna  # already bool/None
    return _resource(e, "azurerm_mssql_server", {
        "public_network_access_enabled": enabled,
    })


def map_aks(e: Dict[str, Any]) -> Optional[Resource]:
    return _resource(e, "azurerm_kubernetes_cluster", {
        "role_based_access_control_enabled": pick(e, "enableRbac"),
        "api_server_authorized_ip_ranges": deep(e, "apiServerAccessProfile.authorizedIpRanges"),
    })


def map_webapp(e: Dict[str, Any]) -> Optional[Resource]:
    kind = (e.get("kind") or "").lower()
    tf_type = "azurerm_linux_web_app" if "linux" in kind else "azurerm_windows_web_app"
    return _resource(e, tf_type, {
        "https_only": pick(e, "httpsOnly"),
        "identity": e.get("identity"),
    })


def map_linux_vm(e: Dict[str, Any]) -> Optional[Resource]:
    os_type = str(deep(e, "storageProfile.osDisk.osType") or "").lower()
    linux_cfg = deep(e, "osProfile.linuxConfiguration")
    if os_type != "linux" and linux_cfg is None:
        return None  # only Linux VMs have a corresponding analyzer rule
    return _resource(e, "azurerm_linux_virtual_machine", {
        "disable_password_authentication": deep(e, "osProfile.linuxConfiguration.disablePasswordAuthentication"),
    })


class _Service:
    __slots__ = ("name", "args", "mapper", "supports_rg")

    def __init__(self, name: str, args: Sequence[str], mapper: Mapper, supports_rg: bool = True):
        self.name = name
        self.args = list(args)
        self.mapper = mapper
        self.supports_rg = supports_rg


# Order roughly by blast radius. Each entry is one read-only `az` list command.
SERVICES: List[_Service] = [
    _Service("storage accounts", ["storage", "account", "list"], map_storage_account),
    _Service("key vaults", ["keyvault", "list"], map_key_vault),
    _Service("network security groups", ["network", "nsg", "list"], map_nsg),
    _Service("role assignments", ["role", "assignment", "list", "--all"], map_role_assignment, supports_rg=False),
    _Service("container registries", ["acr", "list"], map_acr),
    _Service("sql servers", ["sql", "server", "list"], map_sql_server),
    _Service("aks clusters", ["aks", "list"], map_aks),
    _Service("web apps", ["webapp", "list"], map_webapp),
    _Service("virtual machines", ["vm", "list"], map_linux_vm),
]


class AzureCollector(BaseCollector):
    cli_name = "az"

    def __init__(self, subscription: Optional[str] = None, resource_group: Optional[str] = None, runner=None):
        if runner is not None:
            super().__init__(runner)
        else:
            super().__init__()
        self.subscription = subscription
        self.resource_group = resource_group

    def _build_args(self, svc: _Service) -> List[str]:
        args = ["az", *svc.args]
        if self.subscription:
            args += ["--subscription", self.subscription]
        if self.resource_group and svc.supports_rg:
            args += ["--resource-group", self.resource_group]
        args += ["--output", "json"]
        return args

    def collect(self) -> CollectionResult:
        result = CollectionResult()
        for svc in SERVICES:
            args = self._build_args(svc)
            try:
                items = self._json(args)
            except CollectorError as exc:
                # One unreachable/forbidden service should not abort the whole scan.
                result.warnings.append(f"{svc.name}: {exc}")
                continue
            if not isinstance(items, list):
                items = [items]
            for elem in items:
                if not isinstance(elem, dict):
                    continue
                try:
                    mapped = svc.mapper(elem)
                except Exception as exc:  # noqa: BLE001 - defensive: never let one bad record kill the run
                    result.warnings.append(f"{svc.name}: failed to map a resource: {exc}")
                    continue
                if mapped is not None:
                    result.resources.append(mapped)
        return result
