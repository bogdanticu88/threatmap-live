"""
Tests for the Azure live collector.

The point of these tests is the *contract* with threatmap: the collector must map
live `az` JSON into resources that make the unchanged threatmap engine fire its
existing AZ-### rules. So we assert both the mapping and the resulting findings.
"""
from threatmap.analyzers import engine

from threatmap_live.live.azure import AzureCollector
from tests.conftest import fake_az_runner


def _collect():
    return AzureCollector(subscription="sub-1", runner=fake_az_runner).collect()


def test_collects_all_service_types():
    result = _collect()
    types = {r.resource_type for r in result.resources}
    assert {
        "azurerm_storage_account",
        "azurerm_key_vault",
        "azurerm_network_security_group",
        "azurerm_role_assignment",
        "azurerm_container_registry",
        "azurerm_mssql_server",
        "azurerm_kubernetes_cluster",
        "azurerm_linux_web_app",
        "azurerm_linux_virtual_machine",
    }.issubset(types)
    assert not result.warnings


def test_storage_account_mapping_shape():
    result = _collect()
    insecure = next(r for r in result.resources if r.name == "insecurestg")
    # Mapped to terraform property keys the analyzer reads.
    assert insecure.properties["allow_blob_public_access"] is True
    assert insecure.properties["min_tls_version"] == "TLS1_0"
    assert insecure.properties["enable_https_traffic_only"] is False
    assert insecure.properties["network_rules"] == {"default_action": "Allow"}
    assert insecure.provider == "azure"
    assert insecure.source_format == "azure-live"


def test_engine_fires_expected_rules_on_live_resources():
    result = _collect()
    threats = engine.run(result.resources, framework="stride")
    descriptions = " ".join(t.description for t in threats)

    # A representative finding from each mapped service type.
    assert "allows public blob access" in descriptions          # AZ-001 storage
    assert "purge protection" in descriptions                    # AZ-005 key vault
    assert "SSH/RDP" in descriptions                             # AZ-008 nsg
    assert "privileged role 'Owner'" in descriptions             # AZ-009 role assignment
    assert "admin user enabled" in descriptions                  # AZ-015 acr
    assert "public network access enabled" in descriptions       # AZ-016 sql server
    assert "RBAC disabled" in descriptions                       # AZ-013 aks
    assert "HTTPS-only" in descriptions                          # AZ-011 web app
    assert "password authentication" in descriptions             # AZ-018 linux vm

    # Severity sanity: the SSH-open NSG must yield a CRITICAL.
    assert any(t.severity.value == "CRITICAL" for t in threats)


def test_clean_storage_account_produces_no_findings():
    result = _collect()
    threats = engine.run(result.resources, framework="stride")
    secure_findings = [t for t in threats if t.resource_name == "securestg"]
    assert secure_findings == []


def test_sql_public_access_enum_translation():
    # "Enabled" -> not "false" -> AZ-016 fires; ensure the enum->bool mapping holds.
    result = _collect()
    sql = next(r for r in result.resources if r.resource_type == "azurerm_mssql_server")
    assert sql.properties["public_network_access_enabled"] is True


def test_one_failing_service_does_not_abort_scan():
    from threatmap_live.live.base import CollectorError

    def flaky_runner(args):
        if "keyvault" in args:
            raise CollectorError("AuthorizationFailed: caller lacks read on key vaults")
        return fake_az_runner(args)

    result = AzureCollector(subscription="sub-1", runner=flaky_runner).collect()
    assert any("key vaults" in w for w in result.warnings)
    # Other services still collected.
    assert any(r.resource_type == "azurerm_storage_account" for r in result.resources)
