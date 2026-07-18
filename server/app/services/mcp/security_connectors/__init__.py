from app.config import Settings
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors.clamav import (
    CLAMAV_CONNECTOR_NAME,
    ClamAvNotConfiguredError,
    ClamAvPathNotAllowedError,
    ClamAvScanJobRegistry,
    ClamdClient,
    ClamdError,
    ScanJob,
    ScanResult,
    create_clamav_client,
    fetch_av_clamav_data,
    is_clamav_configured,
    quarantine_file,
    register_clamav_connector,
    run_quick_scan,
    start_full_scan,
)
from app.services.mcp.security_connectors.crowdsec import (
    CROWDSEC_CONNECTOR_NAME,
    CrowdSecClient,
    CrowdSecError,
    create_crowdsec_client,
    fetch_ids_console_data,
    is_crowdsec_configured,
    register_crowdsec_connector,
)
from app.services.mcp.security_connectors.os_disk_encryption import (
    OS_DISK_ENCRYPTION_CONNECTOR_NAME,
    OSDiskEncryptionError,
    fetch_disk_encryption_status,
    register_os_disk_encryption_connector,
)
from app.services.mcp.security_connectors.os_firewall import (
    OS_FIREWALL_CONNECTOR_NAME,
    OSFirewallError,
    fetch_firewall_status,
    register_os_firewall_connector,
)
from app.services.mcp.security_connectors.osquery import (
    OSQUERY_CONNECTOR_NAME,
    OsqueryError,
    fetch_av_osquery_data,
    fetch_network_console_data,
    register_osquery_connector,
)
from app.services.mcp.security_connectors.wazuh import (
    WAZUH_CONNECTOR_NAME,
    WazuhClient,
    WazuhError,
    create_wazuh_client,
    fetch_logs_console_data,
    is_wazuh_configured,
    register_wazuh_connector,
)


def register_default_security_connectors(
    registry: MCPRegistry, *, settings: Settings | None = None
) -> None:
    """Wires Phase 0's real security connectors onto `registry`. Called once
    per app instance from `app_factory.create_app()`, mirroring
    `health.checks.register_default_checks` /
    `event_bus.register_default_subscribers`.

    CrowdSec (A-11) was the first; A-18 added the two local OS-tool
    connectors (`os_firewall`, `os_disk_encryption`) that, together with
    CrowdSec's bouncer (reused, not duplicated — see `security_console.py`),
    feed the `perimeter` console. A-15 adds `osquery`, feeding `network`
    (its sole source) and the first source of `av`'s `connectors` dict.
    A-17 adds `clamav`, the second source of `av`'s `connectors` dict.
    A-16 adds `wazuh`, the `logs` console's sole source (FIM findings via
    the Wazuh Manager REST API).
    """
    register_crowdsec_connector(registry, settings=settings)
    register_os_firewall_connector(registry)
    register_os_disk_encryption_connector(registry)
    register_osquery_connector(registry)
    register_clamav_connector(registry, settings=settings)
    register_wazuh_connector(registry, settings=settings)


__all__ = [
    "CLAMAV_CONNECTOR_NAME",
    "ClamAvNotConfiguredError",
    "ClamAvPathNotAllowedError",
    "ClamAvScanJobRegistry",
    "ClamdClient",
    "ClamdError",
    "ScanJob",
    "ScanResult",
    "create_clamav_client",
    "fetch_av_clamav_data",
    "is_clamav_configured",
    "quarantine_file",
    "register_clamav_connector",
    "run_quick_scan",
    "start_full_scan",
    "CROWDSEC_CONNECTOR_NAME",
    "CrowdSecClient",
    "CrowdSecError",
    "create_crowdsec_client",
    "fetch_ids_console_data",
    "is_crowdsec_configured",
    "register_crowdsec_connector",
    "OS_DISK_ENCRYPTION_CONNECTOR_NAME",
    "OSDiskEncryptionError",
    "fetch_disk_encryption_status",
    "register_os_disk_encryption_connector",
    "OS_FIREWALL_CONNECTOR_NAME",
    "OSFirewallError",
    "fetch_firewall_status",
    "register_os_firewall_connector",
    "OSQUERY_CONNECTOR_NAME",
    "OsqueryError",
    "fetch_av_osquery_data",
    "fetch_network_console_data",
    "register_osquery_connector",
    "WAZUH_CONNECTOR_NAME",
    "WazuhClient",
    "WazuhError",
    "create_wazuh_client",
    "fetch_logs_console_data",
    "is_wazuh_configured",
    "register_wazuh_connector",
    "register_default_security_connectors",
]
