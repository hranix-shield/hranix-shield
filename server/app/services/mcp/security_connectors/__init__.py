from app.config import Settings
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors.clamav import (
    CLAMAV_CONNECTOR_NAME,
    ClamAvDbUpdateError,
    ClamAvFolderPickError,
    ClamAvNotConfiguredError,
    ClamAvPathNotAllowedError,
    ClamAvQuarantineNotFoundError,
    ClamAvRestoreConflictError,
    ClamAvScanJobRegistry,
    ClamdClient,
    ClamdError,
    QuarantineEntry,
    ScanJob,
    ScanResult,
    create_clamav_client,
    fetch_av_clamav_data,
    is_clamav_configured,
    list_quarantine_entries,
    list_scan_history,
    pick_scan_folder,
    quarantine_file,
    record_scan_history,
    register_clamav_connector,
    restore_quarantine_file,
    run_custom_scan,
    run_quick_scan,
    start_full_scan,
    update_clamav_databases,
)
from app.services.mcp.security_connectors.crowdsec import (
    CROWDSEC_CONNECTOR_NAME,
    CrowdSecAllowlistError,
    CrowdSecClient,
    CrowdSecError,
    CrowdSecNotConfiguredError,
    CrowdSecScenarioError,
    add_to_allowlist,
    apply_scenario_updates,
    ban_ip,
    check_scenario_updates,
    create_crowdsec_client,
    create_crowdsec_write_client,
    fetch_active_decision_values,
    fetch_allowlists,
    fetch_ids_console_data,
    ip_matches_any_decision,
    is_crowdsec_configured,
    is_crowdsec_write_configured,
    read_scenario_thresholds,
    register_crowdsec_connector,
    remove_from_allowlist,
    unban_decision,
    write_scenario_threshold,
)
from app.services.mcp.security_connectors.country_centroids import (
    country_centroid,
)
from app.services.mcp.security_connectors.geoip import (
    GEOIP_CONNECTOR_NAME,
    is_geoip_configured,
    register_geoip_connector,
    resolve_country,
    resolve_geoip_dir,
)
from app.services.mcp.security_connectors.os_disk_encryption import (
    OS_DISK_ENCRYPTION_CONNECTOR_NAME,
    OSDiskEncryptionError,
    fetch_disk_encryption_status,
    register_os_disk_encryption_connector,
)
from app.services.mcp.security_connectors.network_profile import (
    DEFAULT_CATEGORY,
    NETWORK_PROFILE_CONNECTOR_NAME,
    NetworkProfileError,
    create_default_network_profile_scheduler,
    detect_current_network,
    list_known_networks,
    network_profile_payload,
    register_network_profile_connector,
    run_network_profile_sweep,
    set_network_category,
    touch_network_profile,
)
from app.services.mcp.security_connectors.os_firewall import (
    OS_FIREWALL_CONNECTOR_NAME,
    OSFirewallError,
    block_all_incoming,
    block_ip,
    block_port,
    delete_blocked_ip,
    delete_blocked_port,
    fetch_firewall_rules,
    fetch_firewall_status,
    list_blocked_ips,
    list_blocked_ports,
    read_firewall_rules,
    record_blocked_ip,
    record_blocked_port,
    register_os_firewall_connector,
    unblock_all_incoming,
    unblock_ip,
    unblock_port,
)
from app.services.mcp.security_connectors.os_processes import (
    OSProcessError,
    terminate_process,
)
from app.services.mcp.security_connectors.osquery import (
    OSQUERY_CONNECTOR_NAME,
    OsqueryError,
    fetch_av_osquery_data,
    fetch_listening_ports,
    fetch_network_console_data,
    register_osquery_connector,
)
from app.services.mcp.security_connectors.traffic_counters import (
    TRAFFIC_COUNTERS_CONNECTOR_NAME,
    TrafficCounterError,
    TrafficCounterRegistry,
    fetch_traffic_counters,
    register_traffic_counters_connector,
)
from app.services.mcp.security_connectors.wazuh import (
    WAZUH_CONNECTOR_NAME,
    WazuhClient,
    WazuhError,
    WazuhNotConfiguredError,
    create_wazuh_client,
    fetch_logs_console_data,
    is_wazuh_configured,
    register_wazuh_connector,
    trigger_syscheck_scan,
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
    the Wazuh Manager REST API). A-39 adds `os_counters`, `network`'s second
    source (per-process traffic volume, joined onto osquery's `connections`
    rows — see traffic_counters.py and security_console.py._network_payload).
    A-40 adds `geoip`, a purely local file
    lookup (never a live external service — see that module's docstring)
    enriching `network`'s `connections` rows with a country code; it has
    no `connector.status` of its own in that console's API response (see
    `security_console.py._network_payload`), registered here anyway so it
    still shows up in a future "Плагины/MCP-коннекторы" settings screen
    like every other connector in this stack. A-38 adds `network_profile`,
    the `perimeter` console's own new source for "which network am I on
    right now" (see network_profile.py's docstring) — independent of every
    connector above it, not layered on top of any of them.
    """
    register_crowdsec_connector(registry, settings=settings)
    register_os_firewall_connector(registry)
    register_os_disk_encryption_connector(registry)
    register_osquery_connector(registry)
    register_clamav_connector(registry, settings=settings)
    register_wazuh_connector(registry, settings=settings)
    register_traffic_counters_connector(registry)
    register_geoip_connector(registry, settings=settings)
    register_network_profile_connector(registry)


__all__ = [
    "CLAMAV_CONNECTOR_NAME",
    "ClamAvDbUpdateError",
    "ClamAvFolderPickError",
    "ClamAvNotConfiguredError",
    "ClamAvPathNotAllowedError",
    "ClamAvQuarantineNotFoundError",
    "ClamAvRestoreConflictError",
    "ClamAvScanJobRegistry",
    "ClamdClient",
    "ClamdError",
    "QuarantineEntry",
    "ScanJob",
    "ScanResult",
    "create_clamav_client",
    "fetch_av_clamav_data",
    "is_clamav_configured",
    "list_quarantine_entries",
    "pick_scan_folder",
    "quarantine_file",
    "register_clamav_connector",
    "restore_quarantine_file",
    "run_quick_scan",
    "start_full_scan",
    "update_clamav_databases",
    "CROWDSEC_CONNECTOR_NAME",
    "CrowdSecAllowlistError",
    "CrowdSecClient",
    "CrowdSecError",
    "CrowdSecNotConfiguredError",
    "CrowdSecScenarioError",
    "add_to_allowlist",
    "apply_scenario_updates",
    "ban_ip",
    "check_scenario_updates",
    "create_crowdsec_client",
    "create_crowdsec_write_client",
    "fetch_active_decision_values",
    "fetch_allowlists",
    "fetch_ids_console_data",
    "ip_matches_any_decision",
    "is_crowdsec_configured",
    "is_crowdsec_write_configured",
    "read_scenario_thresholds",
    "register_crowdsec_connector",
    "remove_from_allowlist",
    "unban_decision",
    "write_scenario_threshold",
    "GEOIP_CONNECTOR_NAME",
    "is_geoip_configured",
    "register_geoip_connector",
    "resolve_country",
    "resolve_geoip_dir",
    "country_centroid",
    "OS_DISK_ENCRYPTION_CONNECTOR_NAME",
    "OSDiskEncryptionError",
    "fetch_disk_encryption_status",
    "register_os_disk_encryption_connector",
    "NETWORK_PROFILE_CONNECTOR_NAME",
    "DEFAULT_CATEGORY",
    "NetworkProfileError",
    "create_default_network_profile_scheduler",
    "detect_current_network",
    "list_known_networks",
    "network_profile_payload",
    "register_network_profile_connector",
    "run_network_profile_sweep",
    "set_network_category",
    "touch_network_profile",
    "OS_FIREWALL_CONNECTOR_NAME",
    "OSFirewallError",
    "block_all_incoming",
    "block_ip",
    "block_port",
    "delete_blocked_ip",
    "delete_blocked_port",
    "fetch_firewall_rules",
    "fetch_firewall_status",
    "list_blocked_ips",
    "list_blocked_ports",
    "read_firewall_rules",
    "record_blocked_ip",
    "record_blocked_port",
    "register_os_firewall_connector",
    "unblock_all_incoming",
    "unblock_ip",
    "unblock_port",
    "OSProcessError",
    "terminate_process",
    "OSQUERY_CONNECTOR_NAME",
    "OsqueryError",
    "fetch_av_osquery_data",
    "fetch_listening_ports",
    "fetch_network_console_data",
    "register_osquery_connector",
    "TRAFFIC_COUNTERS_CONNECTOR_NAME",
    "TrafficCounterError",
    "TrafficCounterRegistry",
    "fetch_traffic_counters",
    "register_traffic_counters_connector",
    "WAZUH_CONNECTOR_NAME",
    "WazuhClient",
    "WazuhError",
    "WazuhNotConfiguredError",
    "create_wazuh_client",
    "fetch_logs_console_data",
    "is_wazuh_configured",
    "register_wazuh_connector",
    "trigger_syscheck_scan",
    "register_default_security_connectors",
]
