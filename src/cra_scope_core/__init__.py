"""CRA Scope Core — open-source toolkit for CRA Article 14 reporting.

This package implements the payload builders, validators, and reference data
needed to prepare EU Cyber Resilience Act (Regulation (EU) 2024/2847)
Article 14 notifications for the ENISA Single Reporting Platform (SRP).

It does NOT submit notifications on a manufacturer's behalf. ENISA SRP
authentication uses EU Login (CAS protocol), a closed government-issued
identity scheme. Article 14 reporting is the manufacturer's non-delegable
legal obligation (EC FAQ §4.6.1).

Public API:

    from cra_scope_core import (
        resolve_csirt,
        build_early_warning,
        build_vulnerability_notification,
        build_incident_notification,
        build_final_report,
        validate_notification,
        ValidationError,
    )

For the managed multi-tenant workflow platform (compliance clocks,
case management, dashboards, alerting, audit archive), see CRA Scope SaaS:
https://crascope.com
"""

from cra_scope_core.csirt import EU_CSIRT_MAP, resolve_csirt
from cra_scope_core.srp import (
    ValidationError,
    build_early_warning,
    build_final_report,
    build_incident_notification,
    build_vulnerability_notification,
    validate_notification,
)
from cra_scope_core.version import __version__

__all__ = [
    "__version__",
    "EU_CSIRT_MAP",
    "resolve_csirt",
    "ValidationError",
    "build_early_warning",
    "build_vulnerability_notification",
    "build_incident_notification",
    "build_final_report",
    "validate_notification",
]
