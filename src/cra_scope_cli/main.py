"""cra-scope command-line interface.

Run ``cra-scope --help`` for top-level commands.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

import click

from cra_scope_core import (
    __version__,
    build_early_warning,
    build_final_report,
    build_incident_notification,
    build_vulnerability_notification,
    resolve_csirt,
    validate_notification,
)
from cra_scope_core.csirt import EU_CSIRT_MAP, is_eu_member_state
from cra_scope_core.kev import lookup_cve

SAAS_URL = "https://crascope.eu"


def _emit_json(payload: dict[str, Any], output: Optional[str]) -> None:
    text = json.dumps(payload, indent=2, sort_keys=False, default=str)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        click.echo(f"Wrote {output}", err=True)
    else:
        click.echo(text)


def _csv(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


@click.group(
    help=(
        "Open-source toolkit for preparing EU Cyber Resilience Act (CRA, "
        "Regulation 2024/2847) Article 14 notifications.\n\n"
        f"For managed compliance workflows, see {SAAS_URL}."
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(__version__, prog_name="cra-scope")
def cli() -> None:
    pass


# ---------------------------------------------------------------------------
# csirt
# ---------------------------------------------------------------------------

@cli.command("csirt")
@click.argument("country_code")
def csirt_cmd(country_code: str) -> None:
    """Resolve the designated CSIRT for an EU Member State.

    Example: cra-scope csirt DE
    """
    info = resolve_csirt(country_code)
    if not is_eu_member_state(country_code):
        click.echo(
            f"WARNING: {country_code!r} is not a recognized EU Member State. "
            "CRA Art. 14 reporting requires an EU main establishment.",
            err=True,
        )
    click.echo(json.dumps({"country": country_code.upper(), **info}, indent=2))


@cli.command("csirts")
def csirts_cmd() -> None:
    """List all 27 EU Member State CSIRTs."""
    rows = [{"country": cc, **info} for cc, info in sorted(EU_CSIRT_MAP.items())]
    click.echo(json.dumps(rows, indent=2))


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

@cli.group("build")
def build_group() -> None:
    """Build CRA Article 14 notification payloads."""


_COMMON_OPTS = [
    click.option("--manufacturer-name", required=True),
    click.option("--manufacturer-country", required=True, help="ISO 3166-1 alpha-2"),
    click.option("--manufacturer-contact", required=True, help="contact email"),
    click.option("--product-name", required=True),
    click.option("--product-version", required=True),
    click.option("--product-category", default=""),
    click.option("--detection-timestamp", required=True, help="ISO 8601 UTC"),
    click.option("--out", "-o", default=None, help="Write payload to file (default: stdout)"),
]


def _apply(opts):
    def decorator(fn):
        for opt in reversed(opts):
            fn = opt(fn)
        return fn
    return decorator


@build_group.command("early-warning")
@_apply(_COMMON_OPTS)
@click.option("--vulnerability-id", required=True, help="e.g. CVE-2025-12345")
@click.option("--suspected-malicious", type=bool, required=True)
@click.option("--cross-border-impact", type=bool, required=True)
@click.option("--preliminary-description", default="")
@click.option("--affected-member-states", default="", help="comma-separated codes")
@click.option(
    "--report-subject-type",
    type=click.Choice(["vulnerability", "severe_incident"]),
    default="vulnerability",
)
def build_early_warning_cmd(
    manufacturer_name: str,
    manufacturer_country: str,
    manufacturer_contact: str,
    product_name: str,
    product_version: str,
    product_category: str,
    detection_timestamp: str,
    out: Optional[str],
    vulnerability_id: str,
    suspected_malicious: bool,
    cross_border_impact: bool,
    preliminary_description: str,
    affected_member_states: str,
    report_subject_type: str,
) -> None:
    """Build a 24-hour Early Warning (Art. 14(2)(a) / 14(4)(a))."""
    payload = build_early_warning(
        manufacturer_name=manufacturer_name,
        manufacturer_country=manufacturer_country,
        manufacturer_contact=manufacturer_contact,
        product_name=product_name,
        product_version=product_version,
        product_category=product_category,
        vulnerability_id=vulnerability_id,
        detection_timestamp=detection_timestamp,
        suspected_malicious=suspected_malicious,
        cross_border_impact=cross_border_impact,
        preliminary_description=preliminary_description,
        affected_member_states=_csv(affected_member_states),
        report_subject_type=report_subject_type,
    )
    _emit_json(payload, out)


@build_group.command("vuln-notification")
@_apply(_COMMON_OPTS)
@click.option("--vulnerability-id", required=True)
@click.option("--nature-of-vulnerability", required=True)
@click.option("--severity-assessment", required=True)
@click.option("--cvss-score", type=float, default=None)
@click.option("--cvss-vector", default="")
@click.option("--exploitation-details", default="")
@click.option("--corrective-measures-applied", default="", help="comma-separated")
@click.option("--corrective-measures-planned", default="", help="comma-separated")
@click.option("--user-guidance", default="")
@click.option("--publicly-known", is_flag=True, default=False)
@click.option("--public-references", default="", help="comma-separated URLs")
@click.option("--cross-border-impact", type=bool, default=None)
@click.option("--affected-member-states", default="")
@click.option("--early-warning-reference", default=None)
def build_vuln_cmd(**kw: Any) -> None:
    """Build a 72-hour Vulnerability Notification (Art. 14(2)(b))."""
    out = kw.pop("out")
    kw["corrective_measures_applied"] = _csv(kw.pop("corrective_measures_applied"))
    kw["corrective_measures_planned"] = _csv(kw.pop("corrective_measures_planned"))
    kw["public_references"] = _csv(kw.pop("public_references"))
    kw["affected_member_states"] = _csv(kw.pop("affected_member_states"))
    payload = build_vulnerability_notification(**kw)
    _emit_json(payload, out)


@build_group.command("incident-notification")
@_apply(_COMMON_OPTS)
@click.option("--incident-id", required=True)
@click.option("--incident-description", required=True)
@click.option("--severity-assessment", required=True)
@click.option("--impact-assessment", default="")
@click.option("--estimated-affected-users", type=int, default=None)
@click.option("--corrective-measures-applied", default="")
@click.option("--corrective-measures-planned", default="")
@click.option("--user-guidance", default="")
@click.option("--cross-border-impact", type=bool, default=None)
@click.option("--affected-member-states", default="")
@click.option("--early-warning-reference", default=None)
def build_incident_cmd(**kw: Any) -> None:
    """Build a 72-hour severe Incident Notification (Art. 14(4)(b))."""
    out = kw.pop("out")
    kw["corrective_measures_applied"] = _csv(kw.pop("corrective_measures_applied"))
    kw["corrective_measures_planned"] = _csv(kw.pop("corrective_measures_planned"))
    kw["affected_member_states"] = _csv(kw.pop("affected_member_states"))
    payload = build_incident_notification(**kw)
    _emit_json(payload, out)


@build_group.command("final-report")
@_apply(_COMMON_OPTS)
@click.option("--vulnerability-id", required=True)
@click.option("--detailed-description", required=True)
@click.option(
    "--report-subject-type",
    type=click.Choice(["vulnerability", "severe_incident"]),
    default="vulnerability",
)
@click.option("--severity-assessment", default="")
@click.option("--root-cause-analysis", default="")
@click.option("--threat-type", default="")
@click.option("--security-update-url", default="")
@click.option("--security-update-available", is_flag=True, default=False)
@click.option("--user-guidance", default="")
@click.option("--lessons-learned", default="")
@click.option("--cross-border-impact", type=bool, default=None)
@click.option("--affected-member-states", default="")
@click.option("--deadline-days", type=int, default=14)
@click.option("--early-warning-reference", default=None)
@click.option("--notification-reference", default=None)
def build_final_cmd(**kw: Any) -> None:
    """Build a Final Report (Art. 14(2)(c) — 14 days, or 14(4)(c) — 1 month)."""
    out = kw.pop("out")
    kw["affected_member_states"] = _csv(kw.pop("affected_member_states"))
    payload = build_final_report(**kw)
    _emit_json(payload, out)


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

@cli.command("validate")
@click.argument("payload_file", type=click.Path(exists=True, dir_okay=False, readable=True))
def validate_cmd(payload_file: str) -> None:
    """Validate an SRP notification payload JSON file."""
    payload = json.loads(Path(payload_file).read_text(encoding="utf-8"))
    errors = validate_notification(payload)
    if not errors:
        click.echo("OK: payload is valid.")
        return
    click.echo(f"INVALID: {len(errors)} error(s) found:", err=True)
    for err in errors:
        click.echo(f"  - {err}", err=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# kev-check
# ---------------------------------------------------------------------------

@cli.command("kev-check")
@click.argument("cve_id")
def kev_check_cmd(cve_id: str) -> None:
    """Look up a CVE in the CISA Known Exploited Vulnerabilities catalogue.

    A KEV hit is a strong signal for the CRA Art. 14(2)(a) "actively
    exploited" 24-hour reporting trigger.
    """
    try:
        entry = lookup_cve(cve_id)
    except Exception as exc:  # network / parse errors
        click.echo(f"ERROR: could not fetch KEV catalogue: {exc}", err=True)
        sys.exit(2)

    if entry is None:
        click.echo(json.dumps({"cve": cve_id.upper(), "kev_listed": False}, indent=2))
        return

    click.echo(
        json.dumps(
            {
                "cve": cve_id.upper(),
                "kev_listed": True,
                "vendor_project": entry.get("vendorProject"),
                "product": entry.get("product"),
                "vulnerability_name": entry.get("vulnerabilityName"),
                "date_added": entry.get("dateAdded"),
                "short_description": entry.get("shortDescription"),
                "required_action": entry.get("requiredAction"),
                "due_date": entry.get("dueDate"),
                "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    cli()
