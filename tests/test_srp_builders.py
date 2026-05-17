"""Tests for SRP payload builders."""

import pytest

from cra_scope_core import (
    build_early_warning,
    build_final_report,
    build_incident_notification,
    build_vulnerability_notification,
)


COMMON = dict(
    manufacturer_name="ACME GmbH",
    manufacturer_country="DE",
    manufacturer_contact="security@acme.example",
    product_name="ACME Router",
    product_version="2.4.1",
    product_category="network",
    detection_timestamp="2026-05-17T10:00:00Z",
)


def test_early_warning_vulnerability_path():
    payload = build_early_warning(
        **COMMON,
        vulnerability_id="CVE-2026-12345",
        suspected_malicious=True,
        cross_border_impact=True,
        preliminary_description="Buffer overflow in firmware update handler.",
    )
    assert payload["notification_type"] == "early_warning"
    assert payload["cra_article"] == "14(2)(a)"
    assert payload["deadline_hours"] == 24
    assert payload["designated_csirt"]["id"] == "CSIRT-DE-001"
    assert payload["vulnerability"]["actively_exploited"] is True
    assert payload["vulnerability"]["suspected_malicious_action"] is True


def test_early_warning_severe_incident_path():
    payload = build_early_warning(
        **COMMON,
        vulnerability_id="INC-2026-001",
        suspected_malicious=False,
        cross_border_impact=False,
        report_subject_type="severe_incident",
    )
    assert payload["cra_article"] == "14(4)(a)"
    assert payload["report_subject_type"] == "severe_incident"
    assert payload["incident"]["severe_incident"] is True
    assert "vulnerability" not in payload


def test_vulnerability_notification():
    payload = build_vulnerability_notification(
        **COMMON,
        vulnerability_id="CVE-2026-12345",
        nature_of_vulnerability="Stack-based buffer overflow in CWE-121",
        severity_assessment="High",
        cvss_score=8.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        corrective_measures_applied=["Patch 2.4.2 released"],
    )
    assert payload["notification_type"] == "vulnerability_notification"
    assert payload["cra_article"] == "14(2)(b)"
    assert payload["deadline_hours"] == 72
    assert payload["vulnerability"]["cvss_score"] == 8.1


def test_incident_notification():
    payload = build_incident_notification(
        **COMMON,
        incident_id="INC-2026-001",
        incident_description="Ransomware deployed via supply-chain compromise.",
        severity_assessment="Severe",
        corrective_measures_applied=["Killswitch deployed"],
    )
    assert payload["notification_type"] == "incident_notification"
    assert payload["cra_article"] == "14(4)(b)"
    assert payload["report_subject_type"] == "severe_incident"


def test_final_report_vulnerability():
    payload = build_final_report(
        **COMMON,
        vulnerability_id="CVE-2026-12345",
        detailed_description="Detailed RCE analysis.",
        root_cause_analysis="Missing bounds check in parse_header().",
        security_update_available=True,
        security_update_url="https://acme.example/patches/2.4.2",
    )
    assert payload["notification_type"] == "final_report"
    assert payload["cra_article"] == "14(2)(c)"
    assert payload["deadline_days"] == 14
    assert payload["vulnerability"]["root_cause_analysis"]


def test_final_report_severe_incident_uses_1_month_article():
    payload = build_final_report(
        **COMMON,
        vulnerability_id="INC-2026-001",
        detailed_description="Full incident chronology.",
        threat_type="Ransomware",
        report_subject_type="severe_incident",
        deadline_days=30,
    )
    assert payload["cra_article"] == "14(4)(c)"
    assert payload["incident"]["severe_incident"] is True


def test_non_eu_country_still_builds_but_uses_placeholder_csirt():
    payload = build_early_warning(
        **{**COMMON, "manufacturer_country": "US"},
        vulnerability_id="CVE-2026-12345",
        suspected_malicious=False,
        cross_border_impact=False,
    )
    # Building always succeeds; validate_notification flags the country mismatch.
    assert payload["designated_csirt"]["id"] == "CSIRT-US-000"
