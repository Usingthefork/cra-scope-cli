"""Tests for the SRP payload validator."""

import pytest

from cra_scope_core import (
    ValidationError,
    build_early_warning,
    build_final_report,
    build_incident_notification,
    build_vulnerability_notification,
    validate_notification,
)
from cra_scope_core.srp import assert_valid


COMMON = dict(
    manufacturer_name="ACME GmbH",
    manufacturer_country="DE",
    manufacturer_contact="security@acme.example",
    product_name="ACME Router",
    product_version="2.4.1",
    product_category="network",
    detection_timestamp="2026-05-17T10:00:00Z",
)


def test_valid_early_warning_passes():
    payload = build_early_warning(
        **COMMON,
        vulnerability_id="CVE-2026-12345",
        suspected_malicious=True,
        cross_border_impact=True,
    )
    assert validate_notification(payload) == []


def test_valid_vulnerability_notification_passes():
    payload = build_vulnerability_notification(
        **COMMON,
        vulnerability_id="CVE-2026-12345",
        nature_of_vulnerability="Buffer overflow",
        severity_assessment="High",
        corrective_measures_applied=["Patch released"],
    )
    assert validate_notification(payload) == []


def test_valid_incident_notification_passes():
    payload = build_incident_notification(
        **COMMON,
        incident_id="INC-2026-001",
        incident_description="Ransomware.",
        severity_assessment="Severe",
        corrective_measures_applied=["Killswitch"],
    )
    assert validate_notification(payload) == []


def test_valid_final_report_passes():
    payload = build_final_report(
        **COMMON,
        vulnerability_id="CVE-2026-12345",
        detailed_description="Detailed analysis.",
        root_cause_analysis="Bounds check missing.",
    )
    assert validate_notification(payload) == []


def test_unknown_notification_type_fails_fast():
    errors = validate_notification({"notification_type": "bogus"})
    assert len(errors) == 1
    assert "Invalid notification_type" in errors[0]


def test_non_eu_country_is_flagged():
    payload = build_early_warning(
        **{**COMMON, "manufacturer_country": "US"},
        vulnerability_id="CVE-2026-12345",
        suspected_malicious=True,
        cross_border_impact=True,
    )
    errors = validate_notification(payload)
    assert any("not a recognized EU Member State" in e for e in errors)


def test_early_warning_missing_malicious_flag_is_flagged():
    payload = build_early_warning(
        **COMMON,
        vulnerability_id="CVE-2026-12345",
        suspected_malicious=None,
        cross_border_impact=True,
    )
    errors = validate_notification(payload)
    assert any("suspected_malicious_action" in e for e in errors)


def test_vulnerability_notification_requires_corrective_measure():
    payload = build_vulnerability_notification(
        **COMMON,
        vulnerability_id="CVE-2026-12345",
        nature_of_vulnerability="Buffer overflow",
        severity_assessment="High",
    )
    errors = validate_notification(payload)
    assert any("corrective measure" in e for e in errors)


def test_final_report_requires_root_cause_or_threat_type():
    payload = build_final_report(
        **COMMON,
        vulnerability_id="CVE-2026-12345",
        detailed_description="Some description.",
    )
    errors = validate_notification(payload)
    assert any("root_cause_analysis or threat_type" in e for e in errors)


def test_assert_valid_raises_validation_error():
    bad_payload = {"notification_type": "early_warning"}
    with pytest.raises(ValidationError) as excinfo:
        assert_valid(bad_payload)
    assert excinfo.value.errors  # non-empty
