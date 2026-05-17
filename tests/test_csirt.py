"""Tests for the EU CSIRT resolver."""

from cra_scope_core.csirt import EU_CSIRT_MAP, is_eu_member_state, resolve_csirt


def test_eu_csirt_map_has_27_member_states():
    assert len(EU_CSIRT_MAP) == 27


def test_resolve_csirt_known_country():
    info = resolve_csirt("DE")
    assert info["name"] == "BSI CERT-Bund"
    assert info["id"] == "CSIRT-DE-001"


def test_resolve_csirt_is_case_insensitive():
    assert resolve_csirt("de") == resolve_csirt("DE") == resolve_csirt(" De ")


def test_resolve_csirt_non_eu_returns_placeholder():
    info = resolve_csirt("US")
    assert info["id"] == "CSIRT-US-000"
    assert "US" in info["name"]


def test_is_eu_member_state():
    assert is_eu_member_state("FR") is True
    assert is_eu_member_state("fr") is True
    assert is_eu_member_state("GB") is False
    assert is_eu_member_state("US") is False
