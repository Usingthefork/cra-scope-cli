"""End-to-end CLI tests using Click's CliRunner."""

import json

from click.testing import CliRunner

from cra_scope_cli.main import cli


def test_help():
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Cyber Resilience Act" in result.output


def test_version():
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0


def test_csirt_lookup():
    result = CliRunner().invoke(cli, ["csirt", "DE"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["country"] == "DE"
    assert data["id"] == "CSIRT-DE-001"


def test_csirts_lists_27():
    result = CliRunner().invoke(cli, ["csirts"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data) == 27


def test_build_early_warning_then_validate(tmp_path):
    runner = CliRunner()
    out_file = tmp_path / "ew.json"
    result = runner.invoke(
        cli,
        [
            "build", "early-warning",
            "--manufacturer-name", "ACME GmbH",
            "--manufacturer-country", "DE",
            "--manufacturer-contact", "security@acme.example",
            "--product-name", "ACME Router",
            "--product-version", "2.4.1",
            "--detection-timestamp", "2026-05-17T10:00:00Z",
            "--vulnerability-id", "CVE-2026-12345",
            "--suspected-malicious", "true",
            "--cross-border-impact", "true",
            "--out", str(out_file),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out_file.exists()
    payload = json.loads(out_file.read_text())
    assert payload["notification_type"] == "early_warning"

    validate = runner.invoke(cli, ["validate", str(out_file)])
    assert validate.exit_code == 0, validate.output
    assert "OK" in validate.output


def test_validate_rejects_bad_payload(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"notification_type": "early_warning"}))
    result = CliRunner().invoke(cli, ["validate", str(bad)])
    assert result.exit_code == 1
    assert "INVALID" in result.output
