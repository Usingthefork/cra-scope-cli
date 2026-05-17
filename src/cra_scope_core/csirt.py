"""EU Member State → designated CSIRT mapping.

CRA Article 14(1) requires notifications to be addressed to the CSIRT
designated as coordinator under NIS2 Article 10 in the Member State
where the manufacturer has its main establishment.

Source: NIS2 Cooperation Group / ENISA CSIRTs Network public registry.
"""

from __future__ import annotations

EU_CSIRT_MAP: dict[str, dict[str, str]] = {
    "AT": {"name": "CERT.at", "id": "CSIRT-AT-001"},
    "BE": {"name": "CERT.be", "id": "CSIRT-BE-001"},
    "BG": {"name": "CERT Bulgaria", "id": "CSIRT-BG-001"},
    "HR": {"name": "CERT.hr", "id": "CSIRT-HR-001"},
    "CY": {"name": "CSIRT-CY", "id": "CSIRT-CY-001"},
    "CZ": {"name": "CSIRT.CZ", "id": "CSIRT-CZ-001"},
    "DK": {"name": "CFCS", "id": "CSIRT-DK-001"},
    "EE": {"name": "CERT-EE", "id": "CSIRT-EE-001"},
    "FI": {"name": "NCSC-FI", "id": "CSIRT-FI-001"},
    "FR": {"name": "CERT-FR / ANSSI", "id": "CSIRT-FR-001"},
    "DE": {"name": "BSI CERT-Bund", "id": "CSIRT-DE-001"},
    "GR": {"name": "GR-CSIRT", "id": "CSIRT-GR-001"},
    "HU": {"name": "NCSC-HU", "id": "CSIRT-HU-001"},
    "IE": {"name": "CSIRT-IE", "id": "CSIRT-IE-001"},
    "IT": {"name": "CSIRT Italia", "id": "CSIRT-IT-001"},
    "LV": {"name": "CERT.LV", "id": "CSIRT-LV-001"},
    "LT": {"name": "CERT-LT", "id": "CSIRT-LT-001"},
    "LU": {"name": "CIRCL", "id": "CSIRT-LU-001"},
    "MT": {"name": "CSIRTMalta", "id": "CSIRT-MT-001"},
    "NL": {"name": "NCSC-NL", "id": "CSIRT-NL-001"},
    "PL": {"name": "CERT Polska", "id": "CSIRT-PL-001"},
    "PT": {"name": "CERT.PT", "id": "CSIRT-PT-001"},
    "RO": {"name": "CERT-RO", "id": "CSIRT-RO-001"},
    "SK": {"name": "SK-CERT", "id": "CSIRT-SK-001"},
    "SI": {"name": "SI-CERT", "id": "CSIRT-SI-001"},
    "ES": {"name": "CCN-CERT / INCIBE-CERT", "id": "CSIRT-ES-001"},
    "SE": {"name": "CERT-SE", "id": "CSIRT-SE-001"},
}


def resolve_csirt(country_code: str) -> dict[str, str]:
    """Resolve the designated CSIRT for a manufacturer's main establishment.

    CRA Art. 14(1): notification is addressed to the CSIRT designated
    as coordinator under NIS2 Article 10 in the Member State where the
    manufacturer has its main establishment.

    Parameters
    ----------
    country_code:
        ISO 3166-1 alpha-2 country code (case-insensitive).

    Returns
    -------
    dict with ``name`` and ``id`` keys. For non-EU codes, a synthetic
    placeholder (``CSIRT-<code>-000``) is returned and the caller is
    responsible for raising / re-checking — CRA reporting requires an
    EU main establishment.
    """
    code = country_code.strip().upper()
    if code in EU_CSIRT_MAP:
        return EU_CSIRT_MAP[code]
    return {"name": f"CSIRT ({code})", "id": f"CSIRT-{code}-000"}


def is_eu_member_state(country_code: str) -> bool:
    """Return True if ``country_code`` is a recognized EU Member State."""
    return country_code.strip().upper() in EU_CSIRT_MAP
