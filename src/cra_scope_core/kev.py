"""CISA Known Exploited Vulnerabilities (KEV) lookup.

The CISA KEV catalogue is a public JSON feed of vulnerabilities with
evidence of active exploitation. It is a strong signal for the CRA
Art. 14(2)(a) "actively exploited" trigger.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Feed:   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

_DEFAULT_TIMEOUT = 30.0


def fetch_kev_catalogue(
    *,
    url: str = KEV_FEED_URL,
    timeout: float = _DEFAULT_TIMEOUT,
    client: Optional[httpx.Client] = None,
) -> dict[str, Any]:
    """Fetch and return the full CISA KEV catalogue as a dict."""
    if client is not None:
        resp = client.get(url, timeout=timeout)
    else:
        resp = httpx.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def lookup_cve(
    cve_id: str,
    *,
    catalogue: Optional[dict[str, Any]] = None,
    url: str = KEV_FEED_URL,
    timeout: float = _DEFAULT_TIMEOUT,
) -> Optional[dict[str, Any]]:
    """Look up a single CVE in the KEV catalogue.

    Returns the KEV entry dict if found, ``None`` if the CVE is not listed.
    Pass a pre-fetched ``catalogue`` to avoid repeated network calls.
    """
    cve = cve_id.strip().upper()
    if catalogue is None:
        catalogue = fetch_kev_catalogue(url=url, timeout=timeout)
    for entry in catalogue.get("vulnerabilities", []) or []:
        if entry.get("cveID", "").upper() == cve:
            return entry
    return None


def is_actively_exploited(
    cve_id: str,
    *,
    catalogue: Optional[dict[str, Any]] = None,
    url: str = KEV_FEED_URL,
    timeout: float = _DEFAULT_TIMEOUT,
) -> bool:
    """Return True iff ``cve_id`` appears in the CISA KEV catalogue."""
    return lookup_cve(cve_id, catalogue=catalogue, url=url, timeout=timeout) is not None
