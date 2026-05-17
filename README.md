# cra-scope

> Open-source CLI for preparing EU **Cyber Resilience Act** (Regulation (EU) 2024/2847)
> Article 14 notifications for the **ENISA Single Reporting Platform (SRP)**.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

`cra-scope` builds the four notification payloads the CRA requires under
Article 14 (and the comparable structure of Article 15), validates them
against a stable JSON schema, resolves the designated CSIRT for each EU
Member State, and checks CVEs against the public CISA KEV catalogue.

It is the **open-source core** of the [CRA Scope](https://crascope.com)
ecosystem. Use it to prepare payloads in CI, in scripts, or at the
keyboard — then submit them through the ENISA SRP portal under your
manufacturer's EU Login account, as required by EC FAQ §4.6.1.

For a fully managed workflow — compliance clocks, multi-product case
management, evidence archival, board dashboards, CSIRT/SIEM/ITSM
integrations, alerting, and audit trail — see [CRA Scope SaaS](https://crascope.com).

---

## What's in the box

| Stage             | Article          | Deadline | Builder                                |
| ----------------- | ---------------- | -------- | -------------------------------------- |
| Early warning     | 14(2)(a) / 14(4)(a) | 24 h  | `build early-warning`                  |
| Vuln notification | 14(2)(b)         | 72 h     | `build vuln-notification`              |
| Incident notification | 14(4)(b)     | 72 h     | `build incident-notification`          |
| Final report (vuln)   | 14(2)(c)     | 14 d     | `build final-report`                   |
| Final report (incident) | 14(4)(c)   | 1 m      | `build final-report --report-subject-type severe_incident` |

Plus:
- `cra-scope csirt <country>` — resolve designated CSIRT
- `cra-scope csirts` — list all 27 EU Member State CSIRTs
- `cra-scope validate <payload.json>` — validate a saved payload
- `cra-scope kev-check <CVE>` — check CISA Known Exploited Vulnerabilities

---

## Install

```bash
pip install cra-scope
```

Requires Python 3.10+.

---

## Quick start

Build a 24-hour early warning for an actively exploited vulnerability:

```bash
cra-scope build early-warning \
  --manufacturer-name "ACME GmbH" \
  --manufacturer-country DE \
  --manufacturer-contact security@acme.example \
  --product-name "ACME Router" \
  --product-version 2.4.1 \
  --detection-timestamp 2026-05-17T10:00:00Z \
  --vulnerability-id CVE-2026-12345 \
  --suspected-malicious true \
  --cross-border-impact true \
  --preliminary-description "RCE in firmware update handler" \
  --out early-warning.json
```

Then validate it before uploading:

```bash
cra-scope validate early-warning.json
# OK: payload is valid.
```

Check whether a CVE is actively exploited (CISA KEV):

```bash
cra-scope kev-check CVE-2024-3400
```

---

## Library usage

```python
from cra_scope_core import (
    build_early_warning,
    validate_notification,
    resolve_csirt,
)

payload = build_early_warning(
    manufacturer_name="ACME GmbH",
    manufacturer_country="DE",
    manufacturer_contact="security@acme.example",
    product_name="ACME Router",
    product_version="2.4.1",
    product_category="network",
    vulnerability_id="CVE-2026-12345",
    detection_timestamp="2026-05-17T10:00:00Z",
    suspected_malicious=True,
    cross_border_impact=True,
)

errors = validate_notification(payload)
assert not errors

print(resolve_csirt("DE"))
# {'name': 'BSI CERT-Bund', 'id': 'CSIRT-DE-001'}
```

---

## What this tool does NOT do

- It does **not** submit notifications to ENISA on your behalf. ENISA SRP
  authentication uses EU Login (CAS), a closed government identity scheme;
  Article 14 reporting is the manufacturer's non-delegable legal
  obligation (EC FAQ §4.6.1). `cra-scope` prepares the payload — you
  upload it through the SRP portal.
- It does **not** run a compliance clock, track multiple products, store
  evidence, page on-call engineers, push to your SIEM/ITSM, or produce a
  signed audit archive. Those are workflow concerns better handled by a
  managed platform — see [CRA Scope SaaS](https://crascope.com).
- It is **not** legal advice. CRA Article 14 obligations apply from 11
  September 2026; you remain responsible for your own compliance.

---

## When to use this vs. CRA Scope SaaS

| You need…                                  | Use            |
| ------------------------------------------ | -------------- |
| Build & validate a payload in a script     | `cra-scope`    |
| One-off vulnerability disclosure prep      | `cra-scope`    |
| Multi-product compliance clock + dashboard | CRA Scope SaaS |
| Continuous monitoring, alerts, on-call     | CRA Scope SaaS |
| Signed audit archive, board reporting      | CRA Scope SaaS |
| CSIRT / SIEM / ITSM integrations           | CRA Scope SaaS |

---

## Contributing

Issues and PRs welcome. This project follows
[Semantic Versioning](https://semver.org/) and a
[Keep a Changelog](https://keepachangelog.com/) changelog.

```bash
git clone https://github.com/Usingthefork/cra-scope-cli.git
cd cra-scope-cli
pip install -e ".[dev]"
pytest
```

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

`cra-scope` is not affiliated with, endorsed by, or sponsored by ENISA,
the European Commission, CISA, or any EU Member State CSIRT.
