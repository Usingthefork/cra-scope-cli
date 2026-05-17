# cra-scope

> A command-line tool that builds the **EU Cyber Resilience Act**
> notification reports (CRA Article 14 / 15) you have to submit to
> ENISA when an exploited vulnerability or severe incident hits one
> of your products.

[![PyPI](https://img.shields.io/pypi/v/cra-scope.svg)](https://pypi.org/project/cra-scope/)
[![CI](https://github.com/Usingthefork/cra-scope-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/Usingthefork/cra-scope-cli/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

---

## What is this in plain English?

From **11 September 2026**, manufacturers of products with digital
elements sold in the EU must report:

- **Actively exploited vulnerabilities** to ENISA within **24 h** (early
  warning), then **72 h** (notification), then **14 days** after a fix
  is available (final report).
- **Severe incidents** within the same 24 h / 72 h cadence, with a
  final report due **1 month** later.

ENISA accepts those reports through a web portal called the **Single
Reporting Platform (SRP)** — login is via EU Login, the EU's central
identity service. **There is no public submission API.**

This tool helps you **prepare the report content** — correctly
structured, schema-validated, with the right CSIRT routed for your
country — so that when the clock starts ticking, you have a clean JSON
file ready to paste/upload through the SRP portal.

It does **not** submit anything for you. That part is legally yours.

---

## Who is this for?

- Engineers at a manufacturer who got a CVE alert and need to file
  within 24 h.
- Security teams scripting CRA notification prep into CI/CD.
- Consultants helping clients dry-run the CRA reporting workflow.
- Anyone who wants to know *what fields ENISA actually expects*
  before the September 2026 deadline.

If you also want compliance clocks, multi-product case management,
audit archive, board dashboards, alerting and CSIRT/SIEM integrations,
look at the managed **[CRA Scope SaaS](https://crascope.com)**. This
CLI is the open-source core of that platform.

---

## Install

You need Python 3.10 or newer.

```bash
pip install cra-scope
```

Verify the install:

```bash
cra-scope --version
# cra-scope, version 0.1.1
```

If `cra-scope` isn't found, your Python `bin/` directory isn't on
`PATH`. Either run it as `python -m cra_scope_cli` or fix `PATH`.

---

## 60-second tour

```bash
# 1. Who's my national CSIRT? (lookup for any of the 27 EU states)
cra-scope csirt DE

# 2. Is this CVE actively exploited (per CISA KEV)?
cra-scope kev-check CVE-2024-3400

# 3. Build a 24-hour Early Warning report
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

# 4. Double-check it validates against the schema
cra-scope validate early-warning.json
# OK: payload is valid.
```

Now open the **ENISA SRP portal**, log in with EU Login, and upload
`early-warning.json`. Done — clock #1 of 3 satisfied.

---

## The full reporting flow for one case

Say a CVE in your firmware just got added to CISA KEV. The clock starts
*the moment you become aware* (CRA Article 14(1)). Here's the full
sequence:

| Hour | What CRA requires       | Command                                       |
| ---- | ----------------------- | --------------------------------------------- |
| 0    | Become aware            | `cra-scope kev-check CVE-...`                 |
| ≤ 24 | Submit **Early Warning**| `cra-scope build early-warning ...`           |
| ≤ 72 | Submit **Notification** | `cra-scope build vuln-notification ...`       |
| ≤ 14 d after fix | Submit **Final Report** | `cra-scope build final-report ...` |

For a **severe incident** (not a CVE — e.g. ransomware on production
service), swap `vuln-notification` for `incident-notification` and add
`--report-subject-type severe_incident` to the final report. The final
report deadline becomes **1 month**.

Each command writes a JSON file; each file goes through the SRP portal
as a separate submission, tied to the same case reference ENISA assigns
on first submission.

---

## All commands

```text
cra-scope csirt <COUNTRY>            Resolve designated CSIRT for an EU MS
cra-scope csirts                     List all 27 EU CSIRTs
cra-scope kev-check <CVE>            Check CISA Known Exploited Vulns

cra-scope build early-warning         24h  Art. 14(2)(a) / 14(4)(a)
cra-scope build vuln-notification     72h  Art. 14(2)(b)
cra-scope build incident-notification 72h  Art. 14(4)(b)
cra-scope build final-report          14d / 1m  Art. 14(2)(c) / 14(4)(c)

cra-scope validate <payload.json>    Re-validate a saved JSON payload
```

Run any command with `--help` to see its full flag set:

```bash
cra-scope build early-warning --help
```

---

## Using it from Python

Everything the CLI does is available as a small importable library
(`cra_scope_core`), so you can call it from your own scripts, tests,
or CI jobs:

```python
from cra_scope_core import (
    build_early_warning,
    validate_notification,
    resolve_csirt,
)
from cra_scope_core.kev import is_actively_exploited

if is_actively_exploited("CVE-2024-3400"):
    payload = build_early_warning(
        manufacturer_name="ACME GmbH",
        manufacturer_country="DE",
        manufacturer_contact="security@acme.example",
        product_name="ACME Router",
        product_version="2.4.1",
        product_category="network",
        vulnerability_id="CVE-2024-3400",
        detection_timestamp="2026-05-17T10:00:00Z",
        suspected_malicious=True,
        cross_border_impact=True,
    )
    errors = validate_notification(payload)
    assert not errors, errors
    print("Send to:", resolve_csirt("DE"))
```

Public API: `build_early_warning`, `build_vulnerability_notification`,
`build_incident_notification`, `build_final_report`,
`validate_notification`, `resolve_csirt`, `EU_CSIRT_MAP`,
`ValidationError`. KEV helpers live in `cra_scope_core.kev`:
`fetch_kev_catalogue`, `lookup_cve`, `is_actively_exploited`.

---

## What it does NOT do

- **It does not submit anything.** ENISA SRP login is EU Login (CAS); a
  third party cannot authenticate on your behalf. Article 14 reporting
  is the manufacturer's non-delegable legal obligation (EC FAQ §4.6.1).
- **It does not run a compliance clock or remind you.** It builds a
  file — you start the timer.
- **It does not store evidence, page on-call, or push to SIEM/ITSM.**
  Use [CRA Scope SaaS](https://crascope.com) for that.
- **It is not legal advice.** Final responsibility for the content,
  accuracy and timeliness of your CRA submissions is yours.

---

## CRA Scope CLI vs. CRA Scope SaaS

| If you need…                                | Use            |
| ------------------------------------------- | -------------- |
| Build & validate one notification payload   | `cra-scope`    |
| Scripted CRA payload prep in CI/CD          | `cra-scope`    |
| Multi-product compliance clock + dashboard  | CRA Scope SaaS |
| Continuous KEV/OSV monitoring + alerting    | CRA Scope SaaS |
| Signed evidence archive & board reporting   | CRA Scope SaaS |
| CSIRT / SIEM / ITSM integration             | CRA Scope SaaS |
| EU Login passthrough for SRP submission     | Not possible — manufacturer-only |

---

## Troubleshooting

**`cra-scope: command not found`**
Your Python `bin/` isn't on `PATH`. Try `python -m cra_scope_cli` or
re-install in a venv: `python -m venv .venv && source .venv/bin/activate && pip install cra-scope`.

**`validate` says my payload is invalid**
The error message lists every failing field. Common causes: missing
required field, `detection_timestamp` not in RFC 3339 UTC form
(`2026-05-17T10:00:00Z`), or `manufacturer_country` is not a valid
two-letter EU code.

**`kev-check` says "not in catalogue"**
The CVE simply isn't on CISA KEV today. That doesn't mean it isn't
exploited — it means CISA hasn't listed it. Your obligation under CRA
Art. 14 is broader than KEV; KEV is a *positive* signal, not a
*complete* one.

**Network errors on `kev-check`**
The CLI fetches `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
once per run. If you're behind a proxy, set `HTTPS_PROXY`.

---

## Contributing

Issues and PRs welcome. SemVer + [Keep a Changelog](https://keepachangelog.com/).

```bash
git clone https://github.com/Usingthefork/cra-scope-cli.git
cd cra-scope-cli
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

`cra-scope` is not affiliated with, endorsed by, or sponsored by ENISA,
the European Commission, CISA, or any EU Member State CSIRT.

Maintained by [CRA Scope B.V.](https://crascope.com) · hello@crascope.com
