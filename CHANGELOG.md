# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] — 2026-08-01

### Added

- **EU representative (AR) support** — all four payload builders now accept
  `eu_representative_name`, `eu_representative_country`, and
  `eu_representative_contact`. When provided, `manufacturer.eu_representative`
  is included in the payload and CSIRT routing uses the AR country.
  Aligned with ENISA AR user-guidance published 31 Jul 2026.

- **Art. 16(2) dissemination delay / PEC** — `build_vulnerability_notification`
  and `build_incident_notification` now accept `dissemination_delay_requested`,
  `dissemination_delay_grounds` (`art_16_2_a` / `art_16_2_b` / `art_16_2_c`),
  and `dissemination_delay_justification`. When set, a `dissemination_delay`
  block is added. The ENISA SRP portal shows such notifications as
  "72h under PEC" (Particularly Exceptional Circumstances).

- **ENISA SRP FAQ Q16 optional fields** — all builders now accept
  `notification_level`, `title`, `euvd_id`, `sensitivity_of_information`,
  `product_type`, and `annex_category`. Non-empty values are included in
  the payload.

- `VALID_DISSEMINATION_DELAY_GROUNDS` constant exported from `cra_scope_core`.

### Changed

- `schema_version` bumped `1.0.0` → `1.1.0`. New fields are all optional;
  existing payloads remain valid.
- `validate_notification` now checks `eu_representative.country` (must be an
  EU Member State when present) and validates `dissemination_delay.grounds`
  against `VALID_DISSEMINATION_DELAY_GROUNDS`.

## [0.1.3] — 2026-05-17

### Added
- CI status badge in `README.md`.

### Changed
- First release published via PyPI Trusted Publishing (OIDC); no long-lived
  API tokens are used in the release pipeline.

## [0.1.2] — 2026-05-17

### Changed
- Rewrote `README.md` for clarity: plain-English explanation of what
  the tool does, who it is for, a 60-second tour, a full reporting-flow
  table for one case, a troubleshooting section, and an explicit
  "what this tool does NOT do" section. No code changes.

## [0.1.1] — 2026-05-17

### Fixed
- Corrected project homepage and contact metadata from crascope.eu to crascope.com.

## [0.1.0] — 2026-05-17

### Added
- `cra_scope_core` library:
  - `csirt` — EU Member State → designated CSIRT resolver (27 Member States)
  - `srp` — payload builders for CRA Article 14 notifications:
    - `build_early_warning` (24 h — Art. 14(2)(a))
    - `build_vulnerability_notification` (72 h — Art. 14(2)(b))
    - `build_incident_notification` (72 h — Art. 14(4)(b))
    - `build_final_report` (14 d — Art. 14(2)(c) / 1 m — Art. 14(4)(c))
  - `srp.validate_notification` — schema validator
  - `kev` — CISA Known Exploited Vulnerabilities lookup
- `cra-scope` CLI:
  - `csirt <country>` — resolve designated CSIRT
  - `build early-warning|vuln-notification|final-report` — produce JSON payloads
  - `validate <file>` — validate a saved payload
  - `kev-check <CVE>` — check CISA KEV catalogue
- Apache-2.0 licensing
- Extracted from the CRA Scope SaaS codebase for open-source release
