# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in `cra-scope`,
**do not open a public GitHub issue**.

Email **security@crascope.com** with:

- A description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept.
- The affected version(s) (`pip show cra-scope`).
- Your name and affiliation, if you'd like to be credited.

We will acknowledge receipt within **3 business days** and aim to
provide an initial assessment within **10 business days**. Coordinated
disclosure timelines are agreed case-by-case; we follow a 90-day
default.

## Supported versions

Only the latest minor release on PyPI receives security fixes.

| Version  | Supported |
| -------- | --------- |
| 0.1.x    | Yes       |
| < 0.1    | No        |

## Scope

In scope:

- The `cra_scope_core` library and `cra-scope` CLI as published to PyPI.
- Schema validation logic in `cra_scope_core.srp`.
- The bundled CSIRT map and KEV lookup.

Out of scope:

- The ENISA SRP portal itself.
- CISA KEV catalogue contents.
- Third-party dependencies (please report upstream).
- The managed CRA Scope SaaS — for that, email security@crascope.com
  and mention "SaaS" in the subject.

## PGP

If you require encrypted communication, request a public key in your
first email and we will provide one.
