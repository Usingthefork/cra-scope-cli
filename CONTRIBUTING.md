# Contributing to cra-scope

Thanks for your interest in helping. `cra-scope` is the open-source core
of the [CRA Scope](https://crascope.com) ecosystem. We accept issues
and pull requests under the project's Apache-2.0 licence.

## Ground rules

- **Be specific.** Bug reports without a reproducible example will be
  closed. Feature requests without a CRA-text or ENISA-source reference
  will be triaged but rarely merged.
- **No legal advice in code or docs.** We document what the regulation
  *says*; we do not interpret it for end-users.
- **One logical change per PR.** Keep diffs reviewable.

## Development setup

```bash
git clone https://github.com/Usingthefork/cra-scope-cli.git
cd cra-scope-cli
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

All tests must pass on Python 3.10, 3.11 and 3.12 (the CI matrix).

## Commit & PR conventions

- Branch from `main`.
- Conventional commits style (`feat:`, `fix:`, `docs:`, `chore:`, etc.).
- Add or update tests for any behaviour change.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- Do not bump the version in `pyproject.toml` — maintainers handle releases.

## Release process (maintainers)

1. Move `[Unreleased]` entries under a new version heading in `CHANGELOG.md`.
2. Bump `version` in `pyproject.toml`.
3. Commit, then tag: `git tag vX.Y.Z && git push origin main --tags`.
4. The `release.yml` workflow builds + publishes to PyPI via OIDC.
5. Create a GitHub Release from the tag with the changelog body.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
