# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Proposed as **1.0.0**, the first tagged release. No version has been tagged yet.
(The script's comment-based help lists an internal `Version: 1.1`; that number has
not been published as a release.)

### Added

- `extract-recommended-actions.ps1`: read-only PowerShell 7 script that signs in to
  Microsoft Graph with the delegated `SecurityIncident.Read.All` scope and retrieves
  Microsoft Defender XDR incidents created in the last 30 days from
  `GET /v1.0/security/incidents`, with `$expand=alerts`, 50 incidents per page and
  pagination through `@odata.nextLink`.
- Per-incident extraction of unique alert titles, MITRE ATT&CK technique IDs
  (`mitreTechniques`) and recommended-action texts (`recommendedActions`) from the
  incident's alerts.
- CSV export to `IncidentCatalog_WithActions_YYYYMMDD_HHmmss.csv` in the current
  directory with 17 columns, including incident metadata, alert count, technique
  count and recommended-action count.
- Console summary: incident totals, recommended-action coverage, breakdowns by
  severity, status and classification, total and average alerts per incident, and
  the number of incidents with MITRE ATT&CK mapping.
- README with prerequisites, usage, output columns and permissions; MIT license;
  `.gitignore` that excludes generated CSV files.
- `SECURITY.md` with vulnerability reporting instructions, and a Maintainer section
  in the README.
- This changelog and draft release notes for 1.0.0 in `docs/release-notes/v1.0.0.md`.

### Changed

- README corrected to match the script: full list of CSV columns, delegated
  authentication only, page size, output location and the separators used in
  multi-value columns.

### Removed

- Generated CSV outputs and a macOS `.DS_Store` file that were committed in the
  initial commit were removed from the working tree.
