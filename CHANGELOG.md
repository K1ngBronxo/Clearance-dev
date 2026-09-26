# Changelog

All notable changes to Clearance are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The **corpus** versions independently of the binary and has its own changelog,
published with the corpus bundle. A corpus change is recorded there, not here.
The binary's compatibility promise with the corpus is stated in
[`PLAN/01-ARCHITECTURE/09-interfaces-and-contracts.md`](../PLAN/01-ARCHITECTURE/09-interfaces-and-contracts.md)
section 7.

---

## [Unreleased]

Nothing yet. The next entry will be a binary release; the corpus is versioned
separately.

---

## [0.1.0] - 2026-09-23

The first foundation slice. This version has **not been released as a binary**;
it is the initial state of the repository, recorded here so that the release
history starts with a tagged baseline rather than an empty file.

### Added

- **Go module** `github.com/clearance-dev/clearance`, `go 1.23`, with **zero
  third-party dependencies** ([ADR-001](docs/adr/ADR-001-go-static-zero-deps.md)).
- **L0 primitives**: `internal/cerr` (the typed-error layer and the error
  taxonomy — 80 codes at this baseline, 102 as of 2026-09-25), `internal/safefs`
  (the single file-opening path), `internal/safeyaml`
  and `internal/safejson` (strict, bounded decoders), `internal/cite` (the
  citation index), `internal/prov` (the provenance vocabulary).
- **The decision layer**: `internal/expr` (the predicate language),
  `internal/graph` (dependency-graph types), `internal/policy` (intent x
  obligation -> findings), `internal/verdict` (the four-rule verdict algebra,
  with `Fold` and the frozen exit-code mapping).
- **The knowledge layer**: `internal/corpus` (load, validate, index, and verify
  a signed bundle) and the corpus YAML tree under `corpus/`.
- **L1 input**: `internal/parsers` (npm, PyPI, Go modules, Cargo) and
  `internal/scanner`.
- **Configuration**: `internal/config` — discovery, merge, validation, the six
  required `use.*` fields, and the `policy` block.
- **CI/CD**: `.github/workflows/ci.yml` (guard job first, then test/lint/
  vulncheck/banned-imports), `.github/workflows/release.yml` (GoReleaser,
  cosign, SLSA provenance, SBOM), `.goreleaser.yml`, and a `Makefile`.
- **Linting**: `.golangci.yml` with the `depguard` rules that mirror the
  banned-import checks.
- **Documentation**: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, this
  changelog, and the pages under `docs/`.
- **Decision records**: [ADR-001](docs/adr/ADR-001-go-static-zero-deps.md),
  [ADR-002](docs/adr/ADR-002-graph-and-expr-separate-packages.md),
  [ADR-003](docs/adr/ADR-003-signed-json-corpus-bundle.md).
- **Licence**: Apache-2.0 (`LICENSE`), with the required `NOTICE` file.

### Notes

- The corpus in this slice is a schema and a validation pipeline; it is **not
  yet a signed, published bundle**. The signing key ceremony is a Phase 0 task.
- `corpus-build/` (the internal compiler and signer) and `cmd/clearance/` (the
  entry point) are present as package directories but are not yet populated.
  The libraries they will wire together are complete enough to test.

[Unreleased]: https://github.com/clearance-dev/clearance/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/clearance-dev/clearance/releases/tag/v0.1.0
