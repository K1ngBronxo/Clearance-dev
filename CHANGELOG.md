# Changelog

All notable changes to Clearance are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The **corpus** versions independently of the binary and has its own changelog,
published with the corpus bundle. A corpus change is recorded there, not here.
The binary's compatibility promise with the corpus is stated at the top of
[`corpus/SCHEMA.md`](corpus/SCHEMA.md), where the version negotiation is
described.

---

## [Unreleased]

### Changed

- **The minimum Go version is now 1.25.13**, up from `go 1.23`. This is a
  build-time change only; the binary behaves identically. It is recorded
  because it is the one change here a downstream builder feels: `go 1.23`
  through `go 1.25.12` will now refuse this module, or fetch the declared
  toolchain automatically when `GOTOOLCHAIN` is at its default `auto`.

  The reason is `make vulncheck`, which runs govulncheck against the
  toolchain's own standard library. At `go 1.23.4` it reported 31 reachable
  standard-library advisories and still 24 at `go 1.23.12`; the fixing
  releases are `go 1.25.13` and `go 1.24.11`. Declaring the patched minimum in
  `go.mod` is what turns that from a check that has to be run into a build
  that cannot quietly succeed on a toolchain carrying the defect.

- **`.golangci.yml` is now schema v2**, for golangci-lint v2, because a v1
  binary cannot lint a module declaring `go 1.25` at all — its loader is built
  on `go1.23` and refuses the newer directive. The lint rules themselves are
  unchanged: all four `depguard` banned-import rules survive the migration and
  each was verified to still fire. CI moves with it, from
  `golangci/golangci-lint-action@v6` on `v1.62.2` to `@v8` on `v2.14.0`.

Nothing else yet. The next entry will be a binary release; the corpus is
versioned separately.

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
