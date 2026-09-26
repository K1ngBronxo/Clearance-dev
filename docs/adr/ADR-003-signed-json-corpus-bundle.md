# ADR-003 — The corpus ships as a signed JSON bundle, not SQLite

- **Status:** Accepted
- **Date:** 2026-09-23

## Context

The compiled corpus was originally specified as **SQLite**. The repository
layout calls
`corpus-build` a "YAML -> signed SQLite" compiler, the build target is
`corpus.sqlite`, and the corpus schema specification section 10 gives the full
`CREATE TABLE` schema for it, with the runtime reading a `payload` column as
JSON.

Separately, the plan makes a stronger, load-bearing claim — quoted verbatim at
the top of `internal/corpus/corpus.go`:

> **All judgement lives in the corpus (data), none in the code.** A wrong
> interpretation is fixed by editing YAML, not by shipping a binary. This is the
> moat: a fork can copy the code; a fork cannot sign the corpus.

That claim requires the corpus to be **replaceable without rebuilding the
binary**, and **verifiable by the binary before it is trusted**.

SQLite fails the first requirement cleanly: reading a SQLite database from a Go
binary without CGO means a pure-Go driver, which is a third-party dependency,
which breaks [ADR-001](ADR-001-go-static-zero-deps.md). Building with CGO to get
the standard driver breaks the static-binary promise instead.

## Decision

The compiled corpus is a **three-file signed JSON bundle**:

| File | Role |
|---|---|
| `corpus.json` | The compiled payload: every licence, trap, ToS and territory entry, as JSON. |
| `corpus.version.json` | The manifest (sidecar). Its field set is frozen at bundle schema 1. |
| `corpus.json.sig` | The Ed25519 signature over the SHA-256 digest of `corpus.json`. |

The manifest's seven fields are `version`, `schema_version`, `built_at`,
`signed_at`, `sha256`, `entry_count`, `signature_alg`
(`internal/corpus/verify.go`).

Verification is fixed and non-negotiable, and happens on **every load**, not only
on update:

1. Read `corpus.json`, `corpus.version.json` and `corpus.json.sig`.
2. Compute the SHA-256 of the payload and compare it to the manifest's `sha256`.
3. Verify the Ed25519 signature over **the digest bytes** — not over the file's
   own bytes, which an attacker could swap together with the signature.
4. Check `schema_version` against the binary's supported version
   (`E-CORPUS-003`).

The signing key is **offline**. It never touches a build server, and only
`corpus-build` — which is never shipped — can use it. A compromised CI runner
cannot forge a corpus.

`built_at` and `signed_at` are both recorded because they are different facts:
the gap between them is the only record of how long an unsigned bundle sat on a
disk before it was signed.

## Consequences

**Good.**

- The corpus is a data file the binary can verify with the standard library
  alone. No driver, no CGO, no dependency. ADR-001 holds.
- A wrong interpretation is fixed by editing YAML, recompiling and re-signing
  offline. No binary release is needed, which is exactly what the moat requires.
- The payload is human-inspectable: a JSON file can be diffed and read, which
  matches the product's commitment to a checkable record.

**Bad, and accepted.**

- There is no indexed lookup in the bundle. The runtime loads the whole payload
  into memory and builds its indexes at start-up. At the corpus's expected size
  (bounded at 64 MiB by `MaxCorpusBytes`, `E-NET-008`) this is a fraction of a
  second, and it keeps the binary dependency-free. If the corpus ever outgrows
  that bound, the right answer is a format change with a schema-version bump —
  not a driver.
- The plan's SQLite schema is now dead text. A reader who finds it must find
  this record; the plan documents are not edited here.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| **SQLite via a pure-Go driver** | A third-party dependency, in a zero-dependency supply-chain tool. Breaks ADR-001. |
| **SQLite via CGO** | Breaks the static-binary and cross-compilation promise, and the offline install story. |
| **Embed the corpus in the binary (`go:embed`)** | Would require a binary release to correct a single clause, which destroys the central architectural claim. |
| **A binary serialisation (gob, protobuf, CBOR)** | Not human-inspectable, and gob/protobuf need a schema dependency. JSON is auditable with `cat`, which matters for a published reference work. |

## References

- `internal/corpus/verify.go` — the bundle file names, the manifest type, the
  verification order, and the offline-key note.
- `internal/corpus/corpus.go` — the "all judgement lives in the corpus" claim
  that this decision serves.
- `Makefile` — the `corpus` and `corpus-sign` targets.
- [ADR-001](ADR-001-go-static-zero-deps.md) — the constraint that forced this.
