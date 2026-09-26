# ADR-001 — Go, one static binary, zero third-party dependencies

- **Status:** Accepted
- **Date:** 2026-09-23

## Context

Clearance is a supply-chain tool. Its job is to tell a user whether the
dependencies they ship are safe to ship. That places a constraint on Clearance
that does not apply to most projects: **every dependency Clearance carries is
itself a supply-chain question Clearance would have to answer.**

The plan requires the tool to run:

- offline, on a machine with no Docker and no package manager,
- as a single file a user can download, checksum-verify and run,
- on Windows, macOS and Linux from the same source,

and it requires the verdict to be reproducible, because a verdict that cannot be
reproduced cannot be defended.

## Decision

The implementation language is **Go**, and the module has **zero third-party
dependencies**. `go.mod` declares no `require` block. A release build sets
`CGO_ENABLED=0` and `-trimpath`, producing one static binary per platform.

The rule is enforced, not merely stated:

- `go build` with no module graph is the shortest path to an offline, static
  artefact.
- The build runs `go mod verify` before anything else.
- `govulncheck` runs in CI and must stay green (there is nothing to report, and
  that is the point).
- Adding a dependency is a decision that must be recorded, with the alternative
  that was rejected, per `CONTRIBUTING.md` section 5.

## Consequences

**Good.**

- The install story is "download one file". No runtime, no interpreter, no
  shared library, no container.
- The supply-chain surface of the tool is the tool. There is no transitive
  dependency whose compromise becomes Clearance's compromise.
- The reproducibility property (INV-6) is achievable: with no module graph and a
  fixed toolchain, two builds of the same tag produce the same bytes.

**Bad, and accepted.**

- Some things are more work than they would be with a library: the YAML and JSON
  decoders, the predicate language, and the CLI parsing are all hand-written.
  This is deliberate — see ADR-003 and `internal/safeyaml` — but it is real work.
- A contributor cannot reach for a familiar helper package. The friction is the
  feature.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| **A scripting runtime (Python/Node)** | Needs an interpreter on the target machine; the install story becomes "install the runtime, then install Clearance". Fails the offline, single-file requirement. |
| **Go with a small set of vetted dependencies** | Every dependency is a licence question and a CVE question for a tool whose purpose is answering those questions. The honesty cost is too high. |
| **Rust** | Also produces a static binary, and was a genuine candidate. Rejected on the founder's existing fluency with Go and the smaller standard library needed for the (deliberately simple) work here. Not a technical rejection of Rust. |
| **An embedded database for the corpus** | See ADR-003: an embedded DB needs CGO or a driver, which breaks this decision. |

## References

- `go.mod` — the zero-dependency declaration and its rationale.
- Control C10 — the supply-chain control that forbids a third-party
  dependency from entering the build.
- [ADR-003](ADR-003-signed-json-corpus-bundle.md) — the corpus format decision
  that this one forces.
