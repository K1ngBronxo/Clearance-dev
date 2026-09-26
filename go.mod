module github.com/clearance-dev/clearance

go 1.25.13

// The patch level is deliberate, and it is not cosmetic. `make vulncheck` runs
// govulncheck against the toolchain's own standard library, and at go1.23 the
// standard library carries advisories reachable from code this program actually
// calls — 31 of them at go1.23.4, still 24 at go1.23.12. The fixing releases are
// go1.25.13 and go1.24.11. Declaring the patched minimum here is what makes that
// checkable: an older toolchain refuses to build rather than building quietly.
// CI reads this file (`go-version-file: go.mod`), so it moves with it.

// Clearance has ZERO third-party dependencies, deliberately.
//
//  * Control C10 (supply-chain integrity): every dependency of a supply-chain
//    tool is itself a supply-chain risk. A scanner that audits other people's
//    dependencies has no business carrying its own.
//  * Control C2 / INV-10: the plan requires strict, bounded decoders for all
//    untrusted input. internal/safeyaml implements a documented YAML *subset*
//    with no tag, anchor or alias syntax at all — so YAML deserialisation RCE
//    is not mitigated, it is structurally impossible.
//  * The binary must build and run offline, on a plane, on Windows with no
//    Docker. `go build` with no module graph is the shortest path to that.
//
// Adding a dependency is a decision that must be recorded as an ADR in docs/adr/,
// with the alternative that was rejected.
