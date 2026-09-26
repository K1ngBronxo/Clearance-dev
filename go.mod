module github.com/clearance-dev/clearance

go 1.23

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
// Adding a dependency is a decision that must be recorded in the decision log
// with the alternative that was rejected. See PLAN/99-REFERENCE/01-decision-log.md.
