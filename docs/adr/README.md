# Architecture Decision Records

This directory holds the decisions that are expensive to reverse. Each record is
short, dated, and states the alternatives that were rejected — because the value
of a decision record is the *reason*, not the outcome.

A decision that changes a frozen contract (the CLI flags, the exit codes, the
JSON schema, the corpus schema) also needs a migration note, per
[`PLAN/01-ARCHITECTURE/09-interfaces-and-contracts.md`](../../../PLAN/01-ARCHITECTURE/09-interfaces-and-contracts.md)
section 7.

| ADR | Title | Status |
|---|---|---|
| [ADR-001](ADR-001-go-static-zero-deps.md) | Go, one static binary, zero third-party dependencies | Accepted |
| [ADR-002](ADR-002-graph-and-expr-separate-packages.md) | `internal/graph` and `internal/expr` are their own packages | Accepted |
| [ADR-003](ADR-003-signed-json-corpus-bundle.md) | The corpus ships as a signed JSON bundle, not SQLite | Accepted |

The plan's own decision log lives at
[`PLAN/99-REFERENCE/01-decision-log.md`](../../../PLAN/99-REFERENCE/01-decision-log.md);
these records are the ones that the *code* made, where the code and the plan's
repository layout differ. Each of the three records above cites the plan
document it refines.
