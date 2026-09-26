# Architecture Decision Records

This directory holds the decisions that are expensive to reverse. Each record is
short, dated, and states the alternatives that were rejected — because the value
of a decision record is the *reason*, not the outcome.

A decision that changes a frozen contract (the CLI flags, the exit codes, the
JSON schema, the corpus schema) also needs a migration note. Those four are
frozen forever: see [`docs/ci.md`](../../docs/ci.md) for the exit-code contract
and [`corpus/SCHEMA.md`](../../corpus/SCHEMA.md) for the corpus version rule.

| ADR | Title | Status |
|---|---|---|
| [ADR-001](ADR-001-go-static-zero-deps.md) | Go, one static binary, zero third-party dependencies | Accepted |
| [ADR-002](ADR-002-graph-and-expr-separate-packages.md) | `internal/graph` and `internal/expr` are their own packages | Accepted |
| [ADR-003](ADR-003-signed-json-corpus-bundle.md) | The corpus ships as a signed JSON bundle, not SQLite | Accepted |

These records are the ones the *code* made — the places where the
implementation departed from the layout originally proposed for it, and why.
Each one states the alternatives it rejected.
