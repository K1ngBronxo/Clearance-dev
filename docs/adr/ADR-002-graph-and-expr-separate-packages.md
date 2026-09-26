# ADR-002 — `internal/graph` and `internal/expr` are their own packages

- **Status:** Accepted
- **Date:** 2026-09-23
- **Refines:** `PLAN/01-ARCHITECTURE/01-system-architecture.md` section 1.1,
  `PLAN/01-ARCHITECTURE/03-data-model.md` section 9,
  `PLAN/01-ARCHITECTURE/10-repo-structure.md` section 1

## Context

The plan's repository layout
(`PLAN/01-ARCHITECTURE/10-repo-structure.md` section 1) places two types in
packages that the plan's own layer table forbids them from living in:

1. `Dependency` and `DependencyGraph` are placed inside `internal/scanner` (L1).
2. `Expr`, the predicate tree, is placed inside `internal/policy` (L3).

The layer table in `PLAN/01-ARCHITECTURE/01-system-architecture.md` section 1.1
is **normative** and states:

```
L2 may never import L3
L3 may never import L1
```

with the rationale that a decision layer which reads the filesystem is
untestable, and that the corpus (data) must be knowable without the engine.

Both placements break those rules:

- If the graph types live in L1, `policy.Evaluate` (L3) has to import L1 to name
  its own parameter type. The purity boundary is breached on day one.
- If `Expr` lives in L3, the corpus loader (L2) — which decodes and validates
  every predicate at load time — has to import L3. The data layer would depend
  on the engine.

## Decision

Two small packages sit at the bottom of the stack, beside `cerr`, importing
nothing beyond the standard library and `cerr`:

- **`internal/graph`** — the dependency-graph types (`Kind`, `Evidence`,
  `LicenceRef`, `Dependency`, `DependencyGraph`, `Undetermined`). `scanner` (L1)
  *constructs* a `Graph`; `policy` (L3) *consumes* one. Neither knows about the
  other.
- **`internal/expr`** — the predicate language (`Expr`, `Kind`, `Op`, the
  evaluation entry points). The corpus (L2) stores and validates predicates; the
  policy engine (L3) evaluates them. Both can name the type without an upward
  import.

The type definitions are the whole point: the packages carry no I/O, no clock
and no behaviour that reaches outward.

## Consequences

**Good.**

- The layer table is enforceable as written, and `internal/arch_test.go` can
  check it mechanically. A violation fails the build.
- `policy` and `verdict` become pure functions over plain data. They are
  testable without a filesystem, a clock, or a mock, which is what makes the
  verdict determinism property (INV-6) provable rather than aspirational.
- The same trade-off the plan already made one level up — `corpus` (types) vs
  `scanner` (reading) — is applied consistently one level down.

**Bad, and accepted.**

- Two more packages, and the plan's tree no longer matches the code exactly.
  This record exists so that a reader who notices the difference finds the
  reason rather than assuming a mistake.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| **Follow the plan's tree literally** | It contradicts the normative layer table. One of the two documents has to give, and the layer table is the one with a test behind it. |
| **A single `internal/types` package for both** | Merges two unrelated concerns (the dependency graph and the predicate language) into one package, which makes the arch test coarser and the package harder to reason about. |
| **Move the layer table instead** | The layering is the property that keeps the decision layer pure. Moving it to accommodate a file path is the wrong trade. |

## References

- `internal/graph/graph.go` — the package comment recording this decision.
- `internal/expr/expr.go` — the package comment recording this decision.
- `PLAN/01-ARCHITECTURE/01-system-architecture.md` section 1.1 — the normative
  layer table.
