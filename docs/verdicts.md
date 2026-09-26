# Verdicts

A verdict is the product. It is a single value from a closed set of four, derived
from the findings by a fixed fold. It is deterministic (the same findings always
produce the same verdict), total (every input produces a verdict), explainable
(every finding carries its citation) and conservative (it never produces `SHIP`
when it is unsure).

---

## The four classes

| Class (JSON) | Human label | Meaning |
|---|---|---|
| `SHIP` | `SHIP` | No known obligation contradicts the declared intent. |
| `SHIP_CONDITIONAL` | `SHIP CONDITIONAL` | Usable, subject to stated obligations. Each is listed with a citation. |
| `DO_NOT_SHIP` | `DO NOT SHIP` | A `HIGH`-confidence blocking obligation was found. |
| `UNDETERMINED` | `UNDETERMINED` | At least one item could not be classified. |

`SHIP` claims the least of the four. It does not say the stack is free of licence
risk; it says no *known* obligation contradicts your *declared* intent. The output
says exactly that, in those words.

---

## The four rules

The fold applies these in order. The first rule that matches wins, and the order
is normative:

1. if any blocker exists -> **`DO NOT SHIP`**
2. else if any undetermined item exists -> **`UNDETERMINED`**
3. else if any condition exists -> **`SHIP CONDITIONAL`**
4. else -> **`SHIP`**

**Why a blocker comes first.** A definite block must never be diluted by an
unrelated uncertainty. If one dependency is definitively forbidden and another is
merely unknown, the answer is `DO NOT SHIP` — the unknown does not change that.

**Why `UNDETERMINED` outranks `SHIP CONDITIONAL`.** A condition is a *known*
requirement. An undetermined is an *unknown* risk. Unknown beats known when the
alternative is a false pass.

---

## The confidence gate

**A finding may only block if its confidence is `HIGH`.**

| Confidence | Can block? | Default behaviour |
|---|---|---|
| `HIGH` | yes | Fails the build. |
| `MEDIUM` | no | Produces a `CONDITION`, with a visible "clause text is ambiguous" note. |
| `LOW` | no | Produces a `NOTE`, with the raw clause shown for a human to read. |

The failure mode this guards against is not missing a trap — it is *confidently
mis-blocking* a legitimate use, or *confidently passing* a forbidden one. Both are
worse than saying "this is ambiguous, here is the text".

`--allow-medium-blockers` promotes `MEDIUM` findings to blocking for users who
want maximum conservatism. There is **no flag** that lets a `LOW` finding block. A
`LOW` confidence is an admission that the tool does not know, and a tool that does
not know must not make a decision that costs someone money.

---

## `UNDETERMINED`

`UNDETERMINED` is a first-class verdict, not an error. It is the answer when
Clearance sees something it cannot classify:

- a weight file with no licence statement;
- an unparseable lockfile, so the dependency graph is incomplete;
- licence text it does not recognise;
- an obligation gated on an intent field the user did not declare.

In each case, the honest answer is "I do not know", and the message tells you how
to resolve it. `UNDETERMINED` is never a dead end — it is a request for
information.

The anti-pattern Clearance exists to avoid is the tool that cannot classify a
licence and therefore defaults to "unknown, treat as permissive". That produces a
green build for a project that is legally unusable. **Unknown is never rounded
toward `SHIP`.**

---

## Exit codes

These five codes are a frozen contract (ADR-008). A pipeline written against them
today will still work in five years.

| Code | Meaning | What CI should do |
|---|---|---|
| `0` | Verdict produced; no blocker | Pass |
| `1` | `DO NOT SHIP` | Fail |
| `2` | Configuration error | Fail; the user must fix the config |
| `3` | Corpus error — missing, unsigned, tampered, or unsupported | Fail; a supply-chain problem, not a verdict |
| `4` | Internal error — a Clearance bug | Fail, and report it |
| `5` | `UNDETERMINED` and `--strict` | Fail; only with `--strict` |

Two deliberate choices: `UNDETERMINED` is exit `0` by default (it is a
first-class answer, printed loudly; add `--strict` to make it `5`), and only
`HIGH`-confidence blockers fail the build by default.

---

## Human output

```
CLEARANCE VERDICT — my-saas
========================================
SHIP:        DO NOT SHIP
BLOCKERS:    1
CONDITIONS:  2
SCANNED:     47 dependencies · 3 weight files · 2 upstream CLIs
CORPUS:      v1.4.2 (2026-09-20) · signed
```

A finding block:

```
[BLOCK]   firecrawl                    AGPL-3.0-only
          clause:  LICENSE §13 (network use)
          reason:  you run a MODIFIED version and expose it over HTTP
          evidence: node_modules/firecrawl/LICENSE:1-9
          fix:     swap to crawl4ai (Apache-2.0, same capability)
          confidence: HIGH
```

The `clause:` line is always present (INV-1), the `evidence:` line is always
present, and the `confidence:` line is always present (INV-2). The `fix:` line
appears only when a compatible alternative is known.

---

## Machine-readable output

`--format json` is the canonical contract. It is **additive only** within
`schema_version: 1`.

```json
{
  "schema_version": 1,
  "verdict": "DO_NOT_SHIP",
  "project": "my-saas",
  "summary": {
    "dependencies": 47,
    "weight_files": 3,
    "upstream_clis": 2,
    "blockers": 1,
    "conditions": 2,
    "undetermined": 0
  },
  "blockers": [],
  "conditions": [],
  "notes": [],
  "undetermined": [],
  "meta": {
    "tool_version": "1.0.0",
    "corpus_version": "1.4.2",
    "corpus_signed": true,
    "intent_hash": "sha256:9f2b...",
    "config_path": "clearance.config.yml",
    "scanned_at": 1790265600000,
    "duration_ms": 412,
    "build_commit": "a1b2c3d",
    "build_provenance": "SLSA-3"
  }
}
```

Rules that consumers can rely on:

- **Arrays are always present** (empty `[]`, never `null`), so no consumer has to
  null-check.
- `meta.scanned_at` and `meta.duration_ms` are the **only** non-deterministic
  fields. Zero them and the output is byte-identical across runs on the same
  `(project, intent, corpus)` (INV-6).
- Enum values are `UPPER_SNAKE_CASE`.
- Arrays are sorted explicitly and stably: `blockers`, `conditions` and `notes`
  by `(severity, dependency_id, kind, id)`; `undetermined` by its own sort key.
  Never map iteration order.

Validate output against the published schema, or print it with
`clearance check --json-schema`.

---

## The disclaimer

Every human-readable and Markdown verdict ends with:

> This is an informational finding based on the licence text as published on the
> date recorded. It is not legal advice. Ambiguous clauses are flagged as such.
> Important decisions should be reviewed by a qualified professional.

A test asserts this string is present. See [Not legal advice](not-legal-advice.md).
