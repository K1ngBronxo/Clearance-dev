# Corpus authoring guide

> **Status:** corpus schema `v1`. The binary that reads this is frozen to that
> schema; a bundle declaring a higher version is refused with `E-CORPUS-003`.
>
> **The rule this whole directory exists to serve (ADR-003):** all judgement
> lives in the data, none in the code. A wrong interpretation is fixed by
> editing YAML, not by shipping a new binary. That makes every entry a
> verdict-affecting artefact — vague data is a vague answer for every user.

This guide is the contract for everything below. Where this guide and the code
disagree, **the Go types in `internal/corpus/corpus.go` and the
validator in `internal/corpus/load.go` win** — they are what actually decodes
your file. See "Known spec/code discrepancies" at the end.

---

## 1. Directory layout

| Kind | Directory | Addressed by | Files today |
|---|---|---|---|
| licence | `corpus/licences/` | `spdx_id` | 12 |
| trap | `corpus/traps/` | `id` | 11 files / 12 traps |
| tos | `corpus/tos/` | `platform` | 6 |
| territory | `corpus/territories/` | `code` | 4 |

One YAML document per file for licences, ToS and territories. A `traps/*.yaml`
file may hold **one trap** or a **sequence of traps** (`- id: ...`); both are
accepted. Only direct children of each directory are read — a nested
subdirectory is not a corpus subdirectory.

---

## 2. The YAML subset you must stay inside

`safeyaml` is a strict subset parser. It is not a YAML library wrapper: the
dangerous syntax does not exist in the grammar.

* Supported: block mappings, block sequences, plain / `'single'` / `"double"`
  scalars, block scalars `>` and `|` (with `-`/`+` chomping), flow sequences
  `[a, b]`, flow mappings `{ k: v }`, `#` comments, and the scalar types
  `bool` (`true/false/yes/no/on/off`), `int`, `float`, `null`, `string`.
* **Rejected structurally:** tags (`!foo`, `!!foo` → `E-PARSE-009`), anchors,
  aliases and merge keys (`&a`, `*a`, `<<` → `E-PARSE-008`).
* Rejected: tabs used for indentation; duplicate mapping keys (a mistake, not a
  last-wins); an unknown key in an entry (`E-CORPUS-004`).
* **Unknown keys are errors.** `confidencee:` does not silently load with no
  confidence; it fails the build. Field names below are exact.

Indent with spaces only. Two spaces per level is the convention here.

---

## 3. `licence` entry

```yaml
id: licence.apache-2.0            # licence.<spdx-lowercased>, unique
spdx_id: Apache-2.0               # unique across the corpus (E-CORPUS-005 on dup)
name: Apache License 2.0
family: permissive                # see the closed set below
osi_approved: true
fsf_libre: true
permissiveness: 5                 # integer 1..5, required; 5 = most permissive
obligations: [ ... ]              # may be empty, but should not be
traps: [ ... ]                    # entry-local traps; may be empty
citation: { url: ..., section: ... }
confidence: HIGH                  # HIGH | MEDIUM | LOW
last_verified: "2026-09-20"       # ISO-8601, must not be in the future
correction: { ... }               # only when confidence ROSE (INV-8)
```

| Field | Type | Rule |
|---|---|---|
| `id` | string | required, `licence.<slug>` |
| `spdx_id` | string | required, unique |
| `name` | string | required |
| `family` | enum | `permissive`, `weak-copyleft`, `strong-copyleft`, `network-copyleft`, `source-available`, `non-commercial`, `custom` |
| `osi_approved` | bool | required |
| `fsf_libre` | bool | required |
| `permissiveness` | int | **required, 1..5** — the divergence check compares this |
| `obligations` | []Obligation | required (may be empty) |
| `traps` | []Trap | required (may be empty) |
| `citation` | CitationRef | required; `url` and `section` both non-empty |
| `confidence` | enum | required; there is no default |
| `last_verified` | date | required; not in the future (`E-CORPUS-008`) |
| `correction` | Correction | only if confidence rose vs. the previous version |

`permissiveness` is ordinal, not a score: it exists so the code-vs-weights check
can ask "is the code more permissive than the weights?". Suggested values —
permissive 5, weak-copyleft 2–3, strong/network-copyleft 1, source-available 1,
non-commercial 1, custom 2–4.

---

## 4. `Obligation`

```yaml
- id: apache-2.0.notice-retention      # unique within the entry (E-POLICY-008)
  kind: ATTRIBUTION                    # see the kinds below
  severity: CONDITION                  # BLOCK | CONDITION | NOTE | INFO
  when:                                # required, a predicate (never null)
    op: "=="
    field: use.distributed
    value: true
  message: >
    One or two sentences. 10..600 characters after trimming. Must name the
    clause it rests on, not just assert a rule.
  citation:
    url: https://www.apache.org/licenses/LICENSE-2.0
    section: "§4(d)"
    excerpt: "..."                     # optional, <= 400 chars
    retrieved_at: "2026-09-20"         # optional
  confidence: HIGH
  fix:                                 # optional; only when an alternative is known
    action: attribute                  # replace | rebrand | attribute | configure | remove
    suggestion: "Copy the NOTICE file contents into your own NOTICE."
    alternative: Apache-2.0            # optional
    confidence: HIGH
```

Obligation kinds (the closed vocabulary from the schema spec): `ATTRIBUTION`,
`SOURCE_DISCLOSURE`, `LICENCE_INCLUSION`, `STATE_CHANGES`, `NON_COMMERCIAL`,
`NETWORK_DISCLOSURE`, `SCALE_GATE`, `TERRITORIAL_GATE`, `BRAND_EXCLUSION`,
`PATENT_GRANT`, `PLATFORM_TOS`.

Severity weights (higher blocks harder): `BLOCK` 3, `CONDITION` 2, `NOTE` 1,
`INFO` 0. Confidence weights: `HIGH` 2, `MEDIUM` 1, `LOW` 0.

---

## 5. `Trap`

```yaml
id: trap.lgpl.static-linking
title: "Static linking against an LGPL library"     # required, non-empty
summary: >
  The failure mode, in prose. A trap that is attached to a licence entry is
  evaluated per dependency; a trap in traps/ is global and is evaluated against
  the graph or looked up by id.
when:                                               # required, a predicate
  op: and
  l: { field: dep.licence.family, op: "==", value: weak-copyleft }
  r: { field: use.distributed, op: "==", value: true }
scope: dependency                                   # dependency (default) | graph
severity: CONDITION
citation: { url: ..., section: ... }
confidence: HIGH
fix: { action: configure, suggestion: "...", confidence: HIGH }   # optional
```

### `scope`

How the trap is evaluated. It is **required in the shipped corpus** and
defaults to `dependency` when absent, so a hand-written corpus is not rejected
for omitting the obvious field.

| Value | Meaning |
|---|---|
| `dependency` | `when` is evaluated once per dependency, against the same context an obligation uses (`dep.*`, `use.*`, the resolved entry). The finding's id is `<dep-id>#<trap-id>`. |
| `graph` | The trap cannot be decided from one dependency's facts. `internal/policy` carries a check for it and looks it up by id. The corpus still supplies severity, confidence and citation — the *shape* of the check is code, the *judgement* is data. |

`scope: graph` is only valid for a trap in `traps/`. A trap attached to a
licence entry has exactly one dependency to be evaluated against, so declaring
it graph-scoped is a load error (`E-CORPUS-004`).

**Two traps are graph-scoped and are referenced by name in
`internal/policy/crosscheck.go`. They must keep these exact spellings or the
checks silently do nothing:**

* `trap.code-weights-divergence`
* `trap.declared-vs-actual-conflict`

For `trap.code-weights-divergence`, the corpus supplies severity, confidence
and citation; the engine escalates `CONDITION` → `BLOCK` when the weight licence
is `non-commercial` or `source-available` and the intent declares commercial
use. So the base severity here is `CONDITION`, not `BLOCK`.

The pair is held in place by `TestEveryGraphScopedTrapHasAnEngineCheck`, which
fails in both directions: a `scope: graph` trap the engine has no check for, and
an engine check naming a trap that is not declared graph-scoped. The second
direction is what stops this list from becoming a list of ids that used to
matter.

---

## 6. `tos` entry

```yaml
platform: github                    # slug; unique
display_name: GitHub
summary: >
  What the platform terms govern, and — importantly — what they do not: the
  licence of the code hosted there.
restrictive_clauses:
  - id: github.tos.api-terms
    text_summary: "One-line summary of the clause."
    severity: CONDITION
    citation: { url: ..., section: ... }
    confidence: MEDIUM              # a curated summary, so usually MEDIUM
last_verified: "2026-09-18"
staleness_days: 180                 # past this age the confidence auto-downgrades
```

ToS confidence is `MEDIUM` by default because a ToS entry is a *curated
summary*, not the primary text. The engine distinguishes the two, and past
`staleness_days` a clause is downgraded one level so a stale `MEDIUM` can no
longer block. **Do not add a `kind:` key** — it is not in the Go type and will
fail the load (see the discrepancies section).

---

## 7. `territory` entry

```yaml
code: EU                            # ISO-3166 alpha-2 or a region group; unique
name: European Union
notes: >
  One paragraph on what this jurisdiction adds on top of the licence.
gates:
  - id: eu.database-right
    summary: "The EU sui generis database right can apply independently of the licence."
    severity: NOTE                  # territorial findings are rarely BLOCK
    citation: { url: ..., section: ... }
    confidence: MEDIUM
```

Territorial gates are almost always `NOTE` or `CONDITION`. The tool does not
know a user's use case well enough to block on a jurisdiction, and pretending
otherwise is the "confidently wrong" failure it exists to avoid.

---

## 8. The predicate language (`when`)

A `when` is one of four shapes. It is deliberately not Turing-complete: no
loops, no function calls, no arithmetic beyond comparison, nesting ≤ 8.

```yaml
# comparison
when: { op: "==", field: use.distributed, value: true }

# conjunction / disjunction / negation
when:
  op: and            # or | not (use `x:` for not)
  l: { field: dep.kind, op: "==", value: weights }
  r: { field: use.commercial, op: "==", value: true }

# literal (always applies)
when: true
```

Operators: `==`, `!=`, `>`, `>=`, `<`, `<=`, `in`, `contains`.

**The field registry is closed.** A predicate may only reference these 17 paths,
and the value must type-check against the field's declared type — comparing a
bool field to the string `"true"` fails the build (`E-POLICY-004`).

| Field | Type | Source |
|---|---|---|
| `use.commercial` | bool | intent |
| `use.licence_model` | enum: `closed-source` \| `open-source` \| `source-available` \| `dual` \| `internal-only` | intent |
| `use.modified` | bool | intent |
| `use.network_exposed` | bool | intent |
| `use.distributed` | bool | intent |
| `use.saas` | bool | intent |
| `scale.mau` | int | intent |
| `scale.employees` | int | intent |
| `scale.revenue_eur` | int | intent |
| `territories` | []string | intent |
| `project.name` | string | intent |
| `dep.kind` | enum: `package` \| `vendored` \| `weights` \| `upstream_cli` \| `asset` | dependency |
| `dep.ecosystem` | string | dependency |
| `dep.licence.family` | enum (the seven families) | dependency |
| `dep.licence.permissiveness` | int | dependency |
| `dep.name` | string | dependency |
| `dep.version` | string | dependency |

Notes: a bool field compares only with `==`/`!=` and a bool literal
(unquoted). `territories` supports `contains "EU"` and `in ["EU", "US"]`. An
enum/string field takes `==`/`!=` with a string. `int` fields take the ordered
operators.

---

## 9. Confidence and INV-8

* There is **no default confidence**. An entry without one fails validation.
* **INV-8: confidence may fall freely but may only rise with a `correction`
  record.** When a corpus is loaded with its previous version, any entry whose
  confidence rose must carry a `correction` whose `from` exactly matches the
  previous level, or the load fails with `E-CORPUS-006`.

```yaml
correction:
  reason: "Re-read the canonical text rather than a secondary summary."
  evidence: "https://www.mozilla.org/en-US/MPL/2.0/"   # a URL or a quote
  from: MEDIUM
  to: HIGH
  corrected_at: "2026-09-18"
  corrected_by: "maintainer:corpus-team"
```

Without this friction, confidence laundering is invisible: a guess becomes
`MEDIUM` in one commit and `HIGH` in the next, and nobody notices that no new
evidence ever arrived.

---

## 10. Honesty rules (these are the product)

* **INV-1 — no obligation without a citation.** Every citation needs a real URL
  and a section identifier. `CitationRef.Validate` refuses an empty URL or
  section, and `cite.Index.Resolve` refuses a citation that was never
  registered.
* **Never fabricate a section number.** If you are not sure the clause is in
  `§4`, cite the section you *are* sure of, or describe the clause and set
  `confidence: LOW`. A fabricated pinpoint is the worst defect this corpus can
  carry — worse than an admitted gap, because it is a lie a reader cannot see.
* Prefer canonical sources: `spdx.org/licenses/...`, `www.gnu.org/licenses/...`,
  `www.apache.org/licenses/LICENSE-2.0`, `opensource.org/license/...`,
  `creativecommons.org/licenses/...`, and a platform's own terms URL.
* **Make each `(url, section)` pair unique across the corpus.** Two entries
  citing the same pair produce an `E-CORPUS-004` notice (the first registration
  wins). The shipped corpus carries none; if you need to cite the same clause
  from two places, give the second a descriptive section label.
* `message` is 10–600 characters. A one-word message is not an explanation; a
  2,000-word one is not read. Write sober prose: no marketing superlatives.
* Dates: `last_verified` is ISO-8601 and must not be in the future.

---

## 11. Validation checklist (what the loader enforces)

1. `id`, `spdx_id`, `citation`, `confidence`, `last_verified` present.
2. `spdx_id` unique across the corpus.
3. Every obligation and trap has a `citation` and a `confidence`.
4. Every `when` references a known field path (`E-POLICY-003`).
5. Every `when` type-checks against the field's type (`E-POLICY-004`).
6. Predicate nesting ≤ 8 (`E-POLICY-005`).
7. `last_verified` not in the future (`E-CORPUS-008`).
8. A confidence rise has a matching `correction` (`E-CORPUS-006`).
9. `citation.section` non-empty (rule 10).
10. `message` length 10–600 (rule 11).
11. Obligation ids unique within their entry (`E-POLICY-008`).

---

## 12. Worked examples

**A licence with a conditional obligation** (excerpt):

```yaml
id: licence.mit
spdx_id: MIT
family: permissive
permissiveness: 5
obligations:
  - id: mit.attribution
    kind: ATTRIBUTION
    severity: CONDITION
    when: { op: "==", field: use.distributed, value: true }
    message: >
      MIT requires the copyright notice and the permission notice to travel
      with every copy or substantial portion you distribute.
    citation:
      url: https://opensource.org/license/mit
      section: "Permission notice"
    confidence: HIGH
```

Note the predicate: attribution only bites on *distribution*. A private,
internal build raises nothing, and the corpus says so rather than warning
anyway.

**A global trap the engine looks up by id:**

```yaml
id: trap.code-weights-divergence
title: "The code is permissive but the weights are not"
when:
  op: and
  l: { field: dep.kind, op: "==", value: weights }
  r: { field: dep.licence.family, op: "!=", value: permissive }
severity: CONDITION     # the engine escalates to BLOCK for NC/source-available
citation:
  url: https://huggingface.co/docs/hub/model-cards
  section: "Licence metadata"
confidence: HIGH
```

---

## 13. Known spec/code discrepancies

The prose above is aspirational in two places; the Go types are authoritative
and this corpus follows them.

1. The spec's `tos` example (§6) includes a `kind: hosted-service` field. There
   is **no `kind` field on `ToSEntry`**, so including it fails the load with
   `E-CORPUS-004` (unknown key). This corpus omits it.
2. The spec's ToS detection text (§5) refers to a
   per-clause `when` predicate. There is **no `when` field on `Clause`**; a ToS
   clause applies whenever its platform is invoked. This corpus omits it.

Both are reported to the maintainer rather than worked around silently: a
schema doc that does not match the decoder is a trap for the next author.
