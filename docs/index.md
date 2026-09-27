# Clearance documentation

Clearance is a licence, model-weights and platform-terms scanner. You point it at
a project, declare how you intend to use it, and it returns a **verdict** — not a
report:

- **`SHIP`** — no known obligation contradicts the intent you declared.
- **`SHIP CONDITIONAL`** — usable, subject to stated obligations (attribute this,
  rebrand that, stay under a user threshold).
- **`DO NOT SHIP`** — a `HIGH`-confidence blocking obligation was found.
- **`UNDETERMINED`** — something could not be classified. Unknown is never
  rounded toward `SHIP`.

Every finding carries a **citation** to the clause it relies on, and a
**confidence** level. Only a `HIGH`-confidence finding can block a build.

---

## Start here

| Page | What it covers |
|---|---|
| [Install](install.md) | Step-by-step: download, verify, unpack, PATH setup, first scan, troubleshooting. |
| [Configuration](config.md) | `clearance.config.yml` — the declared intent. |
| [Verdicts](verdicts.md) | The four verdict classes, the confidence gate, and the exit codes. |
| [CI](ci.md) | Wiring Clearance into a pipeline, and the GitHub Action. |
| [Not legal advice](not-legal-advice.md) | What Clearance does and does not claim. |

---

## The four rules

The verdict is a fold over the findings, in a fixed order. The first rule that
matches wins:

1. any `HIGH`-confidence `BLOCK` finding -> `DO NOT SHIP`
2. else any undetermined item -> `UNDETERMINED`
3. else any condition -> `SHIP CONDITIONAL`
4. else -> `SHIP`

The order is normative. A definite block is never diluted by an unrelated
unknown, and an unknown risk outranks a known requirement because the
alternative is a false pass. The properties each rule must satisfy are asserted
in `internal/verdict`, which is where the algebra is implemented.

---

## What Clearance is not

- It is **not legal advice**, and it says so on every verdict. See
  [Not legal advice](not-legal-advice.md).
- It is **not** a report generator. The primary output type is a verdict;
  reports are renderings of it.
- It **never executes** the project it scans, never runs a package manager, and
  never makes an outbound call. The one command that would need the network, the
  signed corpus update, is not implemented in this build.

---

## Repository layout

The code lives under `internal/` in six strictly layered packages, enforced by an
import-graph test that fails the build on an upward import. The knowledge — the
licence and trap definitions — lives in `corpus/` as YAML, because all judgement
is data, not code. The decisions that shaped this are recorded in
[`docs/adr/`](adr/).
