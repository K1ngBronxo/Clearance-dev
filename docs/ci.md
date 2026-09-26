# Wiring Clearance into CI

Clearance returns a **verdict**, not a report: `SHIP`, `SHIP CONDITIONAL`,
`DO NOT SHIP`, or `UNDETERMINED`, with a citation on every finding. In CI you
want one thing — a red build when the verdict is unacceptable — and the exit code
gives you exactly that.

There are two ways to run it: the **GitHub Action** (recommended; it verifies the
binary for you) and a **direct download** of the release binary.

---

## 1. The GitHub Action

The Action contains **no logic of its own**. It downloads the release binary,
**verifies its checksum against the signed `checksums.txt`**, runs
`clearance check`, uploads SARIF, and updates a PR comment. All judgement lives in
the binary, so the Action can never drift from the CLI
([`PLAN/01-ARCHITECTURE/09-interfaces-and-contracts.md`](../../PLAN/01-ARCHITECTURE/09-interfaces-and-contracts.md) §4).

### 1.1 A minimal workflow

```yaml
name: clearance
on: [pull_request]

permissions:
  contents: read

jobs:
  clearance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: clearance
        uses: clearance-dev/clearance/actions/check@v1
        with:
          path: '.'
          strict: 'false'
      - run: echo "verdict=${{ steps.clearance.outputs.verdict }}"
```

### 1.2 Action inputs and outputs

| Input | Default | Meaning |
|---|---|---|
| `version` | `latest` | Which release to download (`1.0.0`, `v1.0.0`, or `latest`) |
| `path` | `.` | The project to scan |
| `strict` | `false` | Pass `--strict`, so `UNDETERMINED` exits `5` and fails the job |
| `args` | *(empty)* | Extra `clearance check` arguments, for example `--fail-on CONDITION` |

| Output | Meaning |
|---|---|
| `verdict` | `SHIP`, `SHIP_CONDITIONAL`, `DO_NOT_SHIP`, or `UNDETERMINED` |
| `exit-code` | The process exit code (`0`–`5`) |

The Action **verifies the archive's SHA-256 against the release's `checksums.txt`
before extracting or running anything**. A mismatch aborts the step. To fail on
conditions rather than only blockers, pass `args: '--fail-on CONDITION'`; to fail
on unknowns, set `strict: 'true'`.

---

## 2. The exit-code contract

These five codes are **frozen forever** and will never be repurposed
([`PLAN/01-ARCHITECTURE/09-interfaces-and-contracts.md`](../../PLAN/01-ARCHITECTURE/09-interfaces-and-contracts.md) §2.3).
A pipeline written against them today will still work in five years.

| Code | Meaning | What CI should do |
|---|---|---|
| `0` | Verdict produced; no blocker (or CI gating disabled) | Pass |
| `1` | **`DO NOT SHIP`** — a blocking obligation | **Fail the build** |
| `2` | **Configuration error** — bad or missing `clearance.config.yml` | Fail; the user must fix the config, not the code |
| `3` | **Corpus error** — missing, unsigned, tampered, or unsupported corpus | Fail; a supply-chain problem, not a verdict |
| `4` | **Internal error** — a Clearance bug | Fail, and please report it |
| `5` | **`UNDETERMINED`** and `--strict` | Fail; only with `--strict` |

Two deliberate choices worth understanding:

- **`UNDETERMINED` is `0` by default.** "We could not classify this" is a
  first-class answer (INV-7), not a failure, and it is printed loudly. If your
  policy is "no unknowns in CI", add `--strict` to get code `5`.
- **Only `HIGH`-confidence blockers fail the build by default.** `MEDIUM` and
  `LOW` findings produce conditions or warnings (INV-2), because the failure mode
  this tool guards against is being *confidently wrong*. Promote `MEDIUM`
  blockers with `--allow-medium-blockers` if your policy demands it.

`--fail-on <sev>` sets the minimum severity that counts as a blocker for the
**exit code**, without changing the verdict itself.

---

## 3. Worked example — fail the build on `BLOCK`

The default already does this, but here is the explicit, self-contained version
that also fails on `UNDETERMINED`:

```yaml
name: clearance
on: [pull_request]

jobs:
  clearance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Clearance
        uses: clearance-dev/check-action@v1
        with:
          path: '.'
          fail-on: 'BLOCK'
          format: 'json'
          upload-sarif: 'false'
          comment: 'true'
```

If a `HIGH`-confidence `BLOCK` finding is present, `clearance check` exits `1`
and the job fails:

```
CLEARANCE VERDICT — my-saas
========================================
SHIP:        DO NOT SHIP
BLOCKERS:    1
...

[BLOCK]   firecrawl                    AGPL-3.0-only
          clause:  LICENSE §13 (network use)
          reason:  you run a MODIFIED version and expose it over HTTP
          evidence: node_modules/firecrawl/LICENSE:1-9
          fix:     swap to crawl4ai (Apache-2.0, same capability)
          confidence: HIGH
---
This is an informational finding based on the licence text as published on the
date recorded. It is not legal advice. ...
```

### 3.1 The same thing without the Action

Download and verify the binary, then branch on the exit code in a shell step:

```yaml
      - name: Install Clearance (checksum-verified)
        run: |
          set -euo pipefail
          curl -fsSL -o clearance.tar.gz \
            "https://github.com/clearance-dev/clearance/releases/latest/download/clearance_1.0.0_linux_amd64.tar.gz"
          curl -fsSL -o checksums.txt \
            "https://github.com/clearance-dev/clearance/releases/latest/download/checksums.txt"
          sha256sum -c --ignore-missing checksums.txt
          tar -xzf clearance.tar.gz

      - name: Run Clearance
        run: |
          set +e
          ./clearance check . --fail-on BLOCK --format sarif --output clearance.sarif
          code=$?
          set -e
          case "$code" in
            0) echo "clearance: ok" ;;
            1) echo "::error::clearance: DO NOT SHIP"; exit 1 ;;
            2) echo "::error::clearance: configuration error"; exit 1 ;;
            3) echo "::error::clearance: corpus error"; exit 1 ;;
            4) echo "::error::clearance: internal error — please report"; exit 1 ;;
            5) echo "::error::clearance: UNDETERMINED (strict)"; exit 1 ;;
            *) echo "::error::clearance: unexpected exit $code"; exit 1 ;;
          esac
```

`set +e` around the command is essential: the point is to *read* the exit code,
not to let the shell abort before you can classify it.

---

## 4. Common policies

| You want to… | Do this |
|---|---|
| Fail only on real blockers (default) | `--fail-on BLOCK` |
| Also fail on conditions | `--fail-on CONDITION` |
| Fail on anything unresolved | add `--strict` (exit `5` on `UNDETERMINED`) |
| Treat `MEDIUM` findings as blocking | add `--allow-medium-blockers` |
| Machine-readable output for another tool | `--format json` |
| Code-scanning annotations | `--format sarif` + upload SARIF |

---

## 5. Machine-readable output

`--format json` is the canonical contract: **additive changes only** within
`schema_version: 1`, arrays always present (never `null`), and byte-identical
across runs once `meta.scanned_at` and `meta.duration_ms` are zeroed (INV-6). Every
verdict names the **corpus version** that produced it, so you can reproduce and
defend a decision months later.

```bash
clearance check . --format json --output verdict.json
jq '.verdict, .meta.corpus_version' verdict.json
```

Validate it against the published schema at
`https://clearance.dev/schema/v1/verdict.json` (or `clearance check --json-schema`)
if you consume it programmatically.

---

## 6. Offline and air-gapped runners

Clearance makes **zero** outbound calls during `check` (INV-3). Only
`clearance corpus update` is opt-in network. On a locked-down runner:

```bash
clearance check . --offline --fail-on BLOCK
```

`--offline` makes even the corpus update impossible. You still need a corpus
file on disk — either bundled in the release or fetched once by your own trusted
mirror.

---

## 7. Troubleshooting

| Symptom | Exit | Likely cause |
|---|---|---|
| `E-CONFIG-*` in the output | `2` | `clearance.config.yml` is missing or invalid — run `clearance config validate` |
| `E-CORPUS-002/003/009` | `3` | Corpus unsigned, tampered, or a schema version this binary cannot read — run `clearance corpus verify` |
| An `E-INTERNAL-*` code | `4` | A Clearance bug — please report it via `SECURITY.md` or the issue tracker |
| `UNDETERMINED` and the job is red | `5` | `--strict` is set; either resolve the unknowns or drop `--strict` |
| The scan is slow the first time | — | The corpus is being fetched once; it is cached thereafter |

For a support request, start with:

```bash
clearance doctor
```

It reports the binary version and build provenance, the corpus version and
signature status, whether the embedded public key matches, and whether the config
and platform paths resolve — the first five things anyone would ask.
