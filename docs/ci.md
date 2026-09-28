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
**verifies its checksum against the release's `checksums.txt`**, runs
`clearance check`, and reports the exit code and the verdict. All judgement lives
in the binary, so the Action can never drift from the CLI.

It does not upload SARIF, post a pull-request comment, or touch the GitHub API
beyond resolving the release tag. Those are the caller's steps, and
[§4](#4-code-scanning) shows the code-scanning one.

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
        uses: K1ngBronxo/Clearance-dev/actions/check@v1
        with:
          path: '.'
          strict: 'false'
      - run: echo "verdict=${{ steps.clearance.outputs.verdict }}"
```

### 1.2 Action inputs and outputs

| Input | Default | Meaning |
|---|---|---|
| `version` | `latest` | Which release to download (`0.1.0-rc.2`, `v0.1.0-rc.2`, or `latest`) |
| `path` | `.` | The project to scan |
| `strict` | `false` | Pass `--strict`, so `UNDETERMINED` exits `5` and fails the job |
| `args` | *(empty)* | Extra `clearance check` arguments, for example `--fail-on CONDITION` |
| `sarif` | `false` | Also write a SARIF 2.1.0 file for code scanning — see [§4](#4-code-scanning) |
| `sarif-file` | `clearance.sarif` | Where to write it, relative to the workspace root |

| Output | Meaning |
|---|---|
| `verdict` | `SHIP`, `SHIP_CONDITIONAL`, `DO_NOT_SHIP`, or `UNDETERMINED` |
| `exit-code` | The process exit code (`0`–`5`) |
| `sarif-file` | Workspace-relative path of the SARIF file, for `upload-sarif` |

The Action **verifies the archive's SHA-256 against the release's `checksums.txt`
before extracting or running anything**. A mismatch aborts the step. To fail on
conditions rather than only blockers, pass `args: '--fail-on CONDITION'`; to fail
on unknowns, set `strict: 'true'`.

---

## 2. The exit-code contract

These five codes are **frozen forever** and will never be repurposed.
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
        uses: K1ngBronxo/Clearance-dev/actions/check@v1
        with:
          path: '.'
          strict: 'true'
          args: '--fail-on BLOCK --format json'
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
            "https://github.com/K1ngBronxo/Clearance-dev/releases/latest/download/clearance_0.1.0-rc.2_linux_amd64.tar.gz"
          curl -fsSL -o checksums.txt \
            "https://github.com/K1ngBronxo/Clearance-dev/releases/latest/download/checksums.txt"
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

## 4. Code scanning

The binary emits **SARIF 2.1.0** with `--format sarif`, which is what GitHub's
code scanning ingests. Findings then appear in a repository's **Security** tab
and as annotations on the pull request, each one carrying the clause it relies on
and a link to the licence text.

With the Action, set `sarif: 'true'` and add the upload step. The upload needs
`security-events: write`; the Action does not request it, so it stays visible in
your workflow:

```yaml
name: clearance
on: [pull_request]

permissions:
  contents: read

jobs:
  clearance:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write      # for upload-sarif, not for the Action
    steps:
      - uses: actions/checkout@v4

      - id: clearance
        uses: K1ngBronxo/Clearance-dev/actions/check@v1
        with:
          path: '.'
          sarif: 'true'

      - uses: github/codeql-action/upload-sarif@v4
        if: always()              # still upload when the job failed on a verdict
        with:
          sarif_file: ${{ steps.clearance.outputs.sarif-file }}
          category: clearance
```

`if: always()` matters: the run most worth seeing is the one that failed, and a
failed step skips every step after it by default.

One more thing is worth asserting, because the upload step can exit `0` having
*warned* that it rejected results. The server returns an id for a stored
analysis, so an empty id means the Security tab is empty while the run is green —
a silent pass, which is the one outcome this tool exists to prevent:

```yaml
      - name: Confirm code scanning stored the analysis
        if: always() && steps.upload.outcome == 'success'
        run: |
          id="${{ steps.upload.outputs.sarif-id }}"
          if [ -z "$id" ] || [ "$id" = "null" ]; then
            echo "::error::Code scanning returned no sarif-id; the analysis was not stored."
            exit 1
          fi
          echo "Code scanning stored the analysis: sarif-id=${id}"
```

That requires `id: upload` on the upload step.

### 4.1 Without the Action

The binary writes the file itself; no conversion step is involved.

```yaml
      - name: Clearance, with SARIF
        run: |
          set +e
          ./clearance check . --format sarif --output clearance.sarif
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

      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: clearance.sarif
```

### 4.2 What the mapping is

Every value comes from the binary; nothing is inferred by the Action or by a
workflow.

| Clearance | SARIF |
|---|---|
| `severity: BLOCK` / `CONDITION` / `NOTE` | `level: error` / `warning` / `note` |
| `kind` (for example `cc-by-nc-4.0.non-commercial`) | `ruleId` |
| `citation.url` | the rule's `helpUri` |
| `citation.section` and the excerpt | the rule's help text |
| `evidence[].path` | `locations[].physicalLocation.artifactLocation.uri` |
| `evidence[].line_start` | `region.startLine`, omitted when the evidence names a file and no line |
| an undetermined item | a result under `clearance.undetermined.<reason>` |

Two consequences worth knowing:

- **An undetermined dependency produces a result, not silence.** A dependency
  Clearance could not classify shows up in the Security tab as `warning`. An
  unknown that only existed in the log would be a false clean bill of health,
  which is the one output this tool exists to avoid.
- **Code scanning has no "condition" tier.** SARIF's three levels are what they
  are, so `SHIP CONDITIONAL` and `DO NOT SHIP` can both contain `error`-level
  results. The verdict is in the log and in the `verdict` output; the Security tab
  reports findings, not verdicts.

---

## 5. Common policies

| You want to… | Do this |
|---|---|
| Fail only on real blockers (default) | `--fail-on BLOCK` |
| Also fail on conditions | `--fail-on CONDITION` |
| Fail on anything unresolved | add `--strict` (exit `5` on `UNDETERMINED`) |
| Treat `MEDIUM` findings as blocking | add `--allow-medium-blockers` |
| Machine-readable output for another tool | `--format json` |
| Code-scanning annotations | `sarif: 'true'` on the Action, or `--format sarif`, then upload — see [§4](#4-code-scanning) |

---

## 6. Machine-readable output

`--format` takes four values:

| Value | Output |
|---|---|
| `human` | The default; the verdict block with the citation on every finding. |
| `json` | The canonical contract — see below. |
| `md` | Markdown, for a pull-request comment, a release note, or a report you paste somewhere. |
| `sarif` | SARIF 2.1.0, for code scanning — see [§4](#4-code-scanning). |

`--format json` is the canonical contract: **additive changes only** within
`schema_version: 1`, arrays always present (never `null`), and byte-identical
across runs once `meta.scanned_at` and `meta.duration_ms` are zeroed (INV-6). Every
verdict names the **corpus version** that produced it, so you can reproduce and
defend a decision months later.

```bash
clearance check . --format json --output verdict.json
jq '.verdict, .meta.corpus_version' verdict.json
```

If you consume it programmatically, the schema is printed by the binary itself —
there is no hosted copy:

```bash
clearance check --json-schema
```

---

## 7. Offline and air-gapped runners

Clearance makes **zero** outbound calls during `check` (INV-3). On a locked-down
runner:

```bash
clearance check . --offline --fail-on BLOCK
```

`--offline` is the default in this build, and it is already true of every
command. `clearance corpus update`, the one command that would need the network,
is **not implemented here** — running it is refused with a clear message rather
than silently accepted. You need a corpus file on disk: either bundled in the
release archive or placed yourself and pointed at with `CLEARANCE_CORPUS`.

---

## 8. Troubleshooting

| Symptom | Exit | Likely cause |
|---|---|---|
| `E-CFG-*` in the output | `2` | `clearance.config.yml` is missing or invalid — run `clearance doctor`, which names the field and why |
| `E-CORPUS-002/003/009` | `3` | Corpus unsigned, tampered, or a schema version this binary cannot read — run `clearance corpus verify` |
| An `E-INT-*` code | `4` | A Clearance bug — please report it via `SECURITY.md` or the issue tracker |
| `UNDETERMINED` and the job is red | `5` | `--strict` is set; either resolve the unknowns or drop `--strict` |
| The scan is slow the first time | — | The signed corpus bundle is read and verified once at startup |

For a support request, start with:

```bash
clearance doctor
```

It reports the binary version and build provenance, the corpus version and
signature status, whether the embedded public key matches, and whether the config
and platform paths resolve — the first five things anyone would ask.
