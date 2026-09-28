# Clearance GitHub Action

A composite action that downloads a **checksum-verified** Clearance release
binary and runs `clearance check`. It contains no judgement of its own: all
decisions live in the binary, so the Action can never drift from the CLI.

## Usage

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
      - name: Show the verdict
        run: echo "verdict=${{ steps.clearance.outputs.verdict }}"
```

## Inputs

| Input | Required | Default | Meaning |
|---|---|---|---|
| `version` | no | `latest` | The release to download (`0.1.0-rc.2`, `v0.1.0-rc.2`, or `latest`). |
| `path` | no | `.` | The project directory to scan. |
| `strict` | no | `false` | Pass `--strict`, so `UNDETERMINED` exits 5 and fails the job. |
| `args` | no | *(empty)* | Extra `clearance check` arguments, for example `--fail-on CONDITION`. |
| `sarif` | no | `false` | Also write a SARIF 2.1.0 file for code scanning. Uploading it is your step — see below. |
| `sarif-file` | no | `clearance.sarif` | Where to write that file, relative to the workspace root. |

## Outputs

| Output | Meaning |
|---|---|
| `verdict` | `SHIP`, `SHIP_CONDITIONAL`, `DO_NOT_SHIP`, or `UNDETERMINED`. Empty if no verdict was produced. |
| `exit-code` | The process exit code (`0`–`5`). The five codes are a frozen contract. |
| `sarif-file` | Workspace-relative path of the SARIF file, for handing straight to `upload-sarif`. Empty unless `sarif: 'true'` and the file was written. |

## Code scanning

Set `sarif: 'true'` and the Action writes a SARIF 2.1.0 file for GitHub's code
scanning. Findings then appear in the **Security** tab and as annotations on the
pull request, with the licence clause as the rule and its citation URL as the
rule's help link — the same findings as the terminal, in a different envelope.

```yaml
permissions:
  contents: read
  security-events: write      # required by upload-sarif, not by this Action

steps:
  - uses: actions/checkout@v4

  - id: clearance
    uses: K1ngBronxo/Clearance-dev/actions/check@v1
    with:
      path: '.'
      sarif: 'true'

  - uses: github/codeql-action/upload-sarif@v3
    if: always()              # upload even when the job failed on a verdict
    with:
      sarif_file: ${{ steps.clearance.outputs.sarif-file }}
      category: clearance
```

Two details that matter:

- **The Action does not upload.** Writing the file needs no permission; uploading
  needs `security-events: write`, and asking for that on the caller's behalf would
  silently widen what the Action can do. The path is handed back as an output and
  the upload is a step you can see.
- **The SARIF is the binary's own.** The Action runs `clearance check --format
  sarif` — a second scan of the same tree — rather than converting the JSON it
  already has. There is no mapping layer between the two, so what the Security
  tab shows cannot disagree with what the terminal printed. If the binary cannot
  write the file, the step warns and leaves `sarif-file` empty; it never
  fabricates one, and it never changes the verdict the job already reported.

## What the Action does, in order

1. Resolves the release tag (via the GitHub API for `latest`).
2. Downloads the platform archive (`linux`/`darwin`/`windows` x `amd64`/`arm64`)
   and the release's `checksums.txt`.
3. **Verifies the archive's SHA-256 against `checksums.txt` before extracting or
   running anything.** A mismatch aborts the step.
4. Runs `clearance check <path> --format json --output <file>` plus `--strict`
   and any `args`.
5. Fails the job on exit `1` (`DO NOT SHIP`), `2` (config), `3` (corpus), `4`
   (internal), and on `5` only when `strict: 'true'`.
6. If `sarif: 'true'`, runs the scan once more with `--format sarif` and reports
   the file path.

## Permissions and scope

The Action makes exactly two kinds of outbound call: the release download and,
for `version: latest`, one GitHub API request to resolve the tag. It does not
upload SARIF, post a comment, or touch any GitHub API beyond that. Uploading
SARIF to code scanning is the caller's step, and it needs
`security-events: write` in the caller's workflow.

The published releases carry no cosign signature today, so this Action can only
verify the archive against `checksums.txt` — integrity, not provenance. When a
release is signed, [`SECURITY.md`](../../SECURITY.md) is where the
`cosign verify-blob` command for `checksums.txt` will live.

See [`docs/ci.md`](../../docs/ci.md) for the exit-code contract and worked
examples, including the same flow without the Action.
