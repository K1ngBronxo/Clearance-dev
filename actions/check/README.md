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

## Outputs

| Output | Meaning |
|---|---|
| `verdict` | `SHIP`, `SHIP_CONDITIONAL`, `DO_NOT_SHIP`, or `UNDETERMINED`. Empty if no verdict was produced. |
| `exit-code` | The process exit code (`0`–`5`). The five codes are a frozen contract. |

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
