# Contributing to Clearance

Thanks for helping. Clearance is a licence / weights / ToS clearance scanner
distributed as a single static binary with **zero runtime dependencies**. Two
properties matter more than anything else here, and they shape every rule below:

1. **Every verdict carries a citation.** An uncited finding is an opinion, and
   opinions are what every competitor already produces.
2. **The tool must be safe to point at hostile input.** It reads attacker-
   controlled dependency trees, so it must never execute, never install, never
   phone home, and never read outside the project root.

If a change weakens either, it will not be merged — however useful it looks.

---

## 1. Prerequisites

- **Go 1.25.13+** — what `go.mod` declares
- **Git**
- On Windows: **Git Bash** (the founder's environment; there is no Docker, no
  WSL, no container anywhere in the workflow)
- Optional: `golangci-lint`, `goreleaser`

Nothing else. The build is `go build`; everything else is files.

---

## 2. The development loop

```bash
git clone https://github.com/K1ngBronxo/Clearance-dev
cd clearance

make test          # guard tests + arch test + go test ./... -race
make fixtures      # every fixture produces its expected verdict
make build         # produces ./clearance (or ./clearance.exe)
./clearance check ./fixtures/npm-agpl-saas
make dogfood       # clearance check . on Clearance itself
```

**`make dogfood` passes, and that is checked rather than asserted.** It runs
`./clearance check . --fail-on BLOCK` against this repository and exits **0**: the last observed run
reported `BLOCKERS: 0`, 2 dependencies and 2 upstream CLIs.

It used to fail, and the history is worth keeping because the fix was a *decision, not a patch*. The
scan stopped at `E-CFG-001`, because there was no `clearance.config.yml` in the repository root —
and a tool whose whole thesis is that a verdict requires a declared intent cannot verdict on itself
without one. Inventing those values inside the tool would have been Clearance assuming facts about a
project instead of being told them, which is exactly what INV-7 forbids it from doing to anyone else.
So the owner of the product's posture stated them, in `clearance.config.yml`, and that file is now
part of the repository: `commercial`, `licence_model: source-available`, `distributed: true`,
`network_exposed: false`, each with the reason it is the honest answer.

Two things about that file a contributor should know. Its `policy.ignore` entries carry a written
reason because `E-SCAN-020` refuses an unexplained ignore — a blocker hidden without a stated reason
is indistinguishable from a blocker hidden — and one of them excludes `fixtures/**`, which is why the
scan reports a couple of dependencies rather than the whole test corpus. And the corpus this runs
against is the **unsigned** YAML tree at `corpus/`, not a signed bundle: `check` completes on an
unsigned corpus with a degradation, which is why dogfooding works in this repository without the
offline signing key.

Run `make help` for the full target list. The target list is frozen; a few targets are maintainer-only
and are marked `[maintainer]`.

### The rule: every step ends with a green test suite

**Do not leave the tree red.** Work in small increments and make each increment
green before moving on. A red tree means the next person cannot tell *their*
breakage from *yours*. If you must land something incomplete, land it behind a
skipped test with a linked issue — never as a failing test.

---

## 3. The invariant discipline

There are ten invariants, and **each is paired with the test that enforces it**
(`internal/guard_invariants_test.go`).
An invariant without a test is a wish, so:

- **`make guard` runs the whole gate** — 23 guards in four groups: the invariant
  guards (`GUARD_INVARIANTS`), the security spine (`GUARD_SECURITY`), the
  build-integrity guards (`GUARD_BUILD`) and the corpus guards (`GUARD_CORPUS`).
  In CI, the `guard` job runs first and gates everything else. If it is red,
  nothing else matters.
- **A change to an invariant is a change to its test, in the same PR.**
- The guard tests are named in `Makefile` in those four `GUARD_*` variables, and
  CI calls `make guard` rather than repeating the list. **You do not have to
  remember to add a guard to the gate** — two meta-guards fail the build if you
  forget, in both directions: `TestEveryGuardTestNamedInTheMakefileExists` fails
  when a named guard does not exist, `TestNoGuardIsLeftOutOfTheGate` fails when a
  real guard exists that no name reaches, and `TestEveryRunNameExists`
  extends the first check to every `-run` argument anywhere in the repo, including
  the workflow files.

  This is not ceremony. `go test -run <name>` exits 0 when the name matches
  nothing, so a gate can report success while running nothing — and this
  repository has shipped that defect **six times** in six different mechanisms
  (`-X` stamps, `-run` names, a directory with no Go files, a non-constant
  initialiser, `-bench .` with no benchmarks, and a CI step whose `-run` pattern
  matched one test out of 108). Each one is recorded rather than hidden.

### Architecture layering

`internal/arch_test.go` parses the import graph and enforces the layer rules
(L0 → L5) and the banned imports.
The rules themselves are the `layers` map in that test.
`make arch` runs it. A violation fails the build. When the pressure to "just
import it here" arrives — and it will — this test is the thing that says no.

The banned-import rules, enforced by the arch test, the `depguard` rules in
`.golangci.yml`, and the `banned-imports` CI job (mirrored by `make lint`), are:

- no `os/exec`, `syscall` or `plugin` in `internal/scanner` (INV-3);
- no `net/http` anywhere except `internal/cli/netclient.go` (C4);
- no direct `yaml.Unmarshal` / `json.Unmarshal` / `NewDecoder` in `internal/` —
  use `internal/safeyaml` / `internal/safejson` (INV-10);
- no `os.Open` / `os.ReadFile` / `os.ReadDir` in `internal/` except
  `internal/safefs`, and no read-mode `os.OpenFile(…, os.O_RDONLY)` there either
  — one function opens files (INV-4, C3). Writing an output file with
  `os.OpenFile` is legitimate (that is the render path, `E-RENDER-001`), so it is
  not banned wholesale — only the read-mode bypass is;
- no `errors.New` / bare `fmt.Errorf` in `internal/` — every error is a typed
  `cerr` with a code (INV-5).

The first four rules constrain the shipped product's runtime, so `*_test.go` is
excluded from the grep-based enforcement (`make lint` and the `banned-imports` CI
job). The guards are themselves Go programs that must read the tree:
`internal/arch_test.go` parses every file's imports, so it calls
`os.ReadDir` / `os.ReadFile`, and it contains the string `"net/http"` because
that is precisely what it searches for. The structural form of both rules is
still enforced on test files by that same arch test, which walks every `.go` file
and excludes only itself.

---

## 4. Corpus changes carry a citation

The corpus (`corpus/**/*.yml`) is the asset, and the source of truth. A corpus
change is not "done" until:

1. **It cites a primary source** — a URL and a section. Every obligation and
   every trap points at the clause it came from. No citation, no entry.
2. **It has a fixture.** Every trap should get a minimal repository under
   `fixtures/` that triggers it, plus the expected verdict in that fixture's
   `expected.yml` (which must carry a `why` — the prose claim the fixture is
   making). The fixture *is* the specification of the trap.

   **This rule is now met.** All **12** declared traps are fired by a fixture —
   `12 declared, 12 fired, 0 acknowledged` — and `trapsWithNoFixture` in
   `internal/guard_corpus_test.go` is **empty**. That list is a **ratchet**: it
   may only shrink. `TestEveryTrapIsEitherFiredByAFixtureOrListed` enumerates
   every trap and fails unless it is fired by a fixture or named in the list, so
   adding a trap means writing its fixture in the same PR. The guard pins three
   failure directions: a new trap with no fixture and no entry, an entry for a
   trap that is no longer declared, and an entry for a trap that now has a
   fixture. An empty list is the goal, not evidence that the guard stopped
   working.
3. **Confidence never rises without a correction record.** Provenance degrades
   freely; an *upgrade* needs a `Correction` block with a reason and evidence,
   appended to the corpus changelog (INV-8). A silent upgrade fails to load.
4. **`make corpus-verify` passes** — schema, citations, predicate type-checking,
   and no-silent-upgrade (`TestConfidenceUpgradeRequiresCorrection`). Note that
   the no-silent-upgrade check works *within* a bundle; comparing against a
   previous corpus version needs `corpus-build --validate --previous`, which the
   CLI does not yet expose, so `--validate` announces `E-CORPUS-012` to say the
   comparison did not happen.

To change a corpus entry by hand you do **not** need the signing key: `make
corpus` compiles an unsigned bundle for testing. `make corpus-sign` requires the
**offline** key and is never run in CI.

**The four corpus targets are maintainer-only** (`make corpus`, `make
corpus-verify`, `make corpus-sign`, `make corpus-dist`), and so is `make
corpus-dist-check`. They all invoke `corpus-build/`, the compiler and signer,
which is deliberately not published because it contains the Ed25519 signing code.
So a checkout of the published repository cannot run them, and `make help` there
does not list them. What still reads the corpus in such a checkout is `make
guard`, whose corpus group fails on a predicate that does not type-check, a trap
with no fixture, or a notice code that contradicts its declared meaning; the
compiler's own `--validate` rules run in the maintainer tree, before a release.

---

## 5. Adding a dependency

The target is **fewer than 10 direct dependencies**, and every dependency is a
licence question Clearance must answer about itself. That is control C10.

A new **direct** dependency requires a written justification in the PR: what it
does, why the standard library cannot, its licence, and its maintenance status.
No copyleft dependencies — a GPL dependency in a licence scanner would be
self-parody. `govulncheck` runs in CI and must stay green.

---

## 6. Determinism

A verdict must be a pure function of `(project files, config, corpus version)`
(INV-6): no clock, no randomness, no map-iteration order. `TestVerdictDeterminism`
renders the same fixture 100 times — through both the human and the JSON
renderer — and asserts the bytes are identical every time.

**There are no golden files.** `internal/report/testdata/` exists but is empty,
`internal/report` has no test files, and no `-update` flag is implemented
anywhere in the module. So the command that used to be documented here,

```bash
go test ./internal/report -update   # does not work
```

fails with "no Go files in …". It was removed rather than left as a plausible
instruction that cannot be followed.

What this means for a renderer change: there is no captured baseline to diff
against, so **the review of a renderer change is the diff of the source, not the
diff of an output file**. The determinism property is enforced; the *stability
of the rendered text across releases* is not captured anywhere. That is a real
gap, and it is recorded here rather than papered over with a
command that does not run.

---

## 7. The "one job that would have caught it" rule

**Every production incident produces a new CI job or test.**

When a wrong verdict reaches a user: re-read the clause, add a fixture that
reproduces the exact case, correct the corpus with a `Correction` block, and
record it in the changelog. The fixture is permanent, so the same mistake can
never recur silently.

---

## 8. Commits and PRs

- **Sign your commits.** Branch protection requires signed commits; `git commit
  -S` (or a configured signing key) is expected.
- Keep PRs focused. One concern per PR.
- Never skip hooks or bypass signing (`--no-verify`, `--no-gpg-sign`). If a hook
  fails, fix the cause.
- The PR description should state the *why*, and link the issue or clause it
  addresses.
- **CI must be green before merge.** There are no exceptions.

---

## 9. What not to change lightly

| Surface | Promise |
|---|---|
| CLI flags | Additive only; removing/renaming a flag is a major version |
| Exit codes (`0`–`5`) | **Frozen forever** |
| JSON output | Additive within `schema_version: 1` |
| Corpus schema | Major-version bump; the binary refuses one it cannot read |

The exit-code contract is in [`docs/ci.md`](docs/ci.md); the other three are
frozen as stated above.

---

## 10. Security

Do **not** open a public issue for a vulnerability. Follow
[`SECURITY.md`](SECURITY.md): a 90-day coordinated-disclosure window, private
reporting, and a safe-harbour commitment.

---

## 11. Licence

By contributing you agree your contributions are licensed under the same licence
as the project: the **Functional Source License 1.1, ALv2 Future License**
(`FSL-1.1-ALv2`), which is **source-available, not open source**. See
[LICENSE](LICENSE) and [NOTICE](NOTICE).
