<div align="center">

# Clearance

**A licence, model-weights and platform-terms scanner that returns a verdict, not a report.**

*Can I ship this — and if not, exactly which clause blocks me?*

[![ci](https://github.com/K1ngBronxo/Clearance-dev/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/K1ngBronxo/Clearance-dev/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/K1ngBronxo/Clearance-dev?include_prereleases&sort=semver)](https://github.com/K1ngBronxo/Clearance-dev/releases)
[![licence](https://img.shields.io/badge/licence-FSL--1.1--ALv2-blue)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/K1ngBronxo/Clearance-dev)](go.mod)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](go.mod)
[![platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-lightgrey)](docs/install.md)

</div>

---

A licence, model-weights and platform-terms scanner that returns a **verdict**,
not a report: *can I ship this, and if not, exactly which clause blocks me?*

Point it at a project, declare how you intend to use it, and it tells you one of
four things — `SHIP`, `SHIP CONDITIONAL`, `DO NOT SHIP`, or `UNDETERMINED` — with
a citation on every finding and a confidence level that decides whether the
finding may block.

---

## What it is

Clearance reads a project's dependency manifests, lockfiles, vendored licences,
model-weight metadata and platform terms, and folds what it finds into a single
decision against your declared intent.

Three properties carry the design:

- **Every finding cites the clause it relies on.** A finding without a citation is
  an opinion, and opinions are what every competitor already produces.
- **Confidence is mandatory.** Only a `HIGH`-confidence finding can block a build.
  A tool that does not know must not make a decision that costs someone money.
- **Unknown is a first-class answer.** `UNDETERMINED` is never rounded toward
  `SHIP`. A false green light is the most dangerous output this kind of tool can
  produce.

The scanner **never executes** the project it reads, **never runs a package
manager**, and **never makes an outbound call during a scan**. The only network
operation in the product is the opt-in, signed corpus update.

---

## The verdict

The verdict is a fold over the findings, applied in a fixed order. The first rule
that matches wins:

1. any `HIGH`-confidence `BLOCK` finding -> **`DO NOT SHIP`**
2. else any undetermined item -> **`UNDETERMINED`**
3. else any condition -> **`SHIP CONDITIONAL`**
4. else -> **`SHIP`**

The order is normative. A definite block is never diluted by an unrelated
unknown, and an unknown risk outranks a known requirement because the alternative
is a false pass. The exit codes are a frozen contract: `0` ok, `1` `DO NOT SHIP`,
`2` config error, `3` corpus error, `4` internal error, `5` `UNDETERMINED` with
`--strict`.

The full statement is in [docs/verdicts.md](docs/verdicts.md) — the four rules, why an
unknown outranks a condition, and the exit-code table.

---

## What it prints

Real output, unedited, from the released `0.1.0-rc.2` binary run against a
one-dependency project whose dependency declares no licence:

```text
CLEARANCE VERDICT — clearance.config.yml
========================================
SHIP:        UNDETERMINED
BLOCKERS:    0
CONDITIONS:  1
SCANNED:     1 dependency
CORPUS:      2026.09.2 · signed ✓
REASON:      1 item could not be classified

CONDITIONS

[BLOCK]         left-pad                        no licence declared
                clause:     For users
                source:     https://choosealicense.com/no-permission/
                finding:    No licence means all rights reserved
                reason:     A dependency with no licence statement is not free to use...
                evidence:   package.json
                trap:       trap.licence.absent-all-rights-reserved
                gate:       severity BLOCK → CONDITION because confidence is MEDIUM
                confidence: MEDIUM — clause text is ambiguous
                fix:        Locate a licence for the dependency, obtain written permission,
                            or remove the dependency.

UNDETERMINED

[UNDETERMINED]  left-pad                        licence unresolved
                error:      E-SCAN-011 — no licence could be resolved for left-pad
                evidence:   package.json
                action:     Read the file, or contribute a corpus entry
```

Two things in that output are the product:

- The trap was classified `BLOCK`, and then **downgraded to a condition because
  the confidence was only `MEDIUM`** — the clause is genuinely ambiguous. A
  finding that cannot be defended does not get to stop a build.
- The verdict is `UNDETERMINED`, not `SHIP`. The dependency has no licence, so
  the honest answer is *we do not know*, and `UNDETERMINED` never rounds toward
  a green light.

`--format json` emits the same result with the citation URL, the verbatim
excerpt, the evidence path, the predicate that fired, and the corpus version and
signature state, for a pipeline to consume.

---

## Quick start

**1. Declare your intent** in `clearance.config.yml`:

```yaml
schema_version: 1
use:
  commercial: true
  licence_model: closed-source
  modified: true
  network_exposed: true
  distributed: false
  saas: true
```

All six `use.*` fields are required: an obligation that depends on an undeclared
fact evaluates to `UNKNOWN`, and an unknown obligation makes the verdict
`UNDETERMINED` rather than `SHIP`. See [docs/config.md](docs/config.md).

**2. Run it:**

```bash
clearance check .
```

**3. Or wire it into CI**, which is what the exit code is for:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: K1ngBronxo/Clearance-dev/actions/check@v1
    with:
      path: '.'
      strict: 'false'
```

See [docs/ci.md](docs/ci.md) and
[`actions/check/README.md`](actions/check/README.md).

---

## Install

A single static binary, no runtime dependencies, on Linux, macOS and Windows,
`amd64` and `arm64`. The archive holds the program and the signed corpus bundle
together — download it, check it, unpack it, and run it.

**New to this?** [**docs/install.md**](docs/install.md) is a step-by-step guide
written for people who have never installed a command-line tool: which of the six
archives to pick, how to verify the download, how to put `clearance` on your
PATH on Windows, macOS or Linux, and what to do when something goes wrong.

The short version, if you already know your way around a terminal:

```bash
# 1. download your platform's archive — see docs/install.md for the name
curl -fsSLO https://clearancedev.vercel.app/dl/clearance_0.1.0-rc.2_linux_amd64.tar.gz
curl -fsSL -o checksums.txt https://clearancedev.vercel.app/dl/checksums.txt

# 2. verify it, and stop if this does not print OK
grep -F clearance_0.1.0-rc.2_linux_amd64.tar.gz checksums.txt | sha256sum -c -

# 3. unpack
tar -xzf clearance_0.1.0-rc.2_linux_amd64.tar.gz

# 4. run
./clearance version
```

The same six archives are attached to the
[v0.1.0-rc.2 release](https://github.com/K1ngBronxo/Clearance-dev/releases/tag/v0.1.0-rc.2);
either source works, and the checksums are identical on both. Building from source
needs Go 1.25.13 or later — see [docs/install.md](docs/install.md#option-b--build-from-source).

---

## Documentation

| Page | What it covers |
|---|---|
| [docs/index.md](docs/index.md) | Overview and the four rules |
| [docs/install.md](docs/install.md) | Step-by-step install: pick your archive, verify it, PATH setup, troubleshooting |
| [docs/config.md](docs/config.md) | The declared intent |
| [docs/verdicts.md](docs/verdicts.md) | Verdict classes, confidence gate, exit codes, JSON |
| [docs/ci.md](docs/ci.md) | Wiring it into a pipeline |
| [docs/not-legal-advice.md](docs/not-legal-advice.md) | What a verdict does and does not claim |
| [docs/adr/](docs/adr/) | The decisions that shaped the code |

One page is published outside this repository, because it is for reading rather than for building:
[**which model weights you can ship**](https://clearancedev.vercel.app/weights) — the weights half of
the corpus, every row carrying the clause it turns on, and a note on how much of its own citation
base has been checked against the source.

---

## Optional AI explanation — off by default, and never part of the verdict

`--ai` adds a plain-language explanation of the findings already produced. It
does not change the verdict, and it is **off unless you ask for it**:

```bash
clearance check . --ai                        # explain with your configured provider
clearance check . --ai --ai-provider ollama   # a local model: no key, no egress
clearance check . --ai --ai-output ai.json    # also write the explanation to a file
```

**The engine decides; the model explains.** The AI step runs after the verdict
is already fixed, reads the findings, and writes prose about them. It cannot add
a finding, remove one, or change a severity — so an unavailable model degrades
to no explanation, never to a different answer.

You bring the key. Set the provider's environment variable, pipe one in with
`--api-key-stdin`, or put it in `~/.config/clearance/keys.yml` at mode `0600`.
There are **20 providers**, including four keyless local ones — `ollama`,
`lmstudio`, `llamacpp` and `vllm` — and `openai-compatible` for anything else
that speaks the OpenAI chat-completions shape. Run `clearance explain --providers`
for the whole list, or `clearance explain E-CFG-001` for any error code the
binary can raise.

If Clearance's own claim is that it never makes an outbound call during a scan,
that claim has to survive this feature, so it does, and you can check it on your
own machine. `clearance doctor` prints the two facts separately:

```text
  network:   disabled - no outbound calls are possible in this build
  ai egress: not armed - no AI call is possible until --ai arms it
```

Egress starts disarmed and only `--ai` arms it, for the explanation step alone.
Without the flag there is no code path that reaches the network. And if the
model is unreachable, the run says so and stops — the observed failure mode is a
note like `E-AI-004 — Cannot reach '127.0.0.1:11434' … The verdict is unaffected.`

---

## Not legal advice

Clearance reports what licence texts say and applies stated, published rules to a
declared intent. It is an informational tool. It is not a lawyer, and it does not
give legal advice.

> Every finding quotes the licence clause it relies on and links to the source.
> Where a clause is ambiguous, Clearance says so and shows you the text rather
> than guessing. For any decision with material consequences, consult a qualified
> professional.

The full statement is in [docs/not-legal-advice.md](docs/not-legal-advice.md).

---

## Status

**`v0.1.0-rc.2` is cut and downloadable**, with archives for Linux, macOS and
Windows on `amd64` and `arm64`, and a `checksums.txt` beside them. It is a
release candidate, not a `1.0`: the corpus is still being audited, and the
archives are checksum-verified but carry **no cosign signature and no build
provenance** yet — that is stated plainly in [SECURITY.md](SECURITY.md) rather
than left for you to discover.

The L0 primitives, the decision layer (the verdict algebra, the predicate
language, the policy engine), the corpus loader and verifier, the CLI entry
point (`cmd/clearance`) and the corpus compiler (`corpus-build`) are implemented
and tested. The MCP server (`internal/mcp`) is implemented: it publishes four
read-only tools over stdio, scoped to a single `fs.read` capability rooted at
the directory the server was started in. CI runs the full suite on Linux, macOS
and Windows — including the Windows short-name and macOS `/var` symlink cases
that a POSIX-only test run does not reach. See [CHANGELOG.md](CHANGELOG.md).

The repository layout is the architecture. Where a choice deviates from the obvious
one, the reason is recorded in [docs/adr/](docs/adr/).

---

## Architecture

The code lives under `internal/`, in six strictly layered packages. An
import-graph test (`internal/arch_test.go`) parses every import and **fails the
build** on an upward or sideways import, so the layering is enforced rather than
hoped for. The knowledge — the licence and trap definitions — lives in `corpus/`
as YAML, because all judgement is data, not code: a wrong interpretation is fixed
by editing a data file, not by shipping a binary.

The module has **zero third-party dependencies**, deliberately. Every dependency
of a supply-chain tool is itself a supply-chain question the tool would have to
answer. See [ADR-001](docs/adr/ADR-001-go-static-zero-deps.md).

---

## Building and contributing

Requires **Go 1.25.13 or later** — the version `go.mod` declares, and an older
Go will fetch it automatically. Nothing else. On Windows, use **Git Bash**.

```bash
make test     # guard tests first, then go test ./... -race
make lint     # golangci-lint + the banned-import checks
make build    # ./clearance
make dogfood  # clearance check . on Clearance itself — must pass
```

Run `make help` for the full target list. A few targets are maintainer-only and are
marked `[maintainer]`; they need the corpus signing key and the corpus compiler,
neither of which is published, so they are absent from this repository and
`make help` here does not name them. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
invariant discipline and the rules a change must satisfy.

---

## Security

Clearance's own security is part of the product. Do not open a public issue for a
vulnerability: follow [SECURITY.md](SECURITY.md) — private reporting, a 90-day
coordinated-disclosure window, and a safe-harbour commitment.

---

## Licence

**Functional Source License 1.1, ALv2 Future License** (`FSL-1.1-ALv2`) — read
that as **source-available, not open source**. The source is public and the
licence is not OSI-approved. On the second anniversary of the first release of a
version, that version's grant becomes an irrevocable Apache-2.0 licence.

See [LICENSE](LICENSE) and [NOTICE](NOTICE). The compiled corpus is distributed
separately from the binary and is licensed CC-BY-4.0; it is a data artefact, not
a code dependency, and is not covered by the FSL grant.
