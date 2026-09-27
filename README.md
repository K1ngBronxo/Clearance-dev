# Clearance

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
`amd64` and `arm64`. Download the archive for your platform from
[clearancedev.vercel.app/docs#install](https://clearancedev.vercel.app/docs#install) or
from the [v0.1.0-rc.2 release](https://github.com/K1ngBronxo/Clearance-dev/releases/tag/v0.1.0-rc.2),
unpack it, and run it — the signed corpus bundle is inside the archive. Building
from source needs Go 1.25.13 or later. See [docs/install.md](docs/install.md).

---

## Documentation

| Page | What it covers |
|---|---|
| [docs/index.md](docs/index.md) | Overview and the four rules |
| [docs/install.md](docs/install.md) | Download, verify, or build |
| [docs/config.md](docs/config.md) | The declared intent |
| [docs/verdicts.md](docs/verdicts.md) | Verdict classes, confidence gate, exit codes, JSON |
| [docs/ci.md](docs/ci.md) | Wiring it into a pipeline |
| [docs/not-legal-advice.md](docs/not-legal-advice.md) | What a verdict does and does not claim |
| [docs/adr/](docs/adr/) | The decisions that shaped the code |

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

This is the **first foundation slice**. The L0 primitives, the decision layer
(the verdict algebra, the predicate language, the policy engine), the corpus
loader and verifier, the CLI entry point (`cmd/clearance`) and the corpus
compiler (`corpus-build`) are implemented and tested. The MCP server
(`internal/mcp`) is implemented: it publishes four read-only tools over stdio,
scoped to a single `fs.read` capability rooted at the directory the server was
started in. No binary release has been cut yet. See
[CHANGELOG.md](CHANGELOG.md).

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
