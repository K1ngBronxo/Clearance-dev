# Configuration — the declared intent

Clearance refuses to guess how you intend to use a project. That intent lives in
`clearance.config.yml`, and it is the single most important input: an obligation
that depends on an undeclared fact evaluates to `UNKNOWN`, and an `UNKNOWN`
obligation makes the verdict `UNDETERMINED` rather than `SHIP`.

The schema is frozen at `schema_version: 1`.

---

## A minimal valid config

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

That is the smallest config that produces a meaningful verdict. Everything else
is refinement.

---

## Discovery and precedence

Clearance looks for the config in this order:

| # | Path | Notes |
|---|---|---|
| 1 | `--config <path>` | Explicit. If it does not load, that is an error — there is no fallback. |
| 2 | `./clearance.config.yml` | Project root. |
| 3 | `./.clearance/config.yml` | Project dotdir. |
| 4 | `~/.config/clearance/config.yml` | User default. Merged **underneath** the project config. |
| 5 | *(none)* | `E-CFG-001`, exit `2`. |

A user-level config supplies defaults; a project config overrides it
field-by-field. When the project config overrides a field the user config set
differently, Clearance says so — it emits `E-CFG-009` (a warning, not a failure)
naming the field. The resolved config is hashed into `meta.intent_hash` in the
JSON output, so a verdict can be tied to the exact facts that produced it.

If both `clearance.config.yml` and `.clearance/config.yml` exist, the first wins
and the second is reported. Two project configs is a mistake a reader should see.

---

## `use` — required

All six fields are required. They are the minimum needed to evaluate a
conditional obligation, and omitting one does not make the obligation "not
apply" — it makes it `UNKNOWN`.

| Field | Type | Why it matters |
|---|---|---|
| `commercial` | bool | Gates every non-commercial licence (CC-BY-NC, "research only"). |
| `licence_model` | enum | `closed-source`, `open-source`, `source-available`, `dual`, or `internal-only`. Gates copyleft disclosure duties. `source-available` is for a licence that publishes its source without being OSI-approved — FSL, BUSL, Elastic — and it is not a synonym for `open-source`. |
| `modified` | bool | The AGPL/GPL section 13 trigger, together with `network_exposed`. |
| `network_exposed` | bool | The AGPL section 13 trigger, together with `modified`. |
| `distributed` | bool | Whether binaries or source leave your control. Triggers distribution duties. |
| `saas` | bool | Distinguishes a service from a shipped product. |

A missing field is refused with `E-CFG-002`, listing every missing field at once.

---

## `project` — optional

| Field | Type | Notes |
|---|---|---|
| `name` | string | Appears in the verdict header. Defaults to the directory name. |
| `description` | string | Context only. Not used in any decision. |

---

## `scale` — conditionally required

| Field | Type | Notes |
|---|---|---|
| `mau` | int | Monthly active users. Required if any scanned dependency has a scale-gated licence. |
| `employees` | int | Some licences gate on company size. |
| `revenue_eur` | int | Some licences gate on revenue. |

**Omitted is not zero.** An omitted `mau` is `UNKNOWN`; a declared `mau: 0` is a
claim that you have no users, which is only valid for a pre-launch project. The
two hash differently into `meta.intent_hash`, because they mean different things.

---

## `territories` — conditionally required

ISO-3166 alpha-2 country codes, or one of the region groups `EU`, `EEA`, `US`,
`GB`, `APAC`, `global`.

**Omitted is not `global`.** If you omit `territories`, every territorial clause
evaluates to `UNKNOWN` and the verdict tells you to declare them. Assuming
global reach would be the tool making a decision on your behalf. An invalid entry
is refused with `E-CFG-004`.

---

## `policy` — optional

| Field | Type | Effect |
|---|---|---|
| `never_allow` | list of strings | SPDX ids that are always blocking, regardless of the corpus. |
| `block_on` | list of severities | Which severities fail CI. Default `["BLOCK"]`. |
| `allow_if` | list of rules | Whitelist one named licence under a predicate. |
| `ignore` | list of rules | Exclude paths from the scan. Requires a `reason`. |

**Policy can only escalate or narrowly whitelist. It can never globally weaken a
corpus severity.** Two things are refused with `E-CFG-006`:

- a `block_on` list that omits `BLOCK` — that would mean a blocker no longer
  fails CI;
- an `allow_if` rule that names a wildcard licence (`*`, `all`, `any`,
  `everything`, or anything containing `*` or `?`) — a whitelist must name what
  it whitelists.

An invalid SPDX id in `never_allow` is refused with `E-CFG-007`, because a typo
in a safety list silently disables the rule, and that is the worst place for a
typo to be invisible.

### Ignore rules

```yaml
policy:
  ignore:
    - path: "vendor/legacy/**"
      reason: "internal tooling, never distributed"
```

- `reason` is **mandatory** (`E-CFG-005`). An unexplained ignore is how a blocker
  gets hidden.
- An ignore may **not** target the project root or a lockfile (`E-CFG-010`).
- Matching supports an exact path, a trailing `/**` (everything under a
  directory) and a trailing `/*` (direct children). It deliberately does not
  support arbitrary glob syntax: a pattern a reader cannot verify by eye is a
  pattern that will one day hide a blocker.
- If an ignore matches more than half the tree, Clearance warns (`E-SCAN-020`),
  because a broad ignore is a plausible way to hide a dependency.

---

## Validation errors

Every configuration error is fatal with exit code `2`, because no intent means
no answer. The table below is the taxonomy.

| Code | Trigger |
|---|---|
| `E-CFG-001` | No config found in any search path |
| `E-CFG-002` | One or more required `use.*` fields missing |
| `E-CFG-003` | `licence_model` is not one of the four enum values |
| `E-CFG-004` | `territories` contains an invalid code or region group |
| `E-CFG-005` | An `ignore` rule has no `reason` |
| `E-CFG-006` | A policy rule would weaken a corpus severity globally |
| `E-CFG-007` | `never_allow` contains an invalid SPDX id |
| `E-CFG-008` | `schema_version` is unknown or newer than the binary supports |
| `E-CFG-009` | A project and user config disagree on a field *(warning)* |
| `E-CFG-010` | An `ignore` rule targets the project root or a lockfile |
| `E-PARSE-003` | The config is not valid YAML |
| `E-PARSE-004` | The config exceeds 256 KiB |

---

## Generating a starter config

```bash
clearance config init
```

This writes a commented `clearance.config.yml`, inferring only `project.name`
and whether the project looks network-exposed. Every field that changes a verdict
is left as an explicit `CHANGE ME`, because the tool does not guess intent.

To check a config without scanning:

```bash
clearance config validate
```
