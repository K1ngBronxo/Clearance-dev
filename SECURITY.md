# Security Policy

Clearance is a supply-chain-integrity tool: it reads untrusted dependency trees
and tells you whether it is safe to ship them. It follows that **Clearance's own
security is part of the product**. This document says what we consider a
vulnerability, how to report one, and what we will do about it.

The controls referenced below are C1–C10, the security controls this project
is built against. Each one is named in the package comment of the code that
enforces it, and asserted by a test in `internal/guard_security_test.go`.

---

## Two supply chains

Clearance has two things worth attacking, and both are in scope:

| # | Chain | An attacker's goal |
|---|---|---|
| 1 | **The binary** — source → CI → release → your machine | Ship a backdoored scanner |
| 2 | **The corpus** — YAML → build → sign → CDN → your machine | Inject a false obligation (a quiet, false `SHIP`) |

The corpus is the more attractive target, because subtly changing one
obligation's severity produces a wrong answer for every user without any obvious
signal. That is why the corpus is signed with an **offline** Ed25519 key that CI
never sees.

---

## Supported versions

Clearance and its corpus version independently. Security fixes are issued for:

| Component | Supported | Notes |
|---|---|---|
| Binary — latest minor (`1.x`) | ✅ | Fixes ship as a patch release |
| Binary — previous minor (`1.x-1`) | ✅ | Security fixes only, for 90 days |
| Binary — older minors | ❌ | Please upgrade; the binary is a single static file |
| Corpus — latest version | ✅ | The corpus is data; corrections ship continuously |
| Corpus — older versions | ✅ (readable) | Entries are deprecated, never removed (INV-9) |
| `corpus-build` | ❌ | Internal tool; never released |
| Hosted vetting API (V2) | — | Not yet shipped |

The CLI verifies the corpus signature on **every** load, so a stale local corpus
is never a silent integrity gap.

---

## Reporting a vulnerability

**Please use GitHub's private vulnerability reporting**, from the repository's
**Security → Report a vulnerability** tab. That keeps the report private and
threaded.

If you cannot use GitHub, email **security@clearance.dev**. Encrypt sensitive
details with our PGP key:

```
Fingerprint: XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX
```

*(Replace with the published fingerprint before launch; the key is the same one
published in the release notes.)*

Please include: the version (`clearance version`), the platform, a minimal
reproduction, and the impact you believe it has. A proof-of-concept is welcome
but not required — a precise description of the bug is more valuable than a
polished exploit.

---

## Our commitments

| Stage | Target |
|---|---|
| Acknowledge your report | within **3 business days** |
| Initial triage and severity assessment | within **7 business days** |
| Status update to you | at least every **14 days** until resolved |
| Fix or documented mitigation | within the coordinated-disclosure window below |
| Credit | in the advisory and the changelog, unless you prefer to stay anonymous |

We will tell you honestly if we cannot reproduce the issue, or if we judge it out
of scope, and why.

---

## Coordinated disclosure — 90 days

We follow a **90-day coordinated-disclosure window** from the date we acknowledge
your report.

- We aim to fix and release well before the deadline.
- If a fix is genuinely complex, we will agree a **short, specific** extension with
  you rather than let the window lapse silently.
- **Exception — active exploitation:** if a vulnerability is being exploited in
  the wild, or a working exploit is public, we will publish a fix and an advisory
  as fast as possible and shorten the window accordingly. The safety of users
  outranks the schedule.
- We will publish a public advisory (GitHub Security Advisory) and, for
  supply-chain events, a post-mortem. A supply-chain tool that hides an incident
  has no credibility.

---

## Scope — what counts as a vulnerability here

Because Clearance is a **static scanner that reads files**, "the scanner executes
attacker-controlled code" is the central fear, and the controls exist to make it
impossible. Broadly: **anything that lets a scanned project, a corpus bundle, or a
third party make Clearance do something it did not declare it would do.**

### In scope

| Class | Examples | Control |
|---|---|---|
| **Code execution / elevation** | RCE via a malicious `package.json`/YAML/JSON; a predicate that can call a function; `plugin.Open` | C1, C2, C7 |
| **Arbitrary file read / traversal** | `../` escape, symlink escape, reading outside the project root, a TOCTOU on the containment check | C3, INV-4 |
| **Denial of service** | YAML alias/billion-laughs bomb, deeply nested JSON (`E-PARSE-006`), a manifest that hangs the scanner past the timeout | C2 |
| **Unwanted network egress** | Any outbound call other than the opt-in corpus update; bypassing `--offline`; a redirect to another host | C4 |
| **Corpus integrity** | A tampered `corpus.json` accepted; a signature-verification bypass; a bundle with a `sha256` that does not match | C5, INV-9 |
| **Supply-chain integrity of the binary** | A release whose checksum/provenance does not verify; a build that embeds a secret; a published artefact that is not reproducible from the tag | C6, SLSA |
| **Privilege / capability escape** | The MCP server reading outside its declared root; an MCP tool that writes or makes a call | C9 |
| **Confidentiality** | Secrets or `.env` contents appearing in output; absolute paths leaking the user's home directory | privacy tests |
| **Verdict integrity caused by a bug** | A crash, memory-safety bug, or parser defect that can be turned into a **false `SHIP`** or a false `DO NOT SHIP` for an attacker-chosen input | INV-1, INV-2, INV-7 |
| **Our dependencies** | A known CVE in a direct or transitive dependency that is reachable | C10, `govulncheck` |

### Out of scope

- **The legal correctness of a corpus entry** — a wrong or debatable reading of a
  licence is an *accuracy* issue, not a security vulnerability. It goes through
  the public wrong-verdict process described in
  [`docs/not-legal-advice.md`](docs/not-legal-advice.md), which is faster and
  produces a permanent fixture. Report it as a normal issue.
- **A dependency of *your* project having a licence you dislike.** Clearance
  reports it; that is the product working.
- **An ambiguous licence clause being flagged as ambiguous.** That is correct
  behaviour (INV-2).
- **Attacks that require code execution on the user's machine already**, or that
  rely on the user running Clearance on a directory they do not trust *and*
  ignoring the tool's own output.
- **Social engineering**, physical access to the maintainer's machine, and the
  offline signing key's physical storage (that is a hardware problem, not a
  software bug — though a weakness in the *ceremony* around it is in scope).
- **Denial of service that requires the victim to feed Clearance a project they
  control** and that only affects that one run (the tool is local and stateless;
  please still report it if it is cheap to trigger).
- **The hosted vetting API** — not shipped yet; the section is added when it is.
- **Findings produced by automated scanners with no demonstrable impact.**

### If you are unsure

Report it. We would rather triage a non-issue than miss a real one. When in
doubt, ask us privately before going public.

---

## Safe harbour

We will not pursue or support legal action against anyone who, in good faith,
researches and reports a vulnerability under this policy — provided they:

- only test against **their own** installation or the released binaries,
- do not access, modify or exfiltrate other people's data,
- do not degrade the service for others, and
- give us a reasonable chance to fix the issue before disclosure.

We consider such research authorised, and we will make that clear to any third
party who asks.

---

## Bounties

Clearance is a solo, part-time project with no revenue yet, so **there is no
monetary bounty programme**. We will credit you in the advisory and the changelog
(unless you prefer otherwise), and we will say thank you. We would rather be
honest about this than imply a reward we cannot pay.

---

## Verifying what you downloaded

Before running a release binary:

```bash
sha256sum -c checksums.txt
```

That confirms the archive arrived intact against the published list. It does
**not** establish who published it, and today nothing else does either: the
archives served from `clearancedev.vercel.app/dl` and from the `v0.1.0-rc.2`
release have no cosign signature, no build provenance and no attestation. When
a signed release is cut, this section will carry the `cosign verify-blob`
command for it, with
`--certificate-identity-regexp 'github.com/K1ngBronxo/Clearance-dev'` and the
GitHub OIDC issuer. Until then, treat the checksum as an integrity check only.

The GitHub Action verifies a downloaded binary before running it. The repository
is public, so the Action is consumable via `uses:`.

---

## Supply-chain incidents

If the corpus signing key, a release artefact, or a dependency is compromised, we
rotate the key, withdraw or re-sign every affected artefact, publish a
security advisory, and ship a public post-mortem.
