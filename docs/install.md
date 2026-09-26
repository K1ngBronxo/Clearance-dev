# Install

Clearance ships as a **single static binary** with no runtime dependencies: no
interpreter, no container, no shared library. There is nothing to install
alongside it.

Supported platforms, all built from the same tag:

| OS | Architectures |
|---|---|
| Linux | `amd64`, `arm64` |
| macOS | `amd64`, `arm64` |
| Windows | `amd64`, `arm64` |

---

## Option A — the GitHub Action

The Action downloads the binary, verifies it, and runs it. See
[`actions/check/README.md`](../actions/check/README.md).

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: clearance-dev/clearance/actions/check@v1
    with:
      path: '.'
```

---

## Option B — download a release binary

Replace `1.0.0` with the version you want, and `linux_amd64` with your platform.
The archive name is `clearance_<version>_<os>_<arch>`, and it is a `.zip` on
Windows and a `.tar.gz` elsewhere.

```bash
set -euo pipefail

version=1.0.0
os=linux          # linux | darwin | windows
arch=amd64        # amd64 | arm64
base="https://github.com/clearance-dev/clearance/releases/download/v${version}"

curl -fsSL -o "clearance_${version}_${os}_${arch}.tar.gz" \
  "${base}/clearance_${version}_${os}_${arch}.tar.gz"
curl -fsSL -o checksums.txt "${base}/checksums.txt"

# Verify the archive's SHA-256 against the release's checksum list.
grep -F "clearance_${version}_${os}_${arch}.tar.gz" checksums.txt \
  | sha256sum -c -

tar -xzf "clearance_${version}_${os}_${arch}.tar.gz"
```

On macOS, use `shasum -a 256 -c -` in place of `sha256sum -c -`.

### Verify the checksum list itself (recommended)

`checksums.txt` is signed with cosign in the release workflow. To verify the
signature over the list, and not only the archive against the list:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'github.com/clearance-dev/clearance' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature checksums.txt.sig checksums.txt
```

The release also carries SLSA build provenance and a CycloneDX SBOM. The
provenance is what lets you confirm the binary was built by this repository's
release workflow from the tag you expect, rather than merely that it matches a
checksum.

### Confirm what you have

```bash
clearance version
```

This prints the tool version, the corpus version and signature status, and the
build provenance (commit and SLSA level).

---

## Option C — build from source

You need **Go 1.25.13 or later** — the version `go.mod` declares. Nothing else.

```bash
git clone https://github.com/clearance-dev/clearance
cd clearance
make build          # produces ./clearance (or ./clearance.exe on Windows)
./clearance version
```

The build is `CGO_ENABLED=0` with `-trimpath`, so the result is a static binary
with no absolute paths embedded. `make test` runs the guard tests first (the ten
invariants plus the security spine) and then the full suite with the race
detector.

On Windows the supported shell is **Git Bash**. There is no Docker and no WSL
anywhere in the workflow, deliberately — the tool must build and run on a plain
machine.

---

## The corpus

The binary contains the corpus **public** key and the verification code; it does
not contain the corpus itself. A corpus bundle
(`corpus.json`, `corpus.version.json`, `corpus.json.sig`) is a separate,
signed artefact. The signature is verified on **every** load, so a local corpus
cannot be tampered with silently.

If you use the release binary and the release bundles a corpus, it is used
automatically. To point Clearance at a corpus elsewhere, set `CLEARANCE_CORPUS`
to its directory.

`clearance corpus update` fetches a signed bundle over the network. It is the
**only** operation in the product that makes an outbound call, and it is opt-in.
Everything else, including a full scan, works offline.
