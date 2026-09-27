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

## Option A — download an archive

This is the fastest path and it works today. The archives are published by the
project site at `clearancedev.vercel.app`. Each one bundles the binary together with
the signed corpus bundle, so the first command after unpacking works with no
further setup.

Replace `0.1.0-rc.2` with the version you want, and `linux_amd64` with your
platform. The archive name is `clearance_<version>_<os>_<arch>`, and it is a
`.zip` on Windows and a `.tar.gz` elsewhere.

```bash
set -euo pipefail

version=0.1.0-rc.2
os=linux          # linux | darwin | windows
arch=amd64        # amd64 | arm64
ext=tar.gz        # tar.gz everywhere except windows, which is zip
base="https://clearancedev.vercel.app/dl"

name="clearance_${version}_${os}_${arch}.${ext}"
curl -fsSL -o "$name" "${base}/${name}"
curl -fsSL -o checksums.txt "${base}/checksums.txt"

# Verify the archive's SHA-256 against the published checksum list.
grep -F "$name" checksums.txt | sha256sum -c -

tar -xzf "$name"
```

On macOS, use `shasum -a 256 -c -` in place of `sha256sum -c -`.

### Windows (PowerShell)

PowerShell aliases `curl` to `Invoke-WebRequest`, which rejects `curl`'s flags,
and it ships no `unzip`. Call `curl.exe` and unpack with `Expand-Archive`. Run
the lines one at a time: `&&` is a syntax error before PowerShell 7.

```powershell
$version = '0.1.0-rc.2'
$arch    = 'amd64'   # amd64 | arm64
$base    = 'https://clearancedev.vercel.app/dl'
$name    = "clearance_${version}_windows_${arch}.zip"

curl.exe -fsSL -o $name "$base/$name"
curl.exe -fsSL -o checksums.txt "$base/checksums.txt"

$want = (Select-String -Path checksums.txt -Pattern ([regex]::Escape($name))).Line.Split(' ')[0]
$got  = (Get-FileHash $name -Algorithm SHA256).Hash.ToLower()
if ($got -ne $want) { throw "SHA-256 mismatch for $name" }

Expand-Archive -Path $name -DestinationPath . -Force
.\clearance.exe version
```

In Git Bash the block above still works as written, with two changes: `curl` is
the real binary there, and the archive unpacks with `unzip -q "$name"`.

The checksum list is served over TLS from the same host as the archives, so it
proves the download arrived intact, not that the publisher is who they claim.
Repository- or registry-level provenance is planned; until it exists, treat the
checksum as an integrity check only.

---

## Option B — build from source

Needs **Go 1.25.13 or later** — the version `go.mod` declares — and nothing
else. The published tree is the repository root, so the module is directly
under it.

```bash
git clone https://github.com/K1ngBronxo/Clearance-dev
cd Clearance-dev
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

## GitHub releases

`v0.1.0-rc.2` is published. The same six archives plus `checksums.txt` are
attached to it, so either base URL works — swap `base` in Option A for:

```
https://github.com/K1ngBronxo/Clearance-dev/releases/download/v0.1.0-rc.2
```

The release assets carry **no cosign signature, no build provenance and no
CycloneDX SBOM**. The `release.yml` workflow that would produce all three cannot
run against the published tree: its corpus pre-flight requires `tools/` and
`corpus-build/`, which are deliberately not published because `corpus-build`
holds the Ed25519 code that signs the corpus. The archives were built and
verified by hand from the maintainer checkout. Treat `checksums.txt` as an
integrity check, not as provenance.

### The GitHub Action

`actions/check` in this repository downloads the binary from a release, verifies
its SHA-256 against `checksums.txt` before extracting it, then runs it. The
repository is public, so the Action is consumable. See
[`actions/check/README.md`](../actions/check/README.md).

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: K1ngBronxo/Clearance-dev/actions/check@v1
    with:
      path: '.'
```

### Confirm what you have

```bash
clearance version
```

This prints the tool version, the corpus version and signature status, and the
build provenance (commit and how the binary was built).

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

`clearance corpus update` will fetch a signed bundle over the network. It is the
**only** operation in the product that would make an outbound call, and it is
deliberately **not implemented in this build**: running it is refused with a
clear message rather than silently accepted. Everything else, including a full
scan, works offline.
