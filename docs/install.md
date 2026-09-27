# Install Clearance

This page takes you from nothing to a working `clearance` command, one step at a
time. Every command is copy-and-paste. You do not need to know Go, Docker, or
anything about how the tool is built.

If you only read one thing: **download the archive, check it, unpack it, and keep
the folder together.** The last part matters more than it sounds — see
[Keep the files together](#keep-the-files-together).

---

## What you are downloading

Clearance is a **single program file**. It has no installer, no runtime, no
dependencies, and nothing to configure before it runs. There is no Docker image
and no package to add to a system package manager.

The archive you download contains four things:

| File | What it is |
|---|---|
| `clearance` (or `clearance.exe` on Windows) | The program |
| `corpus/` | The licence knowledge it reads — a folder of signed data |
| `LICENSE` | The licence Clearance itself is released under |
| `README.md` | The project readme |

The program and the `corpus/` folder belong together. See
[Keep the files together](#keep-the-files-together).

---

## Step 1 — Find out which file you need

There are six archives. You need the one matching your operating system and your
processor type.

| Your system | File you want |
|---|---|
| Windows, most PCs | `..._windows_amd64.zip` |
| Windows on ARM (Surface Pro X, Snapdragon laptops) | `..._windows_arm64.zip` |
| macOS, Apple Silicon (M1 and later) | `..._darwin_arm64.tar.gz` |
| macOS, Intel | `..._darwin_amd64.tar.gz` |
| Linux, most PCs and servers | `..._linux_amd64.tar.gz` |
| Linux on ARM (Raspberry Pi 4/5, Graviton, Ampere) | `..._linux_arm64.tar.gz` |

Not sure? Open a terminal and run the command for your system.

**Windows** (PowerShell):

```powershell
$env:PROCESSOR_ARCHITECTURE
```

`AMD64` means you want `amd64`. `ARM64` means you want `arm64`.

**macOS or Linux** (Terminal):

```bash
uname -m
```

`x86_64` means you want `amd64`. `arm64` or `aarch64` means you want `arm64`.

---

## Step 2 — Download it

There are two places the same files live. Either works; the checksums are
identical on both.

- The project site: `https://clearancedev.vercel.app/dl`
- The GitHub release: `https://github.com/K1ngBronxo/Clearance-dev/releases/tag/v0.1.0-rc.2`

### The easy way — your browser

Open `https://clearancedev.vercel.app/dl` (or the GitHub release page), click the
file from Step 1, and let it save to your Downloads folder. Then skip to Step 3.

### The terminal way

Replace `linux_amd64` with your file from Step 1. Run these one line at a time.

**macOS or Linux:**

```bash
cd ~/Downloads
curl -fsSLO https://clearancedev.vercel.app/dl/clearance_0.1.0-rc.2_linux_amd64.tar.gz
curl -fsSL -o checksums.txt https://clearancedev.vercel.app/dl/checksums.txt
```

**Windows** (PowerShell) — use `curl.exe`, not `curl`. PowerShell replaces `curl`
with its own command that rejects these options:

```powershell
cd ~\Downloads
curl.exe -fsSLO https://clearancedev.vercel.app/dl/clearance_0.1.0-rc.2_windows_amd64.zip
curl.exe -fsSL -o checksums.txt https://clearancedev.vercel.app/dl/checksums.txt
```

---

## Step 3 — Check the download arrived intact

This confirms the file was not corrupted in transit. It takes a second and it is
worth doing: a half-downloaded binary fails in confusing ways later.

**macOS or Linux** (run from the same folder as your download):

```bash
grep -F clearance_0.1.0-rc.2_linux_amd64.tar.gz checksums.txt | shasum -a 256 -c -
```

On Linux, use `sha256sum -c -` instead of `shasum -a 256 -c -`.

You want to see:

```text
clearance_0.1.0-rc.2_linux_amd64.tar.gz: OK
```

**Windows** (PowerShell):

```powershell
$name = 'clearance_0.1.0-rc.2_windows_amd64.zip'
$want = (Select-String -Path checksums.txt -Pattern ([regex]::Escape($name))).Line.Split(' ')[0]
$got  = (Get-FileHash $name -Algorithm SHA256).Hash.ToLower()
if ($got -eq $want) { "OK" } else { "MISMATCH - do not run this file" }
```

You want to see `OK`.

If you see `MISMATCH`, or anything other than `OK`, **stop**. Delete the file and
download it again. Do not run it.

> **What this check does and does not prove.** It proves your download is
> byte-for-byte what the project published. It does not prove who published it —
> the checksum list is served from the same place as the archive. The release
> archives carry no code signature and no build provenance yet; that is stated
> plainly in [SECURITY.md](../SECURITY.md) rather than left for you to discover.

---

## Step 4 — Unpack it

**macOS or Linux:**

```bash
tar -xzf clearance_0.1.0-rc.2_linux_amd64.tar.gz
```

**Windows** (PowerShell):

```powershell
Expand-Archive -Path clearance_0.1.0-rc.2_windows_amd64.zip -DestinationPath . -Force
```

You should now have a `clearance` program and a `corpus` folder side by side.
Check with `ls` (macOS/Linux) or `dir` (Windows).

---

## Step 5 — Put it somewhere permanent

Right now Clearance only runs if you are standing in the folder you unpacked it
in. This step fixes that so you can run `clearance` from anywhere.

The rule is simple: put the **whole folder** somewhere, then add **that folder**
to your PATH. Do not move the program out on its own.

### Windows

PowerShell:

```powershell
$dest = "$env:USERPROFILE\Programs\clearance"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Move-Item .\clearance.exe, .\corpus, .\LICENSE, .\README.md $dest

$old = [Environment]::GetEnvironmentVariable('Path', 'User')
$new = if ([string]::IsNullOrEmpty($old)) { $dest } else { $old.TrimEnd(';') + ';' + $dest }
[Environment]::SetEnvironmentVariable('Path', $new, 'User')
```

**Close the terminal and open a new one.** A PATH change does not reach windows
that are already open. Then go to Step 6.

### macOS and Linux

```bash
mkdir -p ~/.local/clearance
mv clearance corpus LICENSE README.md ~/.local/clearance/
```

Now add it to your PATH. Run this once:

```bash
echo 'export PATH="$HOME/.local/clearance:$PATH"' >> ~/.zshrc
```

On Linux, and on macOS with bash, use `~/.bashrc` instead of `~/.zshrc`.

Then either open a new terminal, or run `source ~/.zshrc` to load it in the one
you have.

---

## Step 6 — Check it works

Open a **new** terminal and run:

```bash
clearance version
```

You should see something like this:

```text
clearance 0.1.0-rc.2 (build ebef4252027d1bb40f82b3eca37fd49433563ea5, release)
go:       go1.25.13
network:  disabled - no outbound calls are possible in this build
corpus:   2026.09.2 at /home/you/.local/clearance/corpus
          signed: yes
          12 licences, 39 obligations, 12 traps, 82 citations
```

Read the `corpus:` lines. `signed: yes` means the licence data passed its
integrity check. `signed: no` means something is wrong — see
[Troubleshooting](#troubleshooting).

One more, which tells you about your own setup:

```bash
clearance doctor
```

If both commands work, you are installed.

---

## Step 7 — Run your first scan

Clearance needs to know how you intend to use the project before it can judge
the licences in it. You declare that once, in a file called
`clearance.config.yml`, in the root of the project you want to check.

Create that file and put this in it:

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

Change the six values to describe your own situation. All six are required —
they are the facts the verdict depends on. What each one means is in
[config.md](config.md).

Then, from that folder:

```bash
clearance check .
```

You get one of four verdicts — `SHIP`, `SHIP CONDITIONAL`, `DO NOT SHIP`, or
`UNDETERMINED` — with the licence clause behind every finding. What the four mean
is in [verdicts.md](verdicts.md).

The exit code carries the same answer, which is what makes it usable in a
pipeline: `0` means `SHIP`, `1` means `DO NOT SHIP`, `5` means `UNDETERMINED`
under `--strict`.

---

## Keep the files together

This is the one mistake worth avoiding.

Clearance looks for its `corpus/` folder **next to the program**. If you copy
`clearance.exe` somewhere on its own and leave `corpus/` behind, the program
still starts, but it has no licence data, and it tells you so:

```text
corpus:   not loaded ()
          E-CORPUS-001 Corpus not found at ''. Reinstall Clearance, or run 'clearance corpus update'.
```

Any scan you run will be `UNDETERMINED`, because with no licence data there is
nothing to judge with. The fix is to move the folder back, or to point Clearance
at a corpus somewhere else:

```bash
export CLEARANCE_CORPUS=/path/to/corpus
```

On Windows PowerShell, set it for the current session with
`$env:CLEARANCE_CORPUS = 'C:\path\to\corpus'`.

---

## Troubleshooting

### `clearance: command not found` (macOS, Linux) or `not recognized` (Windows)

The PATH change has not taken effect. Two causes:

1. **You are in a terminal that was already open** when you changed PATH. Close
   it and open a new one.
2. **The folder you added is wrong.** Check that the folder you added to PATH is
   the one that actually contains the `clearance` file.

To confirm the file is where you think it is, run it by full path:

```bash
~/.local/clearance/clearance version
```

If that works, the program is fine and only PATH is wrong.

### `E-CORPUS-001` — corpus not found

Covered just above: the program and the `corpus/` folder have been separated.
Put them back together.

### Permission denied (macOS, Linux)

The unpacked file lost its executable bit:

```bash
chmod +x ~/.local/clearance/clearance
```

### macOS says the program "cannot be opened because the developer cannot be verified"

The release binary is not signed with an Apple Developer certificate, so macOS
blocks it on first run. Right-click the file in Finder, choose **Open**, and
confirm. You only need to do this once.

### Windows SmartScreen shows a warning

Same cause — the binary carries no code-signing certificate. Click **More info**,
then **Run anyway**.

### `clearance check` says the config is missing

`clearance check` must be run from the folder that contains your
`clearance.config.yml`. Either `cd` into your project, or pass the path:
`clearance check /path/to/project`.

### I want to start over

Delete the folder you created in Step 5, remove the PATH line you added, and go
back to Step 2. Nothing is installed anywhere else — no registry entries, no
system files, no leftovers.

---

## Option B — build from source

Skip this unless you specifically want to build it yourself. It needs **Go
1.25.13 or later** and nothing else.

```bash
git clone https://github.com/K1ngBronxo/Clearance-dev
cd Clearance-dev
make build
./clearance version
```

On Windows the supported shell is **Git Bash**. There is no Docker and no WSL
anywhere in the workflow, deliberately — the tool must build and run on a plain
machine.

`make test` runs the guard tests first and then the full suite with the race
detector. Run `make help` for the full target list.

---

## Use it in GitHub Actions

`actions/check` downloads the binary from a release, verifies its SHA-256 against
the published checksums before extracting it, and then runs it. The repository is
public, so the action is consumable as-is.

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

The action's exit code is the verdict's exit code, so a `DO NOT SHIP` fails the
job. See [`actions/check/README.md`](../actions/check/README.md) and
[ci.md](ci.md).

---

## Where the corpus comes from

The program contains the corpus **public key** and the verification code. It does
not contain the corpus itself. The licence data is a separate, signed artefact
made of three files:

| File | What it is |
|---|---|
| `corpus.json` | The licence, obligation, trap and platform-terms entries |
| `corpus.version.json` | Which version it is, and when it was built |
| `corpus.json.sig` | The Ed25519 signature over the data |

The signature is checked on **every** load, so a local corpus cannot be tampered
with silently. That is what the `signed: yes` line in `clearance version` is
reporting.

If you use the release archive, the bundle is next to the program and is found
automatically. To use a corpus from somewhere else, set `CLEARANCE_CORPUS` to its
folder.

`clearance corpus update` would fetch a fresh signed bundle over the network. It
is the **only** operation in the product that would make an outbound call, and it
is deliberately **not implemented in this build**: running it is refused with a
clear message rather than silently accepted. Everything else, including a full
scan, works entirely offline.

---

## What has been verified

This guide marks what was actually run rather than what ought to work, because
the difference matters on a page people follow literally.

**Verified end to end on Windows 11** with Git Bash and PowerShell: the download,
the SHA-256 check against the published `checksums.txt`, unpacking, the PATH
setup, `clearance version`, `clearance doctor`, and a scan producing a verdict
with exit code `1`. The archive served by the site and the archive attached to
the GitHub release were confirmed **byte-identical**
(`sha256 6aae62182bf074e0dba00165dd17160742f0977d5ad712b456ddb22abf5a3796` for
`clearance_0.1.0-rc.2_windows_amd64.zip`).

The macOS and Linux walkthroughs use the same archive layout and the standard
tools for those systems, but have **not** been run on those platforms by the
maintainer. CI does build and test the source on `ubuntu-latest`,
`windows-latest` and `macos-latest`, which covers the code, not this page. If a
step does not work for you, please open an issue — that is a real bug in this
document.
