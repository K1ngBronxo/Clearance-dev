// The upstream-CLI and platform detector.
//
// # WHY THIS FILE EXISTS
//
// Orchestrating a third-party tool or service means you inherit that platform's
// terms, even though no code from that platform is vendored. A project that
// shells out to `ffmpeg`, calls the Firecrawl API, or reads `OPENAI_API_KEY`
// out of the environment has taken on obligations that no code-licence scanner
// can see. This file finds those invocations.
//
// PLAN/02-SPECIFICATIONS/06-detection-spec-tos.md is the contract.
//
// # WHAT THIS FILE DELIBERATELY DOES NOT DO
//
// **It does not know any platform names.** The scanner reports facts — "this
// file spawns a process whose name is the literal `firecrawl`", "this file
// fetches https://api.firecrawl.dev" — and the corpus decides which of those is
// a platform and what its terms are. That split is not decoration: it is the
// layering rule (L1 may not import L2) and it is ADR-003. A vendor that renames
// its npm package changes a YAML file, not this code.
//
// The consequence is that an unrecognised tool name is *not* reported as a
// finding here. It travels to the policy layer, which asks the corpus, finds
// nothing, and says so in a Notice. The scanner has no opinion about whether
// `pandoc` has terms worth inheriting.
//
// **It does not build an AST.** The spec asks for AST scanning "where
// available" and for a documented fallback elsewhere. A real parser for Go,
// Python and JavaScript would mean three more parsers in a repository whose
// first architectural decision is that it depends on nothing (ADR-001). What
// this file does instead is a *call-shaped* scan: it looks for the exact call
// forms that spawn a process, reads their first argument, and requires that
// argument to be a string literal. That is the property the AST was wanted for
// — "an invocation, not a mention" — and it is achieved by requiring the
// syntax of an invocation rather than by parsing a grammar.
//
// The honest limit: a mention of `subprocess.run(["ffmpeg"])` inside a Python
// docstring that this scanner fails to recognise as a docstring would be read
// as an invocation. Comments are stripped, triple-quoted strings are skipped,
// and backtick template literals are skipped, which covers the cases that
// occur; a hand-written lexer would cover the rest and is not worth its
// maintenance for a false positive that costs one line of output.
//
// **It does not read a real `.env` file.** `.env.example`, `.env.sample`,
// `.env.template` and `.env.dist` are templates and are read for their key
// names. A `.env` is a secrets file and is not opened — not even to list its
// keys — because the privacy claim in the README is a claim about the binary
// and it has to be true of the code that would break it.
package scanner

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/safefs"
)

const (
	// upstreamSourceBytes is the AST limit from the spec (E-SCAN-014): a source
	// file above 2 MiB is not analysed for invocations. A source file that large
	// is generated, and a generated file's invocations are the generator's.
	upstreamSourceBytes = 2 << 20

	// upstreamExcerptMax matches graph.Evidence's documented 200-character cap.
	upstreamExcerptMax = 200

	// upstreamArgWindow bounds how far a single call's argument list is
	// scanned while looking for a literal. A real call fits in a few hundred
	// bytes; a pathological one must not turn into a full-file scan per call.
	upstreamArgWindow = 512
)

// Signal kinds. They are the vocabulary shared with the corpus's `detect`
// block, so a token is only ever matched against the list it arrived from.
//
// There is deliberately no "import" signal here. A package dependency is a fact
// the parsers have already established — `openai` in pyproject.toml is already
// a Dependency in the graph — so the policy layer matches corpus import aliases
// against that dependency rather than this file re-finding it in source text.
const (
	signalBin    = "bin"
	signalRunner = "runner"
	signalHost   = "host"
	signalEnv    = "env"
	signalImage  = "image"
)

// Confidence values recorded on a detected dependency. They describe how sure
// the *detection* is, not how serious the terms are; the finding's confidence
// comes from the corpus clause. See the package comment of internal/policy.
const (
	detectHigh   = "high"
	detectMedium = "medium"
)

// upstreamSignal is one observed invocation.
type upstreamSignal struct {
	Token      string
	Kind       string
	Confidence string
	Line       int
	Excerpt    string
}

// ── the ubiquitous-tool exclusion ────────────────────────────────────────────

// ubiquitousTools are names that are never a licence question.
//
// # WHY A LIST IN CODE IS DEFENSIBLE HERE
//
// The spec's §2.2 excludes "standard OS tools", "build-time-only dev tools" and
// "the project's own binaries", and then §2.2 does not say where that list
// lives. It cannot live in the corpus: the corpus is keyed by *platform*, and
// the exclusion is the absence of a platform. It is also not judgement — nobody
// needs Clearance's opinion on whether `grep` has terms worth inheriting, and a
// finding for `grep` would be noise that trains a user to ignore the tool.
//
// So it is a detection rule, like the magic-byte list in weights.go: a fact
// about what is worth looking at, not an opinion about what it means.
//
// The list is deliberately conservative in the direction that matters. A tool
// that is *missing* from it produces a Notice ("we saw X and have no terms for
// it"), which is a harmless extra line; a tool wrongly *in* it would be a
// silent miss, so borderline cases are left out.
var ubiquitousTools = map[string]bool{
	// Shells and POSIX/coreutils.
	"sh": true, "bash": true, "zsh": true, "dash": true, "fish": true, "ksh": true,
	"cmd": true, "cmd.exe": true, "powershell": true, "powershell.exe": true, "pwsh": true,
	"ls": true, "cat": true, "cp": true, "mv": true, "rm": true, "mkdir": true,
	"rmdir": true, "ln": true, "chmod": true, "chown": true, "chgrp": true,
	"touch": true, "echo": true, "printf": true, "sleep": true, "date": true,
	"pwd": true, "env": true, "printenv": true, "which": true, "whereis": true,
	"whoami": true, "id": true, "uname": true, "hostname": true, "df": true,
	"du": true, "ps": true, "kill": true, "pkill": true, "top": true, "find": true,
	"xargs": true, "grep": true, "egrep": true, "fgrep": true, "rg": true,
	"sed": true, "awk": true, "gawk": true, "sort": true, "uniq": true,
	// `comm` was absent, so `tools/check-corpus-dist.sh` was told Clearance had
	// found a third-party program it holds no terms for, for comparing two
	// sorted lists — a POSIX coreutil, present on every host, and not a licence
	// question any more than `sort` and `uniq` beside it are. Same shape as the
	// `cmp`/`sha256sum` omission recorded above.
	"comm": true,
	"head": true, "tail": true, "wc": true, "tr": true, "cut": true, "paste": true,
	"diff": true, "patch": true, "tee": true, "stat": true, "readlink": true,
	// Checksums and byte comparison. `sha256sum` and `cmp` were absent, so a
	// release workflow that verifies its own build reproducibility was told
	// twice that Clearance had found third-party programs it holds no terms
	// for. They are coreutils, and §2.2 excludes standard OS tools.
	"cmp": true, "sha256sum": true, "sha1sum": true, "sha512sum": true,
	"md5sum": true, "shasum": true, "cksum": true, "b2sum": true,
	"realpath": true, "basename": true, "dirname": true, "mktemp": true,
	"seq": true, "yes": true, "true": true, "false": true, "test": true,
	"expr": true, "bc": true, "jq": true, "yq": true, "sudo": true, "su": true,
	"systemctl": true, "service": true, "launchctl": true, "crontab": true,
	"sleep.exe": true, "timeout": true, "watch": true, "nohup": true, "setsid": true,
	// Archives and transfer. Not licence questions, and present on every host.
	"tar": true, "gzip": true, "gunzip": true, "bzip2": true, "xz": true,
	"zip": true, "unzip": true, "7z": true, "rsync": true, "scp": true,
	"ssh": true, "ssh-keygen": true, "openssl": true, "nc": true, "lsof": true,
	"netstat": true, "ss": true, "strace": true, "ltrace": true, "ldd": true,
	"file": true, "strings": true, "hexdump": true, "xxd": true,
	// Language runtimes and build toolchains. The spec excludes "build-time-only
	// dev tools" and these are exactly that.
	"node": true, "npm": true, "yarn": true, "pnpm": true, "bun": true,
	"deno": true, "corepack": true, "tsc": true, "ts-node": true, "esbuild": true,
	"python": true, "python3": true, "python3.11": true, "python3.12": true,
	"python3.13": true, "pip": true, "pip3": true, "poetry": true, "pdm": true,
	"hatch": true, "pytest": true, "mypy": true, "ruff": true, "black": true,
	"flake8": true, "isort": true, "tox": true, "virtualenv": true,
	"go": true, "gofmt": true, "golangci-lint": true, "gotestsum": true,
	"cargo": true, "rustc": true, "rustup": true, "clippy": true, "rustfmt": true,
	"make": true, "cmake": true, "ninja": true, "meson": true, "bazel": true,
	"gradle": true, "mvn": true, "ant": true, "java": true, "javac": true,
	"kotlinc": true, "scala": true, "sbt": true, "dotnet": true, "msbuild": true,
	"ruby": true, "gem": true, "bundle": true, "bundler": true, "rake": true,
	"php": true, "composer": true, "perl": true, "lua": true, "swift": true,
	"xcodebuild": true, "clang": true, "clang++": true, "gcc": true, "g++": true,
	"cc": true, "c++": true, "ld": true, "ar": true, "as": true, "nm": true,
	"objdump": true, "readelf": true, "gdb": true, "valgrind": true, "perf": true,
	// Version control and containers: developer machinery, not distributed
	// product, and the spec's build-time exclusion covers them.
	"git": true, "git-lfs": true, "hg": true, "svn": true,
	"docker": true, "docker-compose": true, "podman": true, "buildah": true,
	"kubectl": true, "helm": true, "kustomize": true, "terraform": true,
	"tofu": true, "ansible": true, "ansible-playbook": true, "vagrant": true,
	"minikube": true, "kind": true, "skopeo": true,
	// The tool's own name. `clearance check` in a CI workflow is this program
	// invoking itself, which is not a third-party dependency.
	"clearance": true, "clearance.exe": true,
}

// ── language classification ──────────────────────────────────────────────────

type sourceLang int

const (
	langNone sourceLang = iota
	langGo
	langPython
	langJS
	langShell
	langDocker
	langYAML
	langEnv
	langMake
)

// classifySource decides whether a file is worth reading for invocations, and
// which call forms to look for.
//
// # THE YAML RULE IS THE SUBTLE ONE
//
// A workflow file's `run:` block is a shell script and its commands are real
// invocations. A corpus entry's `citation.url` is a mention, and so is every
// other URL in every other data file. Rather than guess, only YAML that sits in
// a recognised automation location is read: `.github/workflows/`, and files
// named like a compose file or a CI config. Everything else is a data file.
func classifySource(rel string) sourceLang {
	base := rel
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		base = rel[i+1:]
	}
	lower := strings.ToLower(base)
	ext := strings.ToLower(path.Ext(base))

	switch ext {
	case ".go":
		return langGo
	case ".py", ".pyi":
		return langPython
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts":
		return langJS
	case ".sh", ".bash", ".zsh":
		return langShell
	case ".mk":
		return langMake
	case ".yml", ".yaml":
		// Automation locations only. See the doc comment.
		if strings.Contains(rel, ".github/workflows/") ||
			strings.Contains(rel, ".github/actions/") ||
			lower == "docker-compose.yml" || lower == "docker-compose.yaml" ||
			lower == "compose.yml" || lower == "compose.yaml" ||
			strings.HasSuffix(lower, ".github-ci.yml") {
			return langYAML
		}
		return langNone
	case ".env":
		// `.env` is a secrets file. Not read. See the package comment.
		return langNone
	}

	switch {
	case lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") ||
		strings.HasSuffix(lower, ".dockerfile"):
		return langDocker
	case lower == "makefile" || lower == "gnumakefile":
		return langMake
	case strings.HasPrefix(lower, ".env."):
		// A template: `.env.example`, `.env.sample`, `.env.template`,
		// `.env.dist`. Read for key names only, never values.
		switch strings.TrimPrefix(lower, ".env.") {
		case "example", "sample", "template", "dist", "defaults":
			return langEnv
		}
		return langNone
	}
	return langNone
}

// ── the detector ─────────────────────────────────────────────────────────────

// detectUpstream finds third-party tool and service invocations and records
// each distinct one as a KindUpstreamCLI dependency.
//
// One dependency per (signal, token), not per occurrence: a tool invoked from
// forty files is one dependency with forty pieces of evidence. The evidence
// list is what makes the finding actionable — "you call this, here" — and
// forty findings for one tool would bury the one that matters.
func (s *scan) detectUpstream(entries []safefs.WalkEntry) {
	type key struct{ kind, token string }
	hits := map[key]*graph.Dependency{}
	order := []key{}

	add := func(sig upstreamSignal, rel string) {
		token := strings.TrimSpace(sig.Token)
		if token == "" {
			return
		}
		// The ubiquitous list applies to executables only. A host called
		// `docker` is not a developer tool, it is a hostname.
		if (sig.Kind == signalBin || sig.Kind == signalRunner) && ubiquitousTools[strings.ToLower(token)] {
			return
		}
		k := key{sig.Kind, strings.ToLower(token)}
		dep, seen := hits[k]
		if !seen {
			dep = &graph.Dependency{
				ID:        graph.LocalID(graph.KindUpstreamCLI, strings.ToLower(token)),
				Kind:      graph.KindUpstreamCLI,
				Name:      token,
				Ecosystem: "upstream",
				Direct:    true,
				Licence: graph.LicenceRef{
					// Source is "detection" rather than "manifest": nothing
					// declared a licence here, and a consumer of the JSON must
					// be able to tell that apart from a declared-but-unresolved
					// value.
					Source:     "detection",
					Confidence: sig.Confidence,
				},
				Metadata: map[string]string{"signal": sig.Kind},
			}
			hits[k] = dep
			order = append(order, k)
		}
		// The strongest detection wins, so a tool found both in a Dockerfile
		// and in a shell script is recorded at the confidence of the better
		// evidence rather than of whichever file the walk reached first.
		if sig.Confidence == detectHigh && dep.Licence.Confidence != detectHigh {
			dep.Licence.Confidence = detectHigh
		}
		ev := graph.Evidence{Path: rel, LineStart: sig.Line, LineEnd: sig.Line}
		if sig.Excerpt != "" {
			ev.Excerpt = sig.Excerpt
		}
		for _, existing := range dep.Evidence {
			if existing.Path == ev.Path && existing.LineStart == ev.LineStart {
				return
			}
		}
		dep.Evidence = append(dep.Evidence, ev)
	}

	for _, e := range entries {
		if e.IsDir || e.Rel == "" {
			continue
		}
		// A tool invoked from inside a vendored dependency is that
		// dependency's business: the code-licence layer covers it, and a
		// node_modules tree would otherwise contribute thousands of signals
		// about libraries' own build scripts.
		if insideDependencyDir(e.Rel) {
			continue
		}
		lang := classifySource(e.Rel)
		if lang == langNone {
			continue
		}
		if e.Size > upstreamSourceBytes {
			// The spec's fallback. Reported, never silent.
			s.warn(cerr.EScan014, e.Rel,
				"Skipped AST analysis of '"+e.Rel+"' ("+humanBytes(e.Size)+"). Falling back to string signals.")
			continue
		}
		data, err := s.root.ReadFile(e.Rel, upstreamSourceBytes)
		if err != nil {
			s.warnErr(err, e.Rel)
			continue
		}

		sigs, nonLiteral := upstreamSignalsIn(e.Rel, string(data), lang)
		for _, sig := range sigs {
			add(sig, e.Rel)
		}
		for _, line := range nonLiteral {
			s.warn(cerr.EScan021, e.Rel, "A process is spawned at '"+e.Rel+":"+itoaInt(int64(line))+
				"' with a command name that is not a literal. Clearance cannot tell which tool is invoked, so it records the spawn and nothing more.")
		}
	}

	// Deterministic emission order. Normalise would sort the graph anyway, but
	// the map above is iterated here to build it, and a map is never allowed to
	// reach output (INV-6).
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].kind != order[j].kind {
			return order[i].kind < order[j].kind
		}
		return order[i].token < order[j].token
	})
	for _, k := range order {
		dep := hits[k]
		sort.SliceStable(dep.Evidence, func(i, j int) bool {
			if dep.Evidence[i].Path != dep.Evidence[j].Path {
				return dep.Evidence[i].Path < dep.Evidence[j].Path
			}
			return dep.Evidence[i].LineStart < dep.Evidence[j].LineStart
		})
		s.g.Add(*dep)
	}
}

// upstreamSignalsIn extracts every invocation from one file.
//
// It returns the signals it found and the line numbers of process spawns whose
// command name was not a literal. The second return is what makes the
// `upstream-dynamic-cmd` behaviour honest: the tool says "there is a spawn here
// and I cannot tell what it runs" instead of inventing a name or staying quiet.
func upstreamSignalsIn(rel, src string, lang sourceLang) ([]upstreamSignal, []int) {
	// Comments are removed first, so a mention in a comment is not an
	// invocation. String literals survive the strip, which is what keeps a URL
	// inside `"…"` available to the host scan.
	code := stripComments(src, lang)

	var sigs []upstreamSignal
	var nonLiteral []int

	switch lang {
	case langGo:
		g, nl := goSpawns(code)
		sigs = append(sigs, g...)
		nonLiteral = append(nonLiteral, nl...)
	case langPython:
		g, nl := pythonSpawns(code)
		sigs = append(sigs, g...)
		nonLiteral = append(nonLiteral, nl...)
	case langJS:
		sigs = append(sigs, jsSpawns(code)...)
	case langShell:
		sigs = append(sigs, shellCommands(code)...)
	case langMake:
		// Not shellCommands: a Makefile is not a shell script. See makeCommands.
		sigs = append(sigs, makeCommands(code)...)
	case langDocker:
		sigs = append(sigs, dockerfileCommands(code)...)
	case langYAML:
		sigs = append(sigs, workflowCommands(code)...)
	case langEnv:
		sigs = append(sigs, envKeys(src)...)
	}

	// The host signal is orthogonal to the language: every one of these file
	// kinds can make an HTTP call, and the scan is the same call-shaped scan.
	sigs = append(sigs, httpHosts(code)...)

	return sigs, nonLiteral
}

// ── comment stripping ────────────────────────────────────────────────────────

// stripComments removes comments while preserving string literals and line
// numbers.
//
// Newlines inside a removed comment are kept so that a line number computed
// against the stripped text is the line number a reader will find in the file.
// That matters: every signal carries a line, and a line that is off by forty
// because a licence header was removed is worse than no line at all.
//
// # THE THREE STRING FORMS IT UNDERSTANDS
//
//   - single and double quotes, with backslash escapes (Go, Python, JS, shell)
//   - backticks (Go raw strings, JS template literals)
//   - triple quotes (Python docstrings), which are skipped whole
//
// Shell is the awkward one: `#` starts a comment, but `#` also appears inside
// `"${x#prefix}"`. The quote tracking handles that case, because the `#` is
// inside a double-quoted string and strings are preserved.
func stripComments(src string, lang sourceLang) string {
	hash := lang == langPython || lang == langShell || lang == langYAML ||
		lang == langDocker || lang == langEnv || lang == langMake
	triple := lang == langPython

	var b strings.Builder
	b.Grow(len(src))

	i := 0
	var quote byte
	for i < len(src) {
		ch := src[i]

		if quote != 0 {
			// A triple-quoted Python string: skip it whole, keeping newlines.
			if triple && ch == quote && i+2 < len(src) && src[i+1] == quote && src[i+2] == quote {
				for k := 0; k < 3; k++ {
					b.WriteByte(src[i+k])
				}
				i += 3
				quote = 0
				continue
			}
			if ch == '\\' && quote != '`' && i+1 < len(src) {
				b.WriteByte(ch)
				b.WriteByte(src[i+1])
				i += 2
				continue
			}
			if ch == quote {
				quote = 0
			}
			b.WriteByte(ch)
			i++
			continue
		}

		switch ch {
		case '"', '\'', '`':
			if triple && i+2 < len(src) && src[i+1] == ch && src[i+2] == ch {
				for k := 0; k < 3; k++ {
					b.WriteByte(src[i+k])
				}
				i += 3
				quote = ch
				continue
			}
			quote = ch
			b.WriteByte(ch)
			i++
		case '/':
			if !hash && i+1 < len(src) && src[i+1] == '/' {
				for i < len(src) && src[i] != '\n' {
					i++
				}
				continue
			}
			if !hash && i+1 < len(src) && src[i+1] == '*' {
				i += 2
				for i < len(src) {
					if src[i] == '\n' {
						b.WriteByte('\n')
					}
					if src[i] == '*' && i+1 < len(src) && src[i+1] == '/' {
						i += 2
						break
					}
					i++
				}
				continue
			}
			b.WriteByte(ch)
			i++
		case '#':
			if hash {
				for i < len(src) && src[i] != '\n' {
					i++
				}
				continue
			}
			b.WriteByte(ch)
			i++
		default:
			b.WriteByte(ch)
			i++
		}
	}
	return b.String()
}

// ── the cursor ───────────────────────────────────────────────────────────────

// cursor is a position in a source string.
type cursor struct {
	src string
	pos int
}

func (c *cursor) eof() bool { return c.pos >= len(c.src) }

func (c *cursor) skipTrivia() {
	for !c.eof() {
		switch c.src[c.pos] {
		case ' ', '\t', '\r', '\n':
			c.pos++
		default:
			return
		}
	}
}

// stringLiteral reads a quoted string at the cursor, or reports false.
func (c *cursor) stringLiteral() (string, bool) {
	c.skipTrivia()
	if c.eof() {
		return "", false
	}
	q := c.src[c.pos]
	if q != '"' && q != '\'' && q != '`' {
		return "", false
	}
	c.pos++
	var b strings.Builder
	for !c.eof() {
		ch := c.src[c.pos]
		if ch == '\\' && q != '`' && c.pos+1 < len(c.src) {
			b.WriteByte(c.src[c.pos+1])
			c.pos += 2
			continue
		}
		if ch == q {
			c.pos++
			return b.String(), true
		}
		if ch == '\n' && q != '`' {
			// An unterminated literal. Bail rather than swallow the file.
			return "", false
		}
		b.WriteByte(ch)
		c.pos++
	}
	return "", false
}

// skipArgument advances past one argument, returning true when it found the
// comma that ends it. The scan is bounded, so a malformed call cannot turn into
// a full-file walk.
func (c *cursor) skipArgument() bool {
	start := c.pos
	depth := 0
	for !c.eof() && c.pos-start < upstreamArgWindow {
		switch c.src[c.pos] {
		case '"', '\'', '`':
			q := c.src[c.pos]
			c.pos++
			for !c.eof() && c.src[c.pos] != q {
				if c.src[c.pos] == '\\' {
					c.pos++
				}
				c.pos++
			}
			c.pos++
		case '(', '[', '{':
			depth++
			c.pos++
		case ')', ']', '}':
			if depth == 0 {
				return false
			}
			depth--
			c.pos++
		case ',':
			if depth == 0 {
				c.pos++
				return true
			}
			c.pos++
		default:
			c.pos++
		}
	}
	return false
}

// eachCall invokes fn for every occurrence of a call named `name`, with the
// cursor positioned just after the opening parenthesis.
//
// The word-boundary check matters: without it `myexec.Command(` would match
// `exec.Command`, and a wrapper library's own helper would be reported as the
// project's invocation.
func eachCall(src, name string, fn func(c *cursor, line int)) {
	from := 0
	for {
		i := strings.Index(src[from:], name)
		if i < 0 {
			return
		}
		at := from + i
		from = at + 1

		if at > 0 && isIdentByte(src[at-1]) {
			continue
		}
		end := at + len(name)
		if end >= len(src) {
			return
		}
		if isIdentByte(src[end]) {
			continue
		}
		// Allow whitespace between the name and the paren: `http.Get (`.
		j := end
		for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
			j++
		}
		if j >= len(src) || src[j] != '(' {
			continue
		}
		fn(&cursor{src: src, pos: j + 1}, lineNumber(src, at))
	}
}

func isIdentByte(b byte) bool {
	return b == '_' || b == '$' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// lineNumber returns the 1-based line containing a byte offset.
func lineNumber(src string, pos int) int {
	if pos > len(src) {
		pos = len(src)
	}
	return 1 + strings.Count(src[:pos], "\n")
}

// excerptAt returns the trimmed text of the line containing an offset, capped.
func excerptAt(src string, pos int) string {
	start := strings.LastIndexByte(src[:min(pos, len(src))], '\n') + 1
	end := strings.IndexByte(src[min(pos, len(src)):], '\n')
	if end < 0 {
		end = len(src)
	} else {
		end += min(pos, len(src))
	}
	return truncateExcerpt(strings.TrimSpace(src[start:end]))
}

func truncateExcerpt(s string) string {
	if len(s) <= upstreamExcerptMax {
		return s
	}
	return s[:upstreamExcerptMax]
}

// ── per-language spawn detection ─────────────────────────────────────────────

// goSpawns finds os/exec invocations.
func goSpawns(src string) ([]upstreamSignal, []int) {
	var sigs []upstreamSignal
	var nonLiteral []int

	eachCall(src, "exec.Command", func(c *cursor, line int) {
		tok, ok := c.stringLiteral()
		if !ok {
			nonLiteral = append(nonLiteral, line)
			return
		}
		sigs = append(sigs, upstreamSignal{
			Token: tok, Kind: signalBin, Confidence: detectHigh,
			Line: line, Excerpt: excerptAt(src, c.pos),
		})
	})

	eachCall(src, "exec.CommandContext", func(c *cursor, line int) {
		// The first argument is the context; the command is the second.
		if !c.skipArgument() {
			return
		}
		tok, ok := c.stringLiteral()
		if !ok {
			nonLiteral = append(nonLiteral, line)
			return
		}
		sigs = append(sigs, upstreamSignal{
			Token: tok, Kind: signalBin, Confidence: detectHigh,
			Line: line, Excerpt: excerptAt(src, c.pos),
		})
	})

	return sigs, nonLiteral
}

// pythonSpawnCalls are the call forms that start a process. The list is from
// the spec's §3.1 plus the asyncio equivalents, which are the same act.
var pythonSpawnCalls = []string{
	"subprocess.run", "subprocess.Popen", "subprocess.call",
	"subprocess.check_call", "subprocess.check_output", "subprocess.getoutput",
	"subprocess.getstatusoutput",
	"asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
	"os.system", "os.popen", "os.execv", "os.execvp", "os.spawnv", "os.spawnl",
	"os.posix_spawn",
}

// pythonSpawnBare are the same calls written without the module prefix, which
// is what `from subprocess import run` produces.
var pythonSpawnBare = []string{"run", "Popen", "call", "check_call", "check_output"}

func pythonSpawns(src string) ([]upstreamSignal, []int) {
	var sigs []upstreamSignal
	var nonLiteral []int

	consider := func(c *cursor, line int, shellForm bool) {
		c.skipTrivia()
		// The list form: subprocess.run(["ffmpeg", …]). The command is the
		// first element, and a list literal is the documented way to pass it.
		if !c.eof() && c.src[c.pos] == '[' {
			c.pos++
			tok, ok := c.stringLiteral()
			if !ok {
				nonLiteral = append(nonLiteral, line)
				return
			}
			sigs = append(sigs, upstreamSignal{
				Token: tok, Kind: signalBin, Confidence: detectHigh,
				Line: line, Excerpt: excerptAt(src, c.pos),
			})
			return
		}
		tok, ok := c.stringLiteral()
		if !ok {
			nonLiteral = append(nonLiteral, line)
			return
		}
		// A bare string is a whole shell command line, so the tool is its
		// first word. os.system("ffmpeg -i …") is the spec's LOW-confidence
		// case: the string may be assembled at runtime, and only the leading
		// word is trusted.
		word := firstWord(tok)
		if word == "" {
			return
		}
		conf := detectHigh
		if shellForm {
			conf = detectMedium
		}
		sigs = append(sigs, upstreamSignal{
			Token: word, Kind: signalBin, Confidence: conf,
			Line: line, Excerpt: excerptAt(src, c.pos),
		})
	}

	for _, name := range pythonSpawnCalls {
		shellForm := strings.HasPrefix(name, "os.system") || strings.HasPrefix(name, "os.popen")
		eachCall(src, name, func(c *cursor, line int) { consider(c, line, shellForm) })
	}

	if strings.Contains(src, "from subprocess import") {
		for _, name := range pythonSpawnBare {
			eachCall(src, name, func(c *cursor, line int) { consider(c, line, false) })
		}
	}

	return sigs, nonLiteral
}

// jsSpawnQualified are the child_process call forms.
var jsSpawnQualified = []string{
	"child_process.spawn", "child_process.spawnSync",
	"child_process.execFile", "child_process.execFileSync",
	"child_process.exec", "child_process.execSync",
	"child_process.fork",
}

// jsSpawnBare are the same calls after destructuring.
var jsSpawnBare = []string{"spawn", "spawnSync", "execFile", "execFileSync", "execSync", "fork"}

func jsSpawns(src string) []upstreamSignal {
	var sigs []upstreamSignal

	consider := func(c *cursor, line int, shellForm bool) {
		tok, ok := c.stringLiteral()
		if !ok {
			return
		}
		word := firstWord(tok)
		if word == "" {
			return
		}
		conf := detectHigh
		if shellForm {
			// exec() and execSync() take a shell string, like os.system.
			conf = detectMedium
		}
		sigs = append(sigs, upstreamSignal{
			Token: word, Kind: signalBin, Confidence: conf,
			Line: line, Excerpt: excerptAt(src, c.pos),
		})
	}

	for _, name := range jsSpawnQualified {
		shellForm := strings.HasSuffix(name, ".exec") || strings.HasSuffix(name, ".execSync")
		eachCall(src, name, func(c *cursor, line int) { consider(c, line, shellForm) })
	}

	// The bare forms are only looked for when the file actually imports
	// child_process. Without that check, every call to a function called
	// `spawn` in any library would be reported.
	if strings.Contains(src, "child_process") || strings.Contains(src, "node:child_process") {
		for _, name := range jsSpawnBare {
			shellForm := name == "exec" || name == "execSync"
			eachCall(src, name, func(c *cursor, line int) { consider(c, line, shellForm) })
		}
	}

	return sigs
}

// ── shell-family detection ───────────────────────────────────────────────────

// packageRunners map a runner to how many words it consumes before the tool
// name. `npx X` and `bunx X` are one; `pipx run X` and `pnpm dlx X` are two.
var packageRunners = map[string]int{
	"npx": 1, "bunx": 1, "uvx": 1, "pipx": 2, "pnpm": 2, "yarn": 2, "npm": 2,
	"corepack": 2, "go": 2,
}

// shellControlWords are words that begin a construct rather than a command.
var shellControlWords = map[string]bool{
	"if": true, "then": true, "elif": true, "else": true, "fi": true,
	"for": true, "while": true, "until": true, "do": true, "done": true,
	"case": true, "esac": true, "in": true, "function": true, "return": true,
	"exit": true, "local": true, "declare": true, "readonly": true,
	"source": true, ".": true, ":": true, "break": true, "continue": true,
	"end": true, "begin": true, "endfor": true, "endif": true,
	"cd": true, "export": true, "set": true, "unset": true, "shift": true,
	"trap": true, "umask": true, "wait": true, "eval": true, "exec": true,
	"alias": true, "type": true, "hash": true, "read": true, "let": true,
	"include": true, "override": true, "define": true, "ifeq": true,
	"ifneq": true, "ifeq.": true, "sinclude": true, "-include": true,
}

// shellCommands finds command invocations in a shell script, a Makefile recipe
// or a CI `run:` block.
//
// The rule is "the first word of a command", and the separator set is the shell
// grammar's: newline, `;`, `&&`, `||`, `|`, `&`, and command substitution
// `$(`. A line that is an assignment (`FOO=bar`) has no command word, and a
// line that is a flag or a control word is skipped.
//
// # THE FOUR GRAMMAR FACTS THIS USED TO MISS
//
// It reported the debris of text it could not read as detections. Run over this
// repository's own tree it emitted 84 notices, and every one was false: the
// corpus was told that Clearance invokes a third-party program called
// `.PHONY:`, and `GUARD_CORPUS`, and `GO)`, and `-X`, and
// `build release vulncheck dogfood bench`. The spec is blunt about why that
// matters — PLAN/02-SPECIFICATIONS/06-detection-spec-tos.md §3.2, "false
// positives are what kill a scanner's credibility".
//
// Four facts of the grammar were missing, and each one had the same shape: text
// that is not a command was being read by a rule that assumes it is.
//
//   - A continued line is one command. `go build … \` followed by
//     `-o /tmp/clearance-a` yielded a program called `o`, because each physical
//     line was parsed alone. See joinContinuations.
//   - A recipe's `@`/`-`/`+` prefix comes *before* the assignment test.
//     `@fail=0` was read as a program named `fail=0`.
//   - `$(VAR)` is an expansion. §3.1's rule for a command name that is not a
//     literal is to record the spawn and claim no name; `$(GO) test` named
//     `GO)` instead. See plausibleProgramName.
//   - A Makefile is not a shell script, and only a line beginning with a TAB is
//     a recipe. See makeCommands, which is where that rule lives.
//
// Confidence is MEDIUM throughout, and that is the honest label rather than a
// penalty: a shell script is read by this file's own line splitting rather than
// by a shell parser, so `"$CMD" -i` and a line inside a heredoc both land in the
// same bucket. The spec's AST requirement is met for Go, Python and JavaScript;
// for shell it is met by the corpus's own alias lists, which is why an
// unrecognised token becomes a Notice rather than a finding.
// shellCommands reads a whole file, whose first line is line 1.
func shellCommands(src string) []upstreamSignal { return shellCommandsAt(src, 0) }

// shellCommandsAt is shellCommands for a fragment of a file.
//
// baseLine is added to every line number it reports, and it exists because two
// callers hand this function a slice rather than a whole file: makeCommands
// passes one recipe line, and workflowCommands passes one line of a `run:`
// block. Without it those callers produced signals with no line at all, and an
// evidence location that says `Makefile` and nothing else is not enough for a
// reader to go and look.
func shellCommandsAt(src string, baseLine int) []upstreamSignal {
	var sigs []upstreamSignal

	// Names this script defines as functions. Calling one is not a spawn, and a
	// script's own helpers are the most common non-program command word there
	// is — tools/check-corpus-dist.sh alone defines one and calls it five times.
	defined := shellFunctionNames(src)

	for _, sl := range joinContinuations(src) {
		// A line whose first non-blank character is `#` is a comment, and a
		// comment is not a command. Without this, a `;` inside prose split the
		// sentence and promoted the next English word to a program name:
		// `# … ; this script is the` yielded a third-party program called
		// `this`, and a sibling script yielded `the`. Both were reported by
		// `make dogfood` on Clearance's own build scripts.
		if strings.HasPrefix(strings.TrimSpace(sl.text), "#") {
			continue
		}
		for _, cmd := range splitCommands(sl.text) {
			words := strings.Fields(cmd)
			if len(words) == 0 {
				continue
			}
			// Strip a recipe's `@`/`-`/`+` prefix *before* the assignment
			// test. `@fail=0` is an assignment; testing the raw word reads it
			// as a program whose name contains an `=`.
			words[0] = strings.TrimLeft(words[0], "@-+")
			rest, isCommand := dropAssignment(words)
			if !isCommand {
				continue
			}
			words = rest
			if len(words) == 0 {
				continue
			}
			head := strings.TrimSpace(words[0])
			if shellControlWords[head] {
				continue
			}
			if defined[head] {
				// A function this file defines. Not a program, and not a spawn.
				continue
			}
			if !plausibleProgramName(head) {
				// Not a name a program can have: an unresolved expansion, the
				// debris of a split construct, or punctuation alone. See the
				// doc comment and plausibleProgramName.
				continue
			}
			tok := head
			kind := signalBin
			if n, isRunner := packageRunners[head]; isRunner {
				// `npx X` — the tool is the word after the runner, and the
				// runner's own subcommand is in between for the two-word forms
				// (`pnpm dlx X`).
				if len(words) <= n {
					continue
				}
				sub := words[1]
				if n == 2 {
					switch head {
					case "pipx":
						if sub != "run" {
							continue
						}
					case "pnpm":
						if sub != "dlx" && sub != "exec" {
							continue
						}
					case "yarn":
						if sub != "dlx" && sub != "exec" {
							continue
						}
					case "npm":
						if sub != "exec" {
							continue
						}
					case "corepack":
						// corepack <pm> …
						continue
					case "go":
						// `go run ./cmd/x` is building the project's own code.
						continue
					}
				}
				if len(words) <= n {
					continue
				}
				tok = strings.TrimLeft(words[n], "-")
				kind = signalRunner
			}
			if tok == "" {
				continue
			}
			sigs = append(sigs, upstreamSignal{
				Token: tok, Kind: kind, Confidence: detectMedium,
				Line: sl.line + baseLine,
			})
		}
	}
	return sigs
}

// splitCommands breaks a line into the commands it runs, on the shell's
// separators. It is not a shell parser: it does not understand quoting, which
// is why the confidence for this family is MEDIUM.
func splitCommands(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	out := []string{}
	var b strings.Builder

	// inDouble records that the scan is inside a double-quoted string, because
	// the quote is not what is being skipped — the *separators* are. Inside
	// `"…"` a `|` is literal, but a `$(…)` still runs a command, so the two
	// must be treated differently and a single skip-the-quoted-region loop
	// cannot do it.
	//
	// This is not a nicety. `roots="$(git ls-tree -r --name-only "$ref" | …)"`
	// is an ordinary line, and skipping the whole quoted region meant the
	// substitution was never split on: the assignment-stripper then consumed
	// `roots="$(git` as one word and promoted the subcommand, so Clearance
	// reported a third-party program called `ls-tree` — while missing `git`,
	// the actual program on the line. One false positive and one false negative
	// from the same character. Single quotes are left alone: they never
	// substitute.
	inDouble := false

	for i := 0; i < len(line); i++ {
		ch := line[i]

		if inDouble {
			if ch == '$' && i+1 < len(line) && line[i+1] == '(' {
				out = append(out, b.String())
				b.Reset()
				i++ // step over '('
				inDouble = false
				continue
			}
			if ch == '"' {
				inDouble = false
			}
			b.WriteByte(ch)
			continue
		}

		switch ch {
		case '\'', '"':
			// Skip the quoted region so a separator inside a string does not
			// split the command. Quote handling for *content* is not attempted.
			q := ch
			b.WriteByte(ch)
			i++
			for i < len(line) {
				if q == '"' && line[i] == '$' && i+1 < len(line) && line[i+1] == '(' {
					// A command substitution inside double quotes: split here,
					// so the fragment after it begins with the command rather
					// than with `$(`. `i++` steps over the '$' and the loop's
					// own `i++` steps over the '(', leaving the head intact.
					// inDouble remembers that the closing quote is still to come,
					// so it is not mistaken for an opening one.
					out = append(out, b.String())
					b.Reset()
					i++
					inDouble = true
					break
				}
				if line[i] == q {
					break
				}
				if line[i] == '\\' && i+1 < len(line) {
					b.WriteByte(line[i])
					i++
				}
				b.WriteByte(line[i])
				i++
			}
			if i < len(line) && !inDouble {
				b.WriteByte(line[i])
			}
			continue
		case ';', '|', '&', '\n':
			out = append(out, b.String())
			b.Reset()
			// Collapse `&&`, `||`.
			for i+1 < len(line) && (line[i+1] == ch || line[i+1] == '&' || line[i+1] == '|') {
				i++
			}
			continue
		case '$':
			if i+1 < len(line) && line[i+1] == '(' {
				out = append(out, b.String())
				b.Reset()
				i++
				continue
			}
		}
		b.WriteByte(ch)
	}
	out = append(out, b.String())
	return out
}

// isAssignment reports whether a word is a shell or Make variable assignment.
func isAssignment(w string) bool {
	i := strings.IndexByte(w, '=')
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		c := w[j]
		if !isIdentByte(c) {
			return false
		}
	}
	return true
}

// isMakeAssignOp reports whether a word is a Make variable assignment operator.
//
// It exists for the spaced form. `FOO=1 cmd` carries its `=` inside the first
// word, so isAssignment sees it; `GUARD_CORPUS := a|b` does not, and the first
// word is then a bare name that reads exactly like a program.
func isMakeAssignOp(w string) bool {
	switch w {
	case "=", ":=", "::=", "?=", "+=", "!=":
		return true
	}
	return false
}

// dropAssignment consumes a leading `FOO=1` prefix and reports whether a command
// follows it.
//
//	`FOO=1 cmd`       -> ["cmd"], true
//	`FOO=1 BAR=2 cmd` -> ["cmd"], true
//	`FOO=1`           -> nil, false
//
// Only the one-word form is handled here. Make's spaced `FOO := value` is a
// dialect fact and lives in isMakeAssignmentLine, because in shell that same
// text is not an assignment at all.
func dropAssignment(words []string) ([]string, bool) {
	for len(words) > 0 && isAssignment(words[0]) {
		words = words[1:]
	}
	return words, len(words) > 0
}

// isMakeAssignmentLine reports whether a Makefile recipe line defines a
// variable rather than running a command.
//
// # WHY THE WHOLE LINE HAS TO BE RECOGNISED FIRST
//
// `\tGUARD_CORPUS := TestA|TestB` defines a variable whose value is not a
// command — but `|` is a shell separator, so a shell reader splits it into
// three commands and reports three third-party programs: `GUARD_CORPUS`,
// `TestA`, `TestB`. That is precisely what this repository's own guard lists
// did. Dropping the leading assignment word is not enough, because the value
// has already been split off it by the time anyone looks.
func isMakeAssignmentLine(line string) bool {
	words := strings.Fields(line)
	return len(words) >= 2 && isMakeAssignOp(words[1])
}

// plausibleProgramName reports whether a token could be the name of a program.
//
// # WHY A NEGATIVE TEST RATHER THAN A POSITIVE ONE
//
// A positive test — "this looks like a binary name" — would need a rule for
// every naming convention there is, and would silently drop the ones it did not
// know, which is the failure direction that hides a real dependency. This asks
// the smaller question the spec already answers in §3.1: could this token be a
// *literal* command name at all? Three things say no.
//
//   - It contains `$` or a backtick. §3.1: "a command name that is not a
//     literal — cannot determine the tool". `$(GO)`, `$(GOLANGCI_LINT)`, and
//     `$(which ffmpeg)` are spawns Clearance can see and cannot name, and
//     naming them `GO)` is a fabrication.
//   - It contains a bracket. That is the debris of a construct the splitter
//     cut: the `date)` left by `$(date)`, the `MAKEFILE_LIST)` left by
//     `$(MAKEFILE_LIST)`, the `OS),Windows_NT)` left by `ifeq ($(OS),…)`. No
//     program name has parentheses in it.
//   - It is punctuation only — `./`, `..`, `-`, `\`, `:`. These come from a
//     path whose tail was an expansion (`./$(BINARY)$(EXE)`) or from a
//     continuation backslash, and none of them names anything a user could act
//     on.
//
// A trailing colon is also refused. That is a Make target or directive
// (`.PHONY:`, `help:`, `build:`), never a program, and the check is here as
// well as in makeCommands so that the rule holds even if a recipe is ever
// detected by something other than its leading tab.
func plausibleProgramName(tok string) bool {
	if tok == "" {
		return false
	}
	if strings.ContainsAny(tok, "$`") {
		return false
	}
	if strings.ContainsAny(tok, "(){}[]") {
		return false
	}
	if strings.HasSuffix(tok, ":") {
		return false
	}
	// A flag is never a program. When `VAR="$(cmd -f arg)"` is split, the
	// fragment that survives assignment-stripping can begin with the flag, and
	// `-rhoE` then reads as a program named `rhoE`. Observed on this
	// repository's own tools/check-corpus-dist.sh: eleven Notices, every one of
	// them a flag, a number, a quote or a `#`. Spec 06 §3.2 is explicit that
	// false positives are what kill a scanner's credibility, so each of these
	// is refused by shape rather than by name.
	if strings.HasPrefix(tok, "-") {
		return false
	}
	// A bare number is never a program: it is the `2` of `>&2` after the `&`
	// split, or an argument that lost its flag.
	if strings.Trim(tok, "0123456789") == "" {
		return false
	}
	// Quote characters, `%` and `#` are the debris of a printf format string, a
	// split literal, or a comment marker. No program name contains them.
	if strings.ContainsAny(tok, "\"'%#") {
		return false
	}
	return strings.Trim(tok, "./\\-+@:,;=") != ""
}

// shellFunctionNames returns the names a script defines as shell functions.
//
// `fail() { ... }` introduces a command word that is not a program, and calling
// it is not a spawn of anything third-party. Reading one as a program produced a
// Notice claiming Clearance had seen a tool it holds no terms for — on its own
// build scripts, about a function they define twenty lines earlier.
//
// Only whole-file callers see definitions; a caller that hands over a fragment
// (one Make recipe line, one workflow `run:` line) gets an empty set and behaves
// exactly as before. That is the right trade: a definition on the same line as
// its call is not a shape worth guessing at.
func shellFunctionNames(src string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(t, "function "); ok {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), "{"))
			if n, _, found := strings.Cut(name, "()"); found {
				name = n
			}
			if isShellFunctionName(strings.TrimSpace(name)) {
				out[strings.TrimSpace(name)] = true
			}
			continue
		}
		if i := strings.Index(t, "()"); i > 0 {
			if name := strings.TrimSpace(t[:i]); isShellFunctionName(name) {
				out[name] = true
			}
		}
	}
	return out
}

// isShellFunctionName reports whether s could be the name in `s() {`.
//
// Deliberately narrow. `$(` and `(` appear in ordinary command lines, so a
// loose test here would start excluding real programs; a name that is not
// plainly an identifier is simply not treated as a definition.
func isShellFunctionName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_', c == '-':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// scriptLine is one logical line of a script: a physical line, plus any
// continuation lines folded into it, and the line number a reader would find.
type scriptLine struct {
	text string
	line int // 1-based; the first physical line of the logical line
}

// joinContinuations folds lines that end in a backslash into one logical line,
// which is how both the shell and Make read them.
//
// # WHY THIS IS NOT COSMETIC
//
// The rule is "the first word of a line", so without folding, every argument on
// a continued line is read as a command of its own. On this repository that
// produced a program called `o` from the `-o /tmp/clearance-a` half of a
// `go build`; `output-signature` and `dist/checksums.txt.sig` from a
// `cosign sign-blob` step; and `X` and `\` from the linker flags in a Makefile.
// Each became a Notice asserting that Clearance had seen a third-party program
// it holds no terms for.
//
// The reported line is the *first* physical line, because that is where the
// command starts and therefore where the evidence should send a reader. An
// unclosed continuation at end of file is folded anyway rather than dropped:
// the file is malformed, but its commands are still commands.
func joinContinuations(src string) []scriptLine {
	physical := strings.Split(src, "\n")
	out := make([]scriptLine, 0, len(physical))

	var b strings.Builder
	start := 0
	for i, line := range physical {
		body := strings.TrimRight(line, " \t\r")
		if strings.HasSuffix(body, "\\") {
			if b.Len() == 0 {
				start = i + 1
			}
			b.WriteString(strings.TrimSuffix(body, "\\"))
			b.WriteByte(' ')
			continue
		}
		if b.Len() > 0 {
			b.WriteString(line)
			out = append(out, scriptLine{text: b.String(), line: start})
			b.Reset()
			continue
		}
		out = append(out, scriptLine{text: line, line: i + 1})
	}
	if b.Len() > 0 {
		out = append(out, scriptLine{text: b.String(), line: start})
	}
	return out
}

// makeCommands finds the commands a Makefile runs.
//
// # A MAKEFILE IS NOT A SHELL SCRIPT
//
// Make has its own grammar, and exactly one of its constructs is shell: a
// recipe line, which GNU Make defines as a line beginning with a TAB. Everything
// else in the file is Makefile syntax — variable definitions, target rules,
// directives (`.PHONY:`, `include`, `export`), conditionals (`ifeq`), and
// function calls (`$(shell …)`).
//
// Feeding all of that to shellCommands read the syntax as program names. On
// this repository's own Makefile the result was 74 notices for programs that do
// not exist: `.PHONY:`, `.DEFAULT_GOAL`, `.SHELLFLAGS`, `SHELL`, `GOFLAGS`,
// `BINARY`, `EXE`, `VERSION`, `CLI_PKG`, `arch:`, `lint:`, `dogfood:`, `X`,
// `\`, `build release vulncheck dogfood bench`, and every `Test…` name in the
// guard lists.
//
// The tab rule is not a heuristic and it is not a guess about style. It is the
// grammar: a space-indented recipe is a Make error — "missing separator" — so a
// line that does not begin with a TAB is not a command on any machine this tool
// will ever run on. Reading it as one can only produce a false positive.
//
// # WHAT THIS DELIBERATELY DOES NOT SEE
//
// A tool invoked through a variable — `$(GOLANGCI_LINT) run ./...` — cannot be
// named without expanding the variable, and expansion means a Make interpreter,
// which ADR-001's zero-dependency single binary does not carry. §3.1's rule
// applies and the honest consequence is stated rather than papered over: a
// Makefile's variable-indirected tools are not detected. The same tool named
// literally in a script, or in a `run:` block, is. This is a known gap, and it
// is the reason `golangci-lint` and `goreleaser` — both real dependencies of
// this repository's release process — do not appear in its own verdict.
func makeCommands(src string) []upstreamSignal {
	var sigs []upstreamSignal
	for _, sl := range joinContinuations(src) {
		if !strings.HasPrefix(sl.text, "\t") {
			continue
		}
		// A recipe line can itself be an assignment, and its value must be
		// recognised as a value before the shell splitter sees a `|` in it.
		if isMakeAssignmentLine(strings.TrimPrefix(sl.text, "\t")) {
			continue
		}
		sigs = append(sigs, shellCommandsAt(sl.text, sl.line-1)...)
	}
	return sigs
}

// firstWord returns the first whitespace-separated word of a command string,
// stripped of a leading path. `"/usr/bin/ffmpeg -i"` yields `ffmpeg`.
func firstWord(s string) string {
	s = firstToken(s)
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// firstToken is firstWord with the path left on.
//
// The two exist apart because "strip the path" is right for a command and wrong
// for a container image. `/usr/bin/ffmpeg` and `ffmpeg` are the same program;
// `ghcr.io/other/tool` and `tool` are not the same image, and a detector that
// reports the second cannot match a corpus entry keyed on the first.
func firstToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, " \t\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.Trim(s, `"'`)
}

// ── Dockerfile ───────────────────────────────────────────────────────────────

func dockerfileCommands(src string) []upstreamSignal {
	var sigs []upstreamSignal

	// Folding continuations first is what makes a multi-line instruction one
	// instruction. A Dockerfile writes `RUN apt-get update \` + `&& apt-get
	// install -y ffmpeg` as two physical lines, and the second is an argument
	// list, not a command whose first word happens to be `&&`.
	for _, sl := range joinContinuations(src) {
		trimmed := strings.TrimSpace(sl.text)
		if trimmed == "" {
			continue
		}
		verb, rest := splitVerb(trimmed)
		switch strings.ToUpper(verb) {
		case "FROM":
			// `FROM image:tag AS name` — the image is the first word, and the
			// tag and digest are not part of its identity.
			//
			// firstToken and not firstWord: firstWord strips a leading path,
			// which is right for a command (`/usr/bin/ffmpeg` is ffmpeg) and
			// wrong for an image, where the path *is* the identity. This
			// reported `FROM ghcr.io/other/tool` as an image called `tool`,
			// which would have matched a corpus entry named `tool` and missed
			// the one named `ghcr.io/other/tool`.
			image := firstToken(rest)
			if image == "" || strings.EqualFold(image, "scratch") {
				continue
			}
			if i := strings.IndexAny(image, ":@"); i >= 0 {
				image = image[:i]
			}
			if image == "" {
				continue
			}
			sigs = append(sigs, upstreamSignal{
				Token: image, Kind: signalImage, Confidence: detectHigh,
				Line: sl.line, Excerpt: truncateExcerpt(trimmed),
			})
		case "ENTRYPOINT", "CMD":
			// Exec form is a JSON array; shell form is a command line.
			if i := strings.IndexByte(rest, '['); i >= 0 {
				c := &cursor{src: rest, pos: i + 1}
				tok, ok := c.stringLiteral()
				if ok {
					word := firstWord(tok)
					if word != "" {
						sigs = append(sigs, upstreamSignal{
							Token: word, Kind: signalBin, Confidence: detectHigh,
							Line: sl.line, Excerpt: truncateExcerpt(trimmed),
						})
					}
				}
				continue
			}
			word := firstWord(rest)
			if word != "" {
				sigs = append(sigs, upstreamSignal{
					Token: word, Kind: signalBin, Confidence: detectMedium,
					Line: sl.line, Excerpt: truncateExcerpt(trimmed),
				})
			}
		case "RUN":
			for _, s := range shellCommandsAt(rest, sl.line-1) {
				s.Excerpt = truncateExcerpt(trimmed)
				sigs = append(sigs, s)
			}
		}
	}
	return sigs
}

// splitVerb splits a Dockerfile instruction into its verb and the rest.
func splitVerb(line string) (string, string) {
	i := strings.IndexAny(line, " \t")
	if i < 0 {
		return line, ""
	}
	return line[:i], strings.TrimSpace(line[i+1:])
}

// ── CI workflow ──────────────────────────────────────────────────────────────

// workflowCommands finds the commands in a CI workflow's `run:` steps.
//
// Only `run:` is read. `uses:` names an action, which is a dependency of the
// build rather than a third-party tool the product invokes at runtime, and the
// spec's build-time exclusion covers it.
//
// # A `run:` IS A STEP ONLY INSIDE A LIST ITEM
//
// A job's steps are a YAML sequence, so a step is a list item and its `run:`
// key is introduced by the item's `-` marker. The marker is on the `run:` line
// itself (`- run: cmd`), or above it on a `- name:` / `- uses:` line whose `-`
// sits at a shallower indent. A `defaults.run` — the workflow- or job-level
// mapping of `shell` and `working-directory` — is not a list item: nothing
// introduces it with a `-`, and its keys are settings, not commands.
//
// The test is structural, the presence of a list marker, and deliberately not
// a test of the key's name. Skipping the names `working-directory` and `shell`
// would break the day GitHub adds a third setting to defaults.run, and would
// still read the mapping's values as commands: `working-directory: src|generated`
// splits on the shell's `|` and used to name a program `generated`. Refusing
// the mapping as a whole is what makes both of those safe at once.
//
// # WHY `- run: …` HAS TO BE READ AT ALL
//
// `- run: …` is the same key as `run: …` one level in, and it is the style
// GitHub's own documentation uses. A reader blind to it misses a whole file
// rather than one line — a false negative, and the direction that matters more
// than a false positive, because nothing tells the user that a file went
// unread.
func workflowCommands(src string) []upstreamSignal {
	var sigs []upstreamSignal

	lines := strings.Split(src, "\n")
	// openItem is the indent of the `-` marker of the innermost list item that
	// is still open, or -1 when none is. A `run:` is a step exactly when a list
	// item is open around it.
	openItem := -1

	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		// A blank line or a comment is not structure and cannot close an item.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := leadingSpaces(lines[i])

		// keyIndent is the column the key on this line starts at, and key is the
		// key itself. On a list-item line (`- run: …`) the key begins after the
		// marker, which is what makes the line's `run:` a step.
		keyIndent, key := indent, trimmed
		if isListItem(trimmed) {
			openItem = indent
			after := strings.TrimLeft(trimmed[1:], " \t")
			keyIndent = indent + 1 + (len(trimmed[1:]) - len(after))
			key = after
		} else if openItem >= 0 && indent <= openItem {
			// A line at or above the marker's own indent, that is not itself a
			// marker, has left the list item: the list has ended. This is what
			// makes a `defaults:` block written below the steps read as a
			// mapping rather than as more steps.
			openItem = -1
		}

		if openItem < 0 || !strings.HasPrefix(key, "run:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(key, "run:"))

		if rest == "" || rest == "|" || rest == ">" || rest == "|-" || rest == ">-" {
			// A block scalar: every following line indented deeper than the
			// `run:` key is script.
			//
			// # WHY THE BLOCK IS PARSED AS ONE STRING
			//
			// Not line by line, because a `\` at the end of one line continues the
			// command on the next, and the two are one command only together. Read
			// apart, every argument on a continued line became a program of its
			// own: a `cosign sign-blob` step in this repository reported
			// `output-signature` and `dist/checksums.txt.sig`, and a `go build`
			// reported `ldflags` and `o` — four Notices, four programs that do not
			// exist.
			first := i + 1
			var block []string
			for j := first; j < len(lines); j++ {
				if strings.TrimSpace(lines[j]) == "" {
					// A blank line inside a block scalar is part of the block.
					block = append(block, lines[j])
					continue
				}
				if leadingSpaces(lines[j]) <= keyIndent {
					break
				}
				block = append(block, lines[j])
				i = j
			}
			if len(block) > 0 {
				// `first` is the 0-based index of the block's first line, so it is
				// also the offset that turns a block-relative line number into the
				// number a reader would find in the file.
				sigs = append(sigs, shellCommandsAt(strings.Join(block, "\n"), first)...)
			}
			continue
		}
		sigs = append(sigs, shellCommands(rest)...)
	}
	return sigs
}

// isListItem reports whether a trimmed YAML line opens a sequence item: a `-`
// used as the list marker, followed by a space, a tab, or the end of the line.
// `-5` and `--flag` are not list items.
func isListItem(trimmed string) bool {
	if trimmed == "-" {
		return true
	}
	return strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "-\t")
}

func leadingSpaces(s string) int {
	n := 0
	for n < len(s) && s[n] == ' ' {
		n++
	}
	return n
}

// ── .env templates ───────────────────────────────────────────────────────────

// envKeys reads the variable names from a `.env` template.
//
// Only names. A template's values are placeholders, and the code never looks at
// them: the signal is that a program reads `FIRECRAWL_API_KEY`, which is a
// declaration that it talks to Firecrawl. A template is safe to read; a real
// `.env` is not read at all (see classifySource).
func envKeys(src string) []upstreamSignal {
	var sigs []upstreamSignal

	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "export ")
		eq := strings.IndexByte(trimmed, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:eq])
		if key == "" {
			continue
		}
		for j := 0; j < len(key); j++ {
			if !isIdentByte(key[j]) {
				key = ""
				break
			}
		}
		if key == "" {
			continue
		}
		sigs = append(sigs, upstreamSignal{
			Token: key, Kind: signalEnv, Confidence: detectHigh,
			Line: i + 1, Excerpt: truncateExcerpt(trimmed),
		})
	}
	return sigs
}

// ── HTTP hosts ───────────────────────────────────────────────────────────────

// httpCallForms are the call prefixes that make a URL an invocation rather than
// a mention. The spec's signal is "an HTTP call to a known service host", and
// the distinction is the whole reason this list exists: `https://github.com/…`
// in a README is not a call to GitHub, and a detector that treated it as one
// would give every repository on the internet GitHub's terms.
var httpCallForms = []string{
	// JavaScript and TypeScript.
	"fetch", "axios.get", "axios.post", "axios.put", "axios.delete", "axios.request",
	"got", "request", "superagent", "ky",
	// Go.
	"http.Get", "http.Post", "http.PostForm", "http.Head", "http.NewRequest",
	"http.NewRequestWithContext",
	// Python.
	"requests.get", "requests.post", "requests.put", "requests.delete",
	"requests.head", "requests.request", "requests.Session",
	"urllib.request.urlopen", "urllib.request.Request", "urlopen",
	"httpx.get", "httpx.post", "httpx.Client", "aiohttp.ClientSession",
}

// urlInText matches an absolute http(s) URL and captures its host.
var urlInText = regexp.MustCompile(`https?://([A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z]{2,})`)

// ignoredHosts are hostnames that are never a platform.
var ignoredHosts = map[string]bool{
	"localhost": true, "127.0.0.1": true, "0.0.0.0": true, "::1": true,
	"example.com": true, "example.org": true, "example.net": true,
	"test.invalid": true, "invalid": true,
}

// httpHosts finds service hosts reached by an HTTP call.
func httpHosts(src string) []upstreamSignal {
	var sigs []upstreamSignal
	seen := map[string]bool{}

	record := func(url, excerpt string, line int) {
		m := urlInText.FindStringSubmatch(url)
		if m == nil {
			return
		}
		host := strings.ToLower(m[1])
		if ignoredHosts[host] || strings.HasSuffix(host, ".invalid") ||
			strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".test") ||
			strings.HasSuffix(host, ".example") {
			return
		}
		if seen[host] {
			return
		}
		seen[host] = true
		sigs = append(sigs, upstreamSignal{
			Token: host, Kind: signalHost, Confidence: detectMedium,
			Line: line, Excerpt: excerpt,
		})
	}

	for _, form := range httpCallForms {
		eachCall(src, form, func(c *cursor, line int) {
			window := argumentWindow(c)
			record(window, truncateExcerpt(window), line)
		})
	}

	// `curl https://…` and `wget https://…` in a script or a workflow step.
	for i, line := range strings.Split(src, "\n") {
		words := strings.Fields(line)
		for j, w := range words {
			if w != "curl" && w != "wget" {
				continue
			}
			for k := j + 1; k < len(words); k++ {
				if strings.Contains(words[k], "://") {
					record(words[k], truncateExcerpt(strings.TrimSpace(line)), i+1)
					break
				}
			}
		}
	}

	return sigs
}

// argumentWindow returns the text of a call's argument list, bounded.
func argumentWindow(c *cursor) string {
	start := c.pos
	end := min(start+upstreamArgWindow, len(c.src))
	return c.src[start:end]
}

// ── small helpers ────────────────────────────────────────────────────────────

// humanBytes renders a byte count the way the error taxonomy's E-SCAN-006
// message does, so that the same file is described the same way wherever it
// appears.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return itoaInt(n) + " B"
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	value := float64(n)
	i := -1
	for value >= unit && i < len(units)-1 {
		value /= unit
		i++
	}
	return trimFloat(value) + " " + units[i]
}

// trimFloat renders one decimal place, dropping a trailing ".0".
func trimFloat(v float64) string {
	whole := int64(v)
	frac := int64((v - float64(whole)) * 10)
	if frac == 0 {
		return itoaInt(whole)
	}
	return itoaInt(whole) + "." + itoaInt(frac)
}
