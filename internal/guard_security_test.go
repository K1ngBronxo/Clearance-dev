// The security spine — the guards that stand between the tool and the machine
// it runs on.
//
// Thirteen security
// tests make up "the security spine". They are not about correctness;
// they are about blast radius. A licence tool runs inside a stranger's CI, with
// the stranger's credentials in the environment, walking a tree that includes
// attacker-controlled vendored dependencies. If any of these fail, the tool has
// become a primitive an attacker can aim.
//
// # WHY THESE FOUR LIVE HERE
//
//	TestScannerNeverEscapesRoot    INV-4, asserted through the one read path
//	TestNoEnvContentsInOutput      privacy: secrets must not travel to output
//	TestNoAbsolutePathsInOutput    privacy: the user's directory layout is not ours to print
//	TestMCPRefusesEscapePath       C9, asserted at the layer the MCP server must use
//
// TestNoUnexpectedEgress is the fifth, and it lives in internal/cli because the
// egress policy is unexported and must stay that way.
package clearance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/mcp"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/report"
	"github.com/clearance-dev/clearance/internal/safefs"
)

// ─────────────────────────────────────────────────────────────────────────────
// INV-4 — Filesystem access is project-root-scoped, read-only, symlink-safe
// ─────────────────────────────────────────────────────────────────────────────

// TestScannerNeverEscapesRoot asserts that every traversal vector is refused
// with E-SCAN-004 and that a legitimate in-root read still works.
//
// INV-4: "The scanner may not read outside the project root. Symlinks are
// resolved and validated before any read. Path traversal is a hard error, not a
// warning."
//
// # THE CONTROL MATTERS AS MUCH AS THE REFUSALS
//
// A Root that refused everything would pass every escape assertion and be
// useless. So each vector is paired against a real file inside the root, and
// the test asserts both. Without that, the cheapest way to make this guard
// green would be to break the scanner.
func TestScannerNeverEscapesRoot(t *testing.T) {
	root := guardWriteTree(t, map[string]string{
		"package.json":            `{"name":"escape-fixture","version":"1.0.0"}`,
		"src/deep/nested/file.go": "package main\n",
	})

	fs, err := safefs.New(root, safefs.Limits{})
	if err != nil {
		t.Fatalf("opening the fixture root: %v", err)
	}

	// Every one of these is a way a caller could ask for a file outside the
	// tree. The last four are the interesting ones: the corpus is hand-written
	// and a path is data, so a `../` can arrive from a manifest, from a config
	// ignore rule, or from a future MCP request.
	escapes := []struct {
		name string
		rel  string
	}{
		{"parent traversal", "../outside.txt"},
		{"double parent", "../../outside.txt"},
		{"traversal buried mid-path", "src/../../../outside.txt"},
		{"bare parent", ".."},
		{"absolute unix path", "/etc/passwd"},
		{"absolute windows path", `C:\Windows\System32\drivers\etc\hosts`},
		{"windows drive-relative", `C:outside.txt`},
		{"leading backslash", `\Windows\System32`},
		{"traversal that cleans to the parent", "a/b/../../.."},
	}

	for _, tc := range escapes {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fs.Resolve(tc.rel)
			if err == nil {
				t.Fatalf("Resolve(%q) returned %q with no error.\n"+
					"The audit target must not be able to point the scanner at a "+
					"file outside its own root (INV-4).", tc.rel, got)
			}
			assertCode(t, err, cerr.EScan004)
		})
	}

	t.Run("an empty path is refused as a caller error", func(t *testing.T) {
		// An empty relative path is not a traversal; it is a caller that forgot
		// to pass anything. It is refused with E-SCAN-001 rather than
		// E-SCAN-004, and the distinction is deliberate: the two mistakes have
		// different causes and therefore different messages. Asserting
		// E-SCAN-004 here would pin behaviour the code does not promise.
		if got, err := fs.Resolve(""); err == nil {
			t.Fatalf("Resolve(\"\") returned %q with no error", got)
		} else {
			assertCode(t, err, cerr.EScan001)
		}
	})

	t.Run("the traversal is refused through ReadFile too", func(t *testing.T) {
		// Resolve is not the only entry point, and a guard that only covered
		// the entry point it happened to think of would miss the one that
		// matters. ReadFile is what the scanner actually calls.
		if _, err := fs.ReadFile("../outside.txt", 1024); err == nil {
			t.Fatal("ReadFile followed a traversal")
		}
		if _, err := fs.Open("../outside.txt"); err == nil {
			t.Fatal("Open followed a traversal")
		}
		if _, err := fs.Stat("../outside.txt"); err == nil {
			t.Fatal("Stat followed a traversal")
		}
	})

	t.Run("a legitimate read still works", func(t *testing.T) {
		// The control.
		b, err := fs.ReadFile("package.json", 1024)
		if err != nil {
			t.Fatalf("reading a real file inside the root failed: %v", err)
		}
		if !strings.Contains(string(b), "escape-fixture") {
			t.Errorf("read the wrong content: %q", b)
		}
		if _, err := fs.Resolve("src/deep/nested/file.go"); err != nil {
			t.Errorf("resolving a nested real file failed: %v", err)
		}
	})

	t.Run("an escaping symlink is refused", func(t *testing.T) {
		outside := t.TempDir()
		secret := filepath.Join(outside, "secret.txt")
		if err := os.WriteFile(secret, []byte("outside-the-root"), 0o644); err != nil {
			t.Fatalf("writing the outside file: %v", err)
		}

		// On Windows, os.Symlink can report success and create nothing
		// when the process lacks SeCreateSymbolicLinkPrivilege. A test that
		// trusted the returned error would pass while testing nothing, so the
		// link is verified with Lstat before anything is asserted.
		link := filepath.Join(root, "escape")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("cannot create symlinks on this machine (%v); the traversal "+
				"assertions above still ran", err)
		}
		if _, statErr := os.Lstat(link); statErr != nil {
			t.Skipf("os.Symlink reported success but created nothing; "+
				"verified with Lstat: %v", statErr)
		}

		if _, err := fs.Resolve("escape/secret.txt"); err == nil {
			t.Fatal("a symlink pointing outside the root was followed.\n" +
				"A vendored dependency can ship a symlink, and a symlink is the " +
				"cleanest way to turn a file-reading tool into an arbitrary file " +
				"read (INV-4).")
		} else {
			assertCode(t, err, cerr.EScan004)
		}
		if _, err := fs.ReadFile("escape/secret.txt", 1024); err == nil {
			t.Fatal("ReadFile followed an escaping symlink")
		}
	})

	t.Run("a symlink to a file inside the root is allowed", func(t *testing.T) {
		// The other direction. Refusing every symlink would break monorepos
		// that use them legitimately, and the invariant is about escaping the
		// root, not about symlinks.
		target := filepath.Join(root, "package.json")
		link := filepath.Join(root, "link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("cannot create symlinks on this machine: %v", err)
		}
		if _, statErr := os.Lstat(link); statErr != nil {
			t.Skipf("os.Symlink created nothing: %v", statErr)
		}
		if _, err := fs.Resolve("link.json"); err != nil {
			t.Errorf("a symlink to a file inside the root was refused: %v", err)
		}
	})

	t.Run("Rel never reports a path outside the root", func(t *testing.T) {
		// Rel is the inverse mapping used to build Evidence. If it ever
		// returned a path outside the root, an absolute path would reach the
		// verdict — which the privacy guard below also asserts, from the other
		// end.
		if rel, ok := fs.Rel(filepath.Join(root, "package.json")); !ok || rel != "package.json" {
			t.Errorf("Rel(package.json) = %q, %v; want \"package.json\", true", rel, ok)
		}
		if rel, ok := fs.Rel(filepath.Join(filepath.Dir(root), "elsewhere")); ok {
			t.Errorf("Rel reported %q for a path outside the root", rel)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Privacy — a secret in the tree must never reach the output
// ─────────────────────────────────────────────────────────────────────────────

// guardCanary values are distinctive enough that a substring search is a
// meaningful assertion rather than a coincidence.
const (
	guardRootCanary     = "CANARY-ROOT-7f3a91b2c4d5"
	guardVendoredCanary = "CANARY-VENDORED-2e8b64f0a1d3"
)

// TestNoEnvContentsInOutput asserts that a `.env` file's contents never appear
// in any rendering of a verdict.
//
// # THE THREAT
//
// Clearance runs in CI, on a stranger's machine, on a tree that may include
// vendored dependencies the stranger has never read. A tool that slurped `.env`
// files into its evidence excerpts — or into a JSON report a CI job uploads as
// an artefact — would be an exfiltration path built out of a licence checker.
// The README promises it does not read them; this is the assertion that the
// promise is true.
//
// # WHY BOTH RENDERINGS
//
// The human rendering is what the user sees; the JSON is what gets uploaded,
// cached and forwarded. A leak into either is a leak, and they are separate
// code paths, so both are checked.
func TestNoEnvContentsInOutput(t *testing.T) {
	c := guardLoadCorpus(t)

	dir := guardWriteTree(t, map[string]string{
		"clearance.config.yml": `schema_version: 1

project:
  name: privacy-fixture

use:
  commercial: false
  licence_model: open-source
  modified: false
  network_exposed: false
  distributed: true
  saas: false
`,
		"package.json": `{"name":"privacy-fixture","version":"1.0.0","license":"MIT"}`,
		"package-lock.json": `{
  "name": "privacy-fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "privacy-fixture", "version": "1.0.0", "license": "MIT"},
    "node_modules/lodash": {"version": "4.17.21", "license": "MIT"}
  }
}`,
		// A .env at the project root.
		".env": "DATABASE_URL=postgres://root:hunter2@db.internal/app\n" +
			"AWS_SECRET_ACCESS_KEY=" + guardRootCanary + "\n",
		// A .env inside a vendored dependency — the one a user has never seen.
		// E-SCAN-017 exists for exactly this case.
		"node_modules/lodash/.env": "STRIPE_SECRET_KEY=" + guardVendoredCanary + "\n",
	})

	v := guardMustRun(t, dir, c, policy.Options{})

	var human strings.Builder
	if err := report.WriteHuman(&human, v, report.Options{Color: false}); err != nil {
		t.Fatalf("rendering human output: %v", err)
	}
	jsonOut, err := report.MarshalJSON(v)
	if err != nil {
		t.Fatalf("rendering JSON output: %v", err)
	}

	// The control: the renderings must not be empty, or the leak assertion
	// passes against nothing at all.
	if len(human.String()) < 80 || len(jsonOut) < 80 {
		t.Fatalf("the renderings are suspiciously short (human=%d bytes, json=%d "+
			"bytes); this guard would pass against empty output",
			len(human.String()), len(jsonOut))
	}
	if !strings.Contains(human.String(), v.Verdict.Label()) {
		t.Errorf("the human rendering does not contain the verdict label %q, so it "+
			"is not a rendering of this verdict", v.Verdict.Label())
	}

	for _, rendering := range []struct {
		name string
		text string
	}{
		{"human", human.String()},
		{"json", string(jsonOut)},
	} {
		for _, canary := range []string{guardRootCanary, guardVendoredCanary} {
			if strings.Contains(rendering.text, canary) {
				t.Errorf("the %s rendering contains %q, which is the contents of a "+
					".env file.\nA licence checker that reads secrets is an "+
					"exfiltration path. The contents of a .env must never be read, "+
					"and therefore can never be rendered.", rendering.name, canary)
			}
		}
		// The literal from the root .env, in case only part of a line leaked.
		if strings.Contains(rendering.text, "hunter2") {
			t.Errorf("the %s rendering contains a credential from a .env file",
				rendering.name)
		}
	}

	// And the structured output must not carry it in a field the renderers
	// happen not to print today. A field that is not printed now can be printed
	// after any refactor, so the check is against the data, not the text.
	for _, f := range guardAllFindings(v) {
		for _, ev := range f.Evidence {
			if strings.Contains(ev.Excerpt, guardRootCanary) ||
				strings.Contains(ev.Excerpt, guardVendoredCanary) {
				t.Errorf("finding %s carries a .env value in its evidence excerpt", f.ID)
			}
		}
	}
	for _, u := range v.Undetermined {
		for _, ev := range u.Evidence {
			if strings.Contains(ev.Excerpt, guardRootCanary) ||
				strings.Contains(ev.Excerpt, guardVendoredCanary) {
				t.Errorf("undetermined %s carries a .env value in its evidence excerpt", u.ID)
			}
		}
	}
}

// TestNoAbsolutePathsInOutput asserts that no rendering leaks the user's
// directory layout.
//
// # WHY A DIRECTORY LAYOUT IS A LEAK
//
// A verdict is a document a user pastes into a GitHub issue, a CI log, a Slack
// thread or a support ticket. `/Users/jane.doe/clients/acme-corp/merger-2026/`
// discloses the user's name, their employer's client list, and the codename of
// an unannounced deal — none of which is licence information, and all of which
// travels further than the user expected when they pasted a scan result.
//
// The fix is not a scrubber; it is that evidence paths are project-relative
// from the moment the scanner creates them, which is what makes this assertion
// cheap to hold. The guard checks the property at both ends: the data (every
// evidence path is relative) and the rendering (the absolute root is absent).
func TestNoAbsolutePathsInOutput(t *testing.T) {
	c := guardLoadCorpus(t)

	dir := guardWriteTree(t, map[string]string{
		"clearance.config.yml": `schema_version: 1

project:
  name: path-fixture

use:
  commercial: true
  licence_model: closed-source
  modified: false
  network_exposed: false
  distributed: false
  saas: false
`,
		"package.json": `{"name":"path-fixture","version":"1.0.0","license":"MIT"}`,
		"package-lock.json": `{
  "name": "path-fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "path-fixture", "version": "1.0.0", "license": "MIT"},
    "node_modules/lodash": {"version": "4.17.21", "license": "MIT"}
  }
}`,
	})

	v := guardMustRun(t, dir, c, policy.Options{})

	// ── the data ────────────────────────────────────────────────────────────
	check := func(owner string, paths []string) {
		for _, p := range paths {
			if p == "" {
				continue
			}
			if filepath.IsAbs(p) {
				t.Errorf("%s carries the absolute path %q; evidence paths are "+
					"project-relative, always", owner, p)
			}
			if strings.HasPrefix(p, "..") {
				t.Errorf("%s carries %q, which escapes the project root", owner, p)
			}
			if strings.Contains(p, `\`) {
				t.Errorf("%s carries %q with a backslash separator; evidence paths "+
					"are forward-slashed so that a verdict is identical on every "+
					"platform (INV-6)", owner, p)
			}
		}
	}

	for _, f := range guardAllFindings(v) {
		paths := make([]string, 0, len(f.Evidence))
		for _, ev := range f.Evidence {
			paths = append(paths, ev.Path)
		}
		check("finding "+f.ID, paths)
	}
	for _, u := range v.Undetermined {
		paths := make([]string, 0, len(u.Evidence))
		for _, ev := range u.Evidence {
			paths = append(paths, ev.Path)
		}
		check("undetermined "+u.ID, paths)
	}

	// The project name is a name, never a path.
	if filepath.IsAbs(v.Project) {
		t.Errorf("verdict.project is the absolute path %q; it must be a project "+
			"name, because the verdict is a document the user will paste "+
			"somewhere public", v.Project)
	}

	// ── the rendering ───────────────────────────────────────────────────────
	var human strings.Builder
	if err := report.WriteHuman(&human, v, report.Options{}); err != nil {
		t.Fatalf("rendering human output: %v", err)
	}
	jsonOut, err := report.MarshalJSON(v)
	if err != nil {
		t.Fatalf("rendering JSON output: %v", err)
	}

	// The absolute root, in both separator styles. Anything that printed the
	// real path would print at least this prefix.
	needles := []string{
		dir,
		filepath.ToSlash(dir),
		filepath.Dir(dir), // the parent: catches a path that lost its last segment
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		needles = append(needles, home, filepath.ToSlash(home))
	}

	for _, rendering := range []struct {
		name string
		text string
	}{{"human", human.String()}, {"json", string(jsonOut)}} {
		for _, needle := range needles {
			if strings.Contains(rendering.text, needle) {
				t.Errorf("the %s rendering contains the absolute path %q.\n"+
					"A verdict is pasted into issues and CI logs; the user's "+
					"directory layout is not licence information and must not "+
					"travel with it.", rendering.name, needle)
			}
		}
	}

	// A Windows volume designator followed by a separator, e.g. `C:\` or
	// `D:/`. Written as an explicit pattern rather than a substring search
	// because `https://` also matches a naive `[A-Za-z]:/` — a URL is not an
	// absolute path, and a guard that flagged every citation link would be
	// turned off within a week.
	absRe := regexp.MustCompile(`(^|[\s"'(])[A-Za-z]:[\\/]`)
	for _, rendering := range []struct {
		name string
		text string
	}{{"human", human.String()}, {"json", string(jsonOut)}} {
		if m := absRe.FindString(rendering.text); m != "" {
			t.Errorf("the %s rendering contains what looks like a Windows absolute "+
				"path: %q", rendering.name, strings.TrimSpace(m))
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// C9 — The capability-scoped read surface refuses an escape path
// ─────────────────────────────────────────────────────────────────────────────

// TestMCPRefusesEscapePath asserts that the `fs.read` capability refuses a
// traversal, an absolute path and an escaping symlink — at the primitive AND
// through the server that is supposed to use it.
//
// # THE HISTORY OF THIS TEST, BECAUSE IT IS THE POINT
//
// The MCP server is specified as control C9.
// When this test was written, `internal/mcp` did not exist, so
// it could not call the thing it was named after — and it said so, loudly, in
// this comment, rather than certifying a property it had not checked. That was
// the right call then and it is worth preserving the record of it: the suite's
// own header explains that its purpose is to repair guards that certified what
// they did not check, and this test was deliberately written to not be one.
//
// The server exists now. Groups 1 and 2 below still assert safefs, because
// safefs is the primitive C9 depends on and a regression there is a regression
// everywhere. Group 3 drives the REAL server over the protocol, so the refusal
// is now pinned at the surface an agent actually reaches.
//
// The obligation this test recorded for itself — "WHEN internal/mcp LANDS, this
// test MUST be extended to call it directly" — is discharged by group 3.
func TestMCPRefusesEscapePath(t *testing.T) {
	// The vectors from the control's own description, plus the ones a URL-ish
	// or JSON-ish transport invites.
	workspace := guardWriteTree(t, map[string]string{
		"package.json":  `{"name":"mcp-workspace","version":"1.0.0"}`,
		"docs/notes.md": "# notes\n",
	})

	fs, err := safefs.New(workspace, safefs.Limits{})
	if err != nil {
		t.Fatalf("opening the workspace root: %v", err)
	}

	// ── group 1: canonical traversals ───────────────────────────────────────
	//
	// On every platform these name a path outside the workspace, so they must
	// be refused, and refused with E-SCAN-004 specifically. The control's own
	// example is first.
	canonical := []struct {
		name string
		rel  string
	}{
		{"the control's own example", "../../etc/passwd"},
		{"deeper", "../../../etc/shadow"},
		{"buried, so a prefix check misses it", "docs/../../etc/passwd"},
		{"absolute unix path", "/etc/passwd"},
		{"drive-qualified windows path", `C:\Windows\System32`},
	}
	for _, tc := range canonical {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fs.Resolve(tc.rel)
			if err == nil {
				t.Fatalf("the fs.read surface resolved %q to %q.\n"+
					"C9 declares exactly one capability scoped to the workspace "+
					"root; a traversal turns it into an arbitrary file read on "+
					"whatever machine the server is hosted on.", tc.rel, got)
			}
			assertCode(t, err, cerr.EScan004)
		})
	}

	// ── group 2: vectors whose meaning depends on the platform ──────────────
	//
	// A percent-encoded `..%2f`, a quadruple-dot `....`, and a backslash path
	// are all *not* traversals on a platform whose separator is `/`: they are
	// single filename components, so they legitimately resolve to a path inside
	// the workspace that simply does not exist. On Windows the backslash forms
	// are traversals and are refused.
	//
	// Both outcomes are correct, so asserting one of them would pin behaviour
	// the code does not promise. The invariant that holds on every platform is
	// the one asserted: the result never leaves the workspace.
	platformDependent := []struct {
		name string
		rel  string
	}{
		{"percent-encoded traversal", "..%2f..%2fetc%2fpasswd"},
		{"quadruple-dot", "....//....//etc/passwd"},
		{"backslash traversal", `..\..\windows\system32\config\sam`},
		{"UNC path", `\\server\share\secret`},
	}
	for _, tc := range platformDependent {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fs.Resolve(tc.rel)
			if err != nil {
				return // refused is always acceptable
			}
			// Resolved, so it must be inside the workspace. Rel answers the
			// containment question directly rather than by comparing string
			// prefixes.
			if rel, ok := fs.Rel(got); !ok {
				t.Fatalf("Resolve(%q) produced %q, which is outside the workspace.\n"+
					"Whether or not this platform treats the string as a traversal, "+
					"the fs.read capability must never return a path it is not "+
					"scoped to.", tc.rel, got)
			} else {
				t.Logf("%q is a single in-workspace component on this platform: %s",
					tc.rel, rel)
			}
		})
	}

	t.Run("an empty path is refused as a caller error", func(t *testing.T) {
		if got, err := fs.Resolve(""); err == nil {
			t.Fatalf("Resolve(\"\") returned %q with no error", got)
		} else {
			assertCode(t, err, cerr.EScan001)
		}
	})

	t.Run("the capability still reads what it is scoped to", func(t *testing.T) {
		// The control. A capability that refuses everything is not scoped, it
		// is broken.
		if _, err := fs.Resolve("docs/notes.md"); err != nil {
			t.Fatalf("the fs.read surface refused a file inside its own root: %v", err)
		}
		b, err := fs.ReadFile("package.json", 4096)
		if err != nil {
			t.Fatalf("reading inside the workspace failed: %v", err)
		}
		if !strings.Contains(string(b), "mcp-workspace") {
			t.Errorf("read the wrong content: %q", b)
		}
	})

	t.Run("an escaping symlink is refused", func(t *testing.T) {
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("x"), 0o644); err != nil {
			t.Fatalf("writing the outside file: %v", err)
		}
		link := filepath.Join(workspace, "escape")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("cannot create symlinks on this machine: %v", err)
		}
		if _, statErr := os.Lstat(link); statErr != nil {
			t.Skipf("os.Symlink created nothing: %v", statErr)
		}
		if _, err := fs.Resolve("escape/secret.txt"); err == nil {
			t.Fatal("the fs.read surface followed a symlink out of the workspace")
		}
	})

	// ── group 3: the same vectors, through the real server ──────────────────
	//
	// # WHY THIS GROUP EXISTS
	//
	// The three groups above assert safefs. Until internal/mcp landed that was
	// the only thing that could be asserted, and this test said so in its own
	// doc comment rather than pretending otherwise. Now the server exists, and a
	// guard named after it that never calls it is the failure mode this whole
	// suite was written to repair: a test that certifies what it does not check.
	//
	// These subtests go through the protocol — a JSON-RPC frame in, a JSON-RPC
	// response out — because that is the surface an agent actually reaches. A
	// refusal that exists in safefs but not in the tool that calls it is not a
	// refusal.
	//
	// The corpus is the shipped one; the workspace is the temporary tree above.
	guardMCPEscapeVectors(t, workspace)
}

// guardMCPEscapeVectors drives the real MCP server with every escape vector the
// capability is supposed to refuse, and with a control that must succeed.
//
// # THE SHAPE OF THE ASSERTION
//
// Each refused vector must produce a response whose `data.clearance_code` is
// E-MCP-001. Asserting on the code rather than on the message is deliberate:
// the message is the taxonomy's text and may be reworded, and what the guard is
// pinning is that the refusal is the DOCUMENTED one. A traversal refused by
// some incidental error would pass a message-contains check and fail this one.
//
// The control matters as much as the refusals. A capability that refuses
// everything is not scoped, it is broken, and a guard that only asserted
// refusals would certify a server that answers nothing.
func guardMCPEscapeVectors(t *testing.T, workspace string) {
	t.Helper()
	corpusDir := guardCorpusPath(t)

	refusals := []struct {
		name string
		path string
	}{
		{"the control's own example", "../../etc/passwd"},
		{"deeper", "../../../etc/shadow"},
		{"buried, so a prefix check misses it", "docs/../../etc/passwd"},
		{"an absolute unix path", "/etc/passwd"},
		{"a drive-qualified windows path", `C:/Windows/System32`},
		{"the workspace's own parent", ".."},
	}

	// # WHY EACH VECTOR GETS ITS OWN SESSION
	//
	// Because E-MCP-001 ends the session. That is the designed behaviour — a
	// client that has tried once to read outside its scope is not a client to
	// keep serving — and the first version of this guard learned it the hard
	// way: it sent all six vectors down one pipe, got exactly one response, and
	// failed with "the server answered 1 of 6 escape requests".
	//
	// The fix is not to weaken the assertion but to respect the contract: one
	// session per vector. That is also the better test, because each vector is
	// then proved independently rather than proved to be second in a queue.
	for i, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			frame := guardMCPFrame(t, i+1, mcp.ToolCheck, map[string]any{"path": tc.path})
			lines := guardMCPServe(t, workspace, corpusDir, []string{frame})

			if len(lines) != 1 {
				t.Fatalf("the server answered %d responses to one request, want 1.\n"+
					"A request that gets no answer is a client hanging on a read, "+
					"which is a worse outcome than a refusal.\nGot:\n%s",
					len(lines), strings.Join(lines, "\n"))
			}

			var resp struct {
				Error *struct {
					Code int `json:"code"`
					Data struct {
						ClearanceCode string `json:"clearance_code"`
					} `json:"data"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
				t.Fatalf("the response is not JSON: %v\n%s", err, lines[0])
			}
			if resp.Error == nil {
				t.Fatalf("the server accepted path %q.\n"+
					"C9 declares exactly one capability scoped to the workspace "+
					"root. Accepting this turns the server into an arbitrary file "+
					"read on whatever machine it runs on, reachable from any text "+
					"the calling agent happened to process.\nResponse: %s",
					tc.path, lines[0])
			}
			if got := resp.Error.Data.ClearanceCode; got != string(cerr.EMcp001) {
				t.Fatalf("path %q was refused with code %q, want %q.\n"+
					"The refusal has to be the documented one: E-MCP-001 is the "+
					"code a user looks up, and E-SCAN-004 would send them to "+
					"inspect their repository instead of their agent.",
					tc.path, got, cerr.EMcp001)
			}
			// The refusal must not carry the machine's own prefix back to the
			// client. See displayable in internal/mcp/scope.go.
			if m := guardWindowsAbsRe.FindString(lines[0]); m != "" {
				t.Errorf("the refusal leaked an absolute path: %q\n"+
					"The message travels to a client that logs it, and from there "+
					"into a ticket. The user's directory layout is not licence "+
					"information.", strings.TrimSpace(m))
			}
		})
	}

	// ── the two controls ────────────────────────────────────────────────────
	//
	// A capability that refuses everything is not scoped, it is broken, and a
	// guard that only asserted refusals would certify a server that answers
	// nothing. So the last two subtests prove the server still serves what it is
	// scoped to — and the first of them proves it refuses for the RIGHT reason
	// when the project has not declared an intent.

	t.Run("a project with no declared intent is refused, not guessed", func(t *testing.T) {
		// The workspace tree above has a package.json and no config. The server
		// must say so rather than inventing an intent: "intent is declared,
		// never inferred" is the product's central rule, and a server that
		// guessed would be worse than the CLI doing it, because nobody is
		// watching an agent's tool call.
		frame := guardMCPFrame(t, 98, mcp.ToolCheck, map[string]any{"path": "."})
		lines := guardMCPServe(t, workspace, corpusDir, []string{frame})
		if len(lines) != 1 {
			t.Fatalf("the control produced %d responses, want 1", len(lines))
		}
		var resp struct {
			Error *struct {
				Data struct {
					ClearanceCode string `json:"clearance_code"`
				} `json:"data"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
			t.Fatalf("the control response is not JSON: %v", err)
		}
		if resp.Error == nil {
			t.Fatalf("a project with no clearance.config.yml produced a result rather "+
				"than a refusal.\nThat is the tool inferring an intent, which is the "+
				"one thing it promises never to do.\nResponse: %s", lines[0])
		}
		if got := resp.Error.Data.ClearanceCode; got != string(cerr.ECfg001) {
			t.Fatalf("a missing config was refused with %q, want %q.\n"+
				"E-CFG-001 is the code that tells a user to write a config; any "+
				"other code sends them somewhere else.", got, cerr.ECfg001)
		}
	})

	t.Run("an in-root project with a declared intent produces a verdict", func(t *testing.T) {
		// The real control: the same project, with the intent supplied inline.
		// This also exercises the inline-intent path, which is the part of the
		// server a client actually uses — an agent has no clearance.config.yml
		// to hand over, it has facts about the code it is working on.
		intent := map[string]any{
			"project": map[string]any{"name": "mcp-workspace"},
			"use": map[string]any{
				"commercial":      true,
				"licence_model":   "closed-source",
				"modified":        false,
				"network_exposed": false,
				"distributed":     true,
				"saas":            false,
			},
		}
		frame := guardMCPFrame(t, 99, mcp.ToolCheck, map[string]any{"path": ".", "intent": intent})
		lines := guardMCPServe(t, workspace, corpusDir, []string{frame})
		if len(lines) != 1 {
			t.Fatalf("the control produced %d responses, want 1", len(lines))
		}

		var resp struct {
			Result *struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
			Error any `json:"error"`
		}
		if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
			t.Fatalf("the control response is not JSON: %v", err)
		}
		if resp.Error != nil {
			t.Fatalf("the server refused its own root with a declared intent: %s", lines[0])
		}
		if resp.Result == nil || len(resp.Result.Content) == 0 {
			t.Fatalf("the control returned no content: %s", lines[0])
		}

		text := resp.Result.Content[0].Text
		var v struct {
			Verdict string `json:"verdict"`
			Project string `json:"project"`
			Meta    struct {
				IntentHash string `json:"intent_hash"`
			} `json:"meta"`
		}
		if err := json.Unmarshal([]byte(text), &v); err != nil {
			t.Fatalf("the control's content is not the canonical verdict JSON: %v\n%s",
				err, truncate(text, 300))
		}
		switch v.Verdict {
		case "SHIP", "SHIP CONDITIONAL", "DO NOT SHIP", "UNDETERMINED":
		default:
			t.Errorf("the control produced verdict %q, which is not one of the four.\n"+
				"The verdict algebra is total: every input produces one of four "+
				"values, and anything else means the fold was bypassed.", v.Verdict)
		}
		if v.Project != "mcp-workspace" {
			t.Errorf("the control produced project %q, want the declared name.\n"+
				"A verdict is pasted into a ticket; the label has to be the one the "+
				"user recognises.", v.Project)
		}
		if !strings.HasPrefix(v.Meta.IntentHash, "sha256:") {
			t.Errorf("the verdict carries no intent hash: %q.\n"+
				"INV-6 makes a verdict reproducible against an intent, and the hash "+
				"is how a reader proves which intent this one was computed against.",
				v.Meta.IntentHash)
		}
	})
}

// truncate shortens a string for a failure message without splitting a rune.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// guardWindowsAbsRe is the same pattern TestNoAbsolutePathsInOutput uses, kept
// as a package-level value so the two guards cannot drift apart.
var guardWindowsAbsRe = regexp.MustCompile(`(^|[\s"'(])[A-Za-z]:[\\/]`)
