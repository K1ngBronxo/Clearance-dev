package parsers

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// resultSnapshot projects a Result onto a string two identical parses must
// produce. Result carries a *cerr.Error, and deep-comparing error values is
// exactly what govet's deepequalerrors guard exists to stop: two runs build
// separate error values, and the comparison can agree for the wrong reason.
// The warning's code and rendered message are the parts a user ever sees, so
// that is what determinism is asserted over.
func resultSnapshot(r Result) string {
	warn := "<nil>"
	if r.Warning != nil {
		warn = fmt.Sprintf("%s: %s", r.Warning.Code(), r.Warning.Error())
	}
	return fmt.Sprintf("%v|%s|%v|%s", r.Declared, r.OwnLicence, r.Fallback, warn)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func mustManifest(t *testing.T, p Parser, rel, body string) Result {
	t.Helper()
	res, err := p.ParseManifest(rel, []byte(body))
	if err != nil {
		t.Fatalf("%s.ParseManifest(%s) returned an unexpected error: %v", p.Ecosystem(), rel, err)
	}
	return res
}

func mustLockfile(t *testing.T, p Parser, rel, body string) Result {
	t.Helper()
	res, err := p.ParseLockfile(rel, []byte(body))
	if err != nil {
		t.Fatalf("%s.ParseLockfile(%s) returned an unexpected error: %v", p.Ecosystem(), rel, err)
	}
	return res
}

// find returns the declaration for a name, failing the test when absent.
func find(t *testing.T, res Result, name string) Declared {
	t.Helper()
	for _, d := range res.Declared {
		if d.Name == name {
			return d
		}
	}
	var have []string
	for _, d := range res.Declared {
		have = append(have, d.Name)
	}
	t.Fatalf("no declaration for %q; have %v", name, have)
	return Declared{}
}

// ── the regression test that matters most ────────────────────────────────────

// TestProjectLicenceIsNeverStampedOnDependencies is the guard for the single
// most dangerous bug this package can have.
//
// An earlier draft assigned the manifest's own licence to every dependency it
// returned. A project declaring MIT while depending on an AGPL package would
// then have had every dependency labelled MIT — a false SHIP, produced by a
// parser trying to be helpful. Every ecosystem is checked, because the mistake
// was made twice in two files and would otherwise be made again.
func TestProjectLicenceIsNeverStampedOnDependencies(t *testing.T) {
	cases := []struct {
		name     string
		parser   Parser
		file     string
		body     string
		own      string
		depNames []string
	}{
		{
			name:   "npm",
			parser: NPM{},
			file:   "package.json",
			body: `{"name":"app","license":"MIT",
			        "dependencies":{"agpl-pkg":"1.0.0"},
			        "devDependencies":{"jest":"29.0.0"}}`,
			own:      "MIT",
			depNames: []string{"agpl-pkg", "jest"},
		},
		{
			name:   "go",
			parser: GoMod{},
			file:   "go.mod",
			body: `// license: MIT
			       module example.com/app
			       require github.com/agpl/pkg v1.0.0`,
			own:      "MIT",
			depNames: []string{"github.com/agpl/pkg"},
		},
		{
			name:   "cargo",
			parser: Cargo{},
			file:   "Cargo.toml",
			body: `[package]
			       name = "app"
			       license = "MIT"

			       [dependencies]
			       agpl-pkg = "1.0"`,
			own:      "MIT",
			depNames: []string{"agpl-pkg"},
		},
		{
			name:   "pypi",
			parser: PyPI{},
			file:   "pyproject.toml",
			body: `[project]
			       name = "app"
			       license = "MIT"
			       dependencies = ["agpl-pkg"]`,
			own:      "MIT",
			depNames: []string{"agpl-pkg"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustManifest(t, tc.parser, tc.file, tc.body)
			if res.OwnLicence != tc.own {
				t.Errorf("OwnLicence = %q, want %q", res.OwnLicence, tc.own)
			}
			if len(res.Declared) != len(tc.depNames) {
				t.Fatalf("got %d declarations, want %d", len(res.Declared), len(tc.depNames))
			}
			for _, name := range tc.depNames {
				d := find(t, res, name)
				if d.LicenceRaw != "" {
					t.Errorf("dependency %q carries LicenceRaw %q; the project's own licence must never be stamped onto a dependency",
						name, d.LicenceRaw)
				}
			}
		})
	}
}

// TestNPMLockfileLicenceIsKept is the other half: a licence recorded against a
// *dependency* is a real fact and must survive. Suppressing it would trade a
// false SHIP for a false DO-NOT-SHIP.
func TestNPMLockfileLicenceIsKept(t *testing.T) {
	body := `{
	  "name": "app",
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app", "version": "1.0.0", "license": "MIT"},
	    "node_modules/left-pad": {"version": "1.3.0", "license": "WTFPL"},
	    "node_modules/@scope/pkg": {"version": "2.0.0", "license": "AGPL-3.0-only"},
	    "node_modules/a/node_modules/b": {"version": "3.0.0"}
	  }
	}`
	res := mustLockfile(t, NPM{}, "package-lock.json", body)

	// The root project is not a dependency of itself.
	if len(res.Declared) != 3 {
		t.Fatalf("got %d declarations, want 3", len(res.Declared))
	}
	if got := find(t, res, "left-pad").LicenceRaw; got != "WTFPL" {
		t.Errorf("left-pad licence = %q, want WTFPL", got)
	}
	if got := find(t, res, "@scope/pkg").LicenceRaw; got != "AGPL-3.0-only" {
		t.Errorf("@scope/pkg licence = %q, want AGPL-3.0-only", got)
	}
	if !find(t, res, "left-pad").Direct {
		t.Error("left-pad should be direct (one node_modules level)")
	}
	if find(t, res, "b").Direct {
		t.Error("a nested node_modules entry should not be direct")
	}
}

func TestNPMLockfileV1NestedTree(t *testing.T) {
	body := `{
	  "name": "app",
	  "lockfileVersion": 1,
	  "dependencies": {
	    "left-pad": {
	      "version": "1.3.0",
	      "dependencies": {"nested": {"version": "1.0.0"}}
	    }
	  }
	}`
	res := mustLockfile(t, NPM{}, "package-lock.json", body)
	if len(res.Declared) != 2 {
		t.Fatalf("got %d declarations, want 2", len(res.Declared))
	}
	if !find(t, res, "left-pad").Direct {
		t.Error("a top-level dependency should be direct")
	}
	if find(t, res, "nested").Direct {
		t.Error("a nested dependency should not be direct")
	}
}

// TestNPMLockfileUnknownStructureRefused: an empty result would look like a
// project with no dependencies, which is the most dangerous answer available.
func TestNPMLockfileUnknownStructureRefused(t *testing.T) {
	if _, err := (NPM{}).ParseLockfile("package-lock.json", []byte(`{"name":"app","lockfileVersion":3}`)); err == nil {
		t.Fatal("expected a refusal for an unrecognised lockfile structure, got nil")
	}
}

func TestNPMUnsupportedLockfilesAreDeclared(t *testing.T) {
	// The refusal has to be visible, not silent: the scanner reads this to warn.
	got := (NPM{}).UnsupportedLockfiles()
	want := []string{"pnpm-lock.yaml", "yarn.lock"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("UnsupportedLockfiles() = %v, want %v", got, want)
	}
}

// ── pypi ─────────────────────────────────────────────────────────────────────

func TestPyProjectPEP621(t *testing.T) {
	body := `[project]
name = "app"
version = "1.0.0"
license = "MIT"
dependencies = ["requests>=2.0", "flask"]
`
	res := mustManifest(t, PyPI{}, "pyproject.toml", body)
	if res.OwnLicence != "MIT" {
		t.Errorf("OwnLicence = %q, want MIT", res.OwnLicence)
	}
	req := find(t, res, "requests")
	if req.Version != "2.0" || !req.IsRange {
		t.Errorf("requests = (%q, IsRange=%v), want (2.0, true)", req.Version, req.IsRange)
	}
	if find(t, res, "flask").Version != "" {
		t.Error("an unpinned dependency should carry no version")
	}
}

func TestPyProjectPEP639TableLicence(t *testing.T) {
	body := `[project]
name = "app"
license = { text = "Apache-2.0" }
dependencies = ["requests"]
`
	res := mustManifest(t, PyPI{}, "pyproject.toml", body)
	if res.OwnLicence != "Apache-2.0" {
		t.Errorf("OwnLicence = %q, want Apache-2.0", res.OwnLicence)
	}
}

// TestPyProjectLicenceFileIsNotALicence: `license = { file = "LICENSE" }` is a
// pointer. Reporting it as a licence would put a filename where an SPDX
// identifier belongs.
func TestPyProjectLicenceFileIsNotALicence(t *testing.T) {
	body := `[project]
name = "app"
license = { file = "LICENSE" }
dependencies = ["requests"]
`
	res := mustManifest(t, PyPI{}, "pyproject.toml", body)
	if res.OwnLicence != "" {
		t.Errorf("OwnLicence = %q, want empty (a file pointer is not a licence)", res.OwnLicence)
	}
}

func TestRequirementsSkipsDirectives(t *testing.T) {
	body := `# a comment
requests==2.31.0
flask>=2.0
-r other.txt
-e .
https://example.com/pkg.whl
uvicorn==0.23.0 ; python_version < "3.9"
pkg[extra]==1.0
`
	res := mustManifest(t, PyPI{}, "requirements.txt", body)
	if len(res.Declared) != 4 {
		t.Fatalf("got %d declarations, want 4: %+v", len(res.Declared), res.Declared)
	}
	if got := find(t, res, "requests").Version; got != "2.31.0" {
		t.Errorf("requests version = %q, want 2.31.0", got)
	}
	// `==1.0` must not leave a stray operator in the display version.
	if got := find(t, res, "pkg").Version; got != "1.0" {
		t.Errorf("pkg version = %q, want 1.0 (operators are stripped)", got)
	}
	if !res.Fallback {
		t.Error("skipping -r/-e/URL directives must set Fallback so the user is told")
	}
	if res.Warning == nil {
		t.Error("skipping a directive must produce a Warning, not silence")
	}
}

func TestSetupPyIsRefused(t *testing.T) {
	_, err := (PyPI{}).ParseManifest("setup.py", []byte("from setuptools import setup\nsetup()\n"))
	if err == nil {
		t.Fatal("setup.py must be refused: reading it means parsing Python, and executing it is forbidden by INV-3")
	}
}

func TestPoetryLock(t *testing.T) {
	body := `[[package]]
name = "Requests"
version = "2.31.0"
category = "main"

[[package]]
name = "pytest"
version = "7.0.0"
category = "dev"
`
	res := mustLockfile(t, PyPI{}, "poetry.lock", body)
	if len(res.Declared) != 2 {
		t.Fatalf("got %d declarations, want 2", len(res.Declared))
	}
	// Python package names are case-insensitive; they are lowercased for lookup.
	if got := find(t, res, "requests").Version; got != "2.31.0" {
		t.Errorf("requests version = %q, want 2.31.0", got)
	}
	if !find(t, res, "pytest").Dev {
		t.Error("a poetry package with category = dev should be marked Dev")
	}
}

// ── go ───────────────────────────────────────────────────────────────────────

func TestGoModRequireBlockAndIndirect(t *testing.T) {
	body := `module example.com/app

go 1.23

require (
	github.com/direct/pkg v1.2.3
	github.com/indirect/pkg v0.9.0 // indirect
)

require github.com/single/pkg v2.0.0 // indirect
`
	res := mustManifest(t, GoMod{}, "go.mod", body)
	if len(res.Declared) != 3 {
		t.Fatalf("got %d declarations, want 3: %+v", len(res.Declared), res.Declared)
	}
	if !find(t, res, "github.com/direct/pkg").Direct {
		t.Error("a require without // indirect is direct")
	}
	if find(t, res, "github.com/indirect/pkg").Direct {
		t.Error("// indirect inside a block must be honoured")
	}
	// The single-line form is the one an earlier draft got wrong: stripping the
	// comment before looking for the marker means never finding it.
	if find(t, res, "github.com/single/pkg").Direct {
		t.Error("// indirect on a single-line require must be honoured")
	}
	if got := find(t, res, "github.com/direct/pkg").Version; got != "v1.2.3" {
		t.Errorf("version = %q, want v1.2.3", got)
	}
	if got := find(t, res, "github.com/direct/pkg").Line; got != 6 {
		t.Errorf("line = %d, want 6", got)
	}
}

// TestGoModReplaceModule: a replaced module means the code that actually gets
// built is the replacement, so the replacement's licence governs. Ignoring the
// directive would produce a graph naming a module nobody ships.
func TestGoModReplaceModule(t *testing.T) {
	body := `module example.com/app

go 1.23

require github.com/original/pkg v1.0.0

replace github.com/original/pkg => github.com/fork/pkg v1.5.0
`
	res := mustManifest(t, GoMod{}, "go.mod", body)
	if len(res.Declared) != 1 {
		t.Fatalf("got %d declarations, want 1", len(res.Declared))
	}
	d := res.Declared[0]
	if d.Name != "github.com/fork/pkg" {
		t.Errorf("name = %q, want github.com/fork/pkg (the replacement is what is built)", d.Name)
	}
	if d.Version != "v1.5.0" {
		t.Errorf("version = %q, want v1.5.0", d.Version)
	}
}

func TestGoModReplaceLocalPath(t *testing.T) {
	body := `module example.com/app

go 1.23

require example.com/local/pkg v1.0.0

replace example.com/local/pkg => ../local
`
	res := mustManifest(t, GoMod{}, "go.mod", body)
	d := res.Declared[0]
	if !d.Local {
		t.Error("a replacement pointing at a directory is local, not a registry dependency")
	}
	if d.PathDep != "../local" {
		t.Errorf("PathDep = %q, want ../local so the scanner can check containment", d.PathDep)
	}
}

// TestGoSumIsNotALockfile: go.sum legitimately holds hashes for module versions
// the build no longer uses, so reading it would invent dependencies.
func TestGoSumIsNotALockfile(t *testing.T) {
	if got := (GoMod{}).LockfileNames(); len(got) != 0 {
		t.Errorf("GoMod.LockfileNames() = %v, want empty: go.mod is both declaration and resolution", got)
	}
	if _, err := (GoMod{}).ParseLockfile("go.sum", []byte("github.com/a/b v1.0.0 h1:xyz=\n")); err == nil {
		t.Fatal("go.sum must be refused so that wiring it in fails loudly instead of producing a phantom graph")
	}
}

// ── cargo ────────────────────────────────────────────────────────────────────

func TestCargoManifestAllForms(t *testing.T) {
	body := `[package]
name = "app"
version = "0.1.0"
license = "MIT OR Apache-2.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.35", features = ["full"], optional = true }

[dependencies.clap]
version = "4.4"
features = ["derive"]

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"

[target.'cfg(windows)'.dependencies]
winapi = "0.3"

[workspace.dependencies]
anyhow = "1.0"
`
	res := mustManifest(t, Cargo{}, "Cargo.toml", body)

	if res.OwnLicence != "MIT OR Apache-2.0" {
		t.Errorf("OwnLicence = %q, want MIT OR Apache-2.0", res.OwnLicence)
	}

	// `name` and `version` under [package] must never become dependencies.
	for _, d := range res.Declared {
		if d.Name == "name" || d.Name == "version" || d.Name == "app" {
			t.Errorf("[package] field %q leaked into the dependency list", d.Name)
		}
	}

	// serde: a bare string, and a bare Cargo string is a caret requirement.
	serde := find(t, res, "serde")
	if serde.Version != "1.0" || !serde.IsRange {
		t.Errorf("serde = (%q, IsRange=%v); a Cargo.toml version is always a requirement", serde.Version, serde.IsRange)
	}

	// tokio: an inline table, with its optional flag.
	tokio := find(t, res, "tokio")
	if tokio.Version != "1.35" || !tokio.Optional {
		t.Errorf("tokio = (%q, Optional=%v), want (1.35, true)", tokio.Version, tokio.Optional)
	}

	// clap: split across two keys ([dependencies.clap] version + features) and
	// therefore the case that would produce a duplicate without merging.
	if got := find(t, res, "clap").Version; got != "4.4" {
		t.Errorf("clap version = %q, want 4.4", got)
	}
	n := 0
	for _, d := range res.Declared {
		if d.Name == "clap" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("clap appears %d times, want 1", n)
	}

	if !find(t, res, "criterion").Dev {
		t.Error("criterion is a dev-dependency")
	}
	if find(t, res, "cc").Dev {
		t.Error("a build-dependency is not a dev-dependency")
	}
	// A platform-specific dependency still applies: an obligation does not stop
	// applying because the build was run on Linux.
	if got := find(t, res, "winapi").Version; got != "0.3" {
		t.Errorf("winapi (target-specific) version = %q, want 0.3", got)
	}
	if got := find(t, res, "anyhow").Version; got != "1.0" {
		t.Errorf("anyhow (workspace) version = %q, want 1.0", got)
	}
}

func TestCargoPathDependencyIsLocal(t *testing.T) {
	body := `[package]
name = "app"
version = "0.1.0"

[dependencies]
sibling = { path = "../sibling" }
serde = "1.0"
`
	res := mustManifest(t, Cargo{}, "Cargo.toml", body)
	sib := find(t, res, "sibling")
	if !sib.Local {
		t.Error("a path dependency is local, not a registry dependency")
	}
	if sib.PathDep != "../sibling" {
		t.Errorf("PathDep = %q, want ../sibling", sib.PathDep)
	}
	if find(t, res, "serde").Local {
		t.Error("a registry dependency must not be marked local")
	}
}

func TestCargoLockDirectSet(t *testing.T) {
	body := `version = 3

[[package]]
name = "myapp"
version = "0.1.0"
dependencies = ["serde 1.0.0", "libc"]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "libc"
version = "0.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "transitive"
version = "9.9.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
`
	res := mustLockfile(t, Cargo{}, "Cargo.lock", body)
	if len(res.Declared) != 4 {
		t.Fatalf("got %d declarations, want 4", len(res.Declared))
	}

	// The root crate has no `source`, so it is the project, not a dependency.
	if !find(t, res, "myapp").Local {
		t.Error("a [[package]] with no source is the project itself")
	}
	// Direct-ness comes from the root's own dependency list, which is exact.
	if !find(t, res, "serde").Direct {
		t.Error("serde is named by the root, so it is direct")
	}
	if !find(t, res, "libc").Direct {
		t.Error("libc is named by the root without a version, so it is direct")
	}
	if find(t, res, "transitive").Direct {
		t.Error("transitive is named by nobody's root, so it is not direct")
	}
	// A lockfile records resolutions, never ranges.
	if find(t, res, "serde").IsRange {
		t.Error("a lockfile version is a resolution, so IsRange must be false")
	}

	// Sorted by name, so the graph does not depend on file order.
	want := []string{"libc", "myapp", "serde", "transitive"}
	for i, d := range res.Declared {
		if d.Name != want[i] {
			t.Errorf("Declared[%d].Name = %q, want %q", i, d.Name, want[i])
		}
	}
}

func TestCargoLockVirtualWorkspace(t *testing.T) {
	// No root package: a virtual workspace manifest. Direct-ness cannot be
	// derived, so everything is provisionally direct and the manifest merge
	// refines it — better than marking a whole workspace transitive and hiding
	// it from review.
	body := `[[package]]
name = "member-a"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`
	res := mustLockfile(t, Cargo{}, "Cargo.lock", body)
	if !find(t, res, "serde").Direct {
		t.Error("with no root package, nothing may be hidden as transitive")
	}
}

func TestCargoLockWithoutPackagesIsRefused(t *testing.T) {
	if _, err := (Cargo{}).ParseLockfile("Cargo.lock", []byte("version = 3\n")); err == nil {
		t.Fatal("a Cargo.lock with no [[package]] entries must be refused, not read as an empty graph")
	}
}

// ── TOML subset ──────────────────────────────────────────────────────────────

func TestTOMLSubset(t *testing.T) {
	body := `# a comment
top = "value"
dotted.key = "dotted"

[table]
quoted = "he said \"hi\""
literal = 'raw \n not escaped'
number = 42
float = 1.5
flag = true
list = [
  "a",
  "b",
]
inline = { k = "v", n = 1 }
`
	doc, err := parseTOML([]byte(body), 1<<20)
	if err != nil {
		t.Fatalf("parseTOML: %v", err)
	}
	for _, tc := range []struct{ path, want string }{
		{"top", "value"},
		{"dotted.key", "dotted"},
		{"table.quoted", `he said "hi"`},
		{"table.literal", `raw \n not escaped`},
		{"table.number", "42"},
		{"table.flag", "true"},
		{"table.inline", ""},
	} {
		if got := doc.String(tc.path); got != tc.want {
			t.Errorf("String(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
	if got := doc.Strings("table.list"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("Strings(table.list) = %v, want [a b]", got)
	}
	if got := doc.Line("top"); got != 2 {
		t.Errorf("Line(top) = %d, want 2", got)
	}
}

func TestTOMLRefusesUnsupportedValue(t *testing.T) {
	// The subset has no date type. Refusing beats half-parsing: a lockfile that
	// half-parses produces a graph that is quietly wrong.
	if _, err := parseTOML([]byte("when = 1979-05-27T07:32:00Z\n"), 1<<20); err == nil {
		t.Fatal("expected a refusal for a value outside the TOML subset")
	}
}

// ── whole-package invariants ─────────────────────────────────────────────────

func TestAllParsersAreRegisteredAndNamed(t *testing.T) {
	all := All()
	if len(all) != 4 {
		t.Fatalf("All() returned %d parsers, want 4", len(all))
	}
	seen := map[string]bool{}
	for _, p := range all {
		if p.Ecosystem() == "" {
			t.Error("a parser has an empty ecosystem name")
		}
		if seen[p.Ecosystem()] {
			t.Errorf("ecosystem %q is registered twice", p.Ecosystem())
		}
		seen[p.Ecosystem()] = true
		if len(p.ManifestNames()) == 0 {
			t.Errorf("ecosystem %q declares no manifest name", p.Ecosystem())
		}
		if got, ok := ByEcosystem(p.Ecosystem()); !ok || got.Ecosystem() != p.Ecosystem() {
			t.Errorf("ByEcosystem(%q) did not round-trip", p.Ecosystem())
		}
	}
	for _, want := range []string{"npm", "pypi", "go", "cargo"} {
		if !seen[want] {
			t.Errorf("ecosystem %q is not registered", want)
		}
	}
}

// TestParsersAreDeterministic guards INV-6 at the parser boundary. Two runs
// over identical bytes must produce identical declarations, including order.
func TestParsersAreDeterministic(t *testing.T) {
	type run struct {
		p    Parser
		rel  string
		body string
		lock bool
	}
	runs := []run{
		{NPM{}, "package.json", `{"name":"a","license":"MIT","dependencies":{"z":"1.0.0","a":"2.0.0","m":"3.0.0"}}`, false},
		{GoMod{}, "go.mod", "module x\n\nrequire (\n\tb v1.0.0\n\ta v1.0.0\n\tc v1.0.0 // indirect\n)\n", false},
		{Cargo{}, "Cargo.toml", "[package]\nname = \"x\"\nlicense = \"MIT\"\n\n[dependencies]\nz = \"1.0\"\na = \"2.0\"\nm = \"3.0\"\n", false},
		{PyPI{}, "requirements.txt", "z==1.0\na==2.0\nm==3.0\n", false},
		{NPM{}, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"node_modules/z":{"version":"1.0.0"},"node_modules/a":{"version":"2.0.0"}}}`, true},
		{Cargo{}, "Cargo.lock", "[[package]]\nname = \"z\"\nversion = \"1.0.0\"\nsource = \"registry+x\"\n\n[[package]]\nname = \"a\"\nversion = \"2.0.0\"\nsource = \"registry+x\"\n", true},
	}

	for _, r := range runs {
		var first Result
		for i := 0; i < 5; i++ {
			var got Result
			var err error
			if r.lock {
				got, err = r.p.ParseLockfile(r.rel, []byte(r.body))
			} else {
				got, err = r.p.ParseManifest(r.rel, []byte(r.body))
			}
			if err != nil {
				t.Fatalf("%s %s: %v", r.p.Ecosystem(), r.rel, err)
			}
			if i == 0 {
				first = got
				continue
			}
			if resultSnapshot(first) != resultSnapshot(got) {
				t.Errorf("%s %s is not deterministic:\n first = %s\n  run%d = %s",
					r.p.Ecosystem(), r.rel, resultSnapshot(first), i, resultSnapshot(got))
				break
			}
		}
		// The same guarantee for the declarations' order specifically.
		var names []string
		for _, d := range first.Declared {
			names = append(names, d.Name)
		}
		sorted := append([]string(nil), names...)
		sortStrings(sorted)
		if !reflect.DeepEqual(names, sorted) {
			t.Errorf("%s %s: declarations are not sorted: %v", r.p.Ecosystem(), r.rel, names)
		}
	}
}

// TestEveryDeclarationHasAnIdentity makes sure no parser emits a declaration
// that cannot be named in a finding. An entry with no name is invisible to the
// user and unaccountable in the output.
func TestEveryDeclarationHasAnIdentity(t *testing.T) {
	res := mustManifest(t, Cargo{}, "Cargo.toml", "[dependencies]\nserde = \"1.0\"\n")
	for _, d := range res.Declared {
		if d.Name == "" {
			t.Error("a declaration has an empty name")
		}
		if d.Ecosystem == "" {
			t.Error("a declaration has an empty ecosystem")
		}
		if !strings.HasPrefix(d.ID(), "cargo:") {
			t.Errorf("ID() = %q, want a cargo: prefix", d.ID())
		}
	}
}
