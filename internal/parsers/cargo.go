package parsers

import (
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// Cargo reads Cargo.toml and Cargo.lock.
//
// NEITHER FILE RECORDS A DEPENDENCY'S LICENCE.
//
// Cargo.toml declares version requirements; Cargo.lock resolves them to exact
// versions. A crate's licence lives in crates.io metadata, and this scanner has
// no network (INV-3), so a Cargo dependency's licence resolves from a vendored
// copy of the crate — `vendor/<name>/Cargo.toml` or its `LICENSE-*` file — and
// is otherwise UNDETERMINED with a note telling the user to run `cargo vendor`.
// That is the honest answer, not a failure.
//
// The one licence these files DO carry is the project's own, in
// `[package].license`. It is returned as Result.OwnLicence and is never stamped
// onto a dependency — see the comment on Result.OwnLicence for why that
// distinction is load-bearing rather than pedantic.
type Cargo struct{}

func (Cargo) Ecosystem() string { return "cargo" }

func (Cargo) ManifestNames() []string { return []string{"Cargo.toml"} }

func (Cargo) LockfileNames() []string { return []string{"Cargo.lock"} }

// parseTOML takes a byte limit. Both limits sit below safefs' MaxFileSize, so
// they are a second line of defence rather than the only one: a file this large
// has already been refused by the reader.
const (
	cargoManifestLimit = 4 << 20
	cargoLockLimit     = 8 << 20
)

// isDependencyTable reports whether a TOML path segment names a table that
// declares dependencies. A switch rather than a map lookup so that the set is
// visible in one place and cannot be mutated at runtime.
func isDependencyTable(name string) bool {
	switch name {
	case "dependencies", "dev-dependencies", "build-dependencies":
		return true
	}
	return false
}

// cargoEntry accumulates one crate's declaration across however many TOML keys
// describe it, because Cargo splits a dependency over several keys:
//
//	serde = "1.0"                                    → one key
//	serde = { version = "1.0", optional = true }      → one key, an inline table
//	[dependencies.serde]                              → two keys, version+features
//	version = "1.0"
//	features = ["derive"]
//
// Merging by crate name is what makes the second and third forms produce one
// dependency instead of a duplicate.
type cargoEntry struct {
	version  string
	isRange  bool
	optional bool
	pathDep  string
	dev      bool
	line     int
}

// ParseManifest reads Cargo.toml.
//
// Target-specific tables are read as ordinary dependencies rather than being
// skipped. `[target.'cfg(windows)'.dependencies.winapi]` is a dependency of the
// project on some platforms; omitting it would mean a Windows-only dependency
// escapes review, and a licence obligation does not stop applying because the
// build was run on Linux.
func (Cargo) ParseManifest(rel string, data []byte) (Result, error) {
	doc, err := parseTOML(data, cargoManifestLimit)
	if err != nil {
		return Result{}, cerr.Wrap(cerr.EParse002, err, rel, describeParseError(err))
	}

	// `license` is the canonical key. `licence` is accepted because it appears
	// in the wild and Cargo does not reject it. `license-file` is deliberately
	// NOT read: it names a file rather than naming a licence, so it is a
	// pointer, not an answer — the scanner reads the file it points at.
	own := doc.String("package.license")
	if own == "" {
		own = doc.String("package.licence")
	}

	found := map[string]cargoEntry{}
	var order []string

	for _, key := range doc.AllKeys() {
		// The crate name is the segment after the LAST dependency-table segment
		// in the path. Taking the last rather than the first is what makes
		// `target.'cfg(target.arch = "x86_64")'.dependencies.winapi` work: the
		// cfg expression itself may contain dots, and splitting on them yields
		// more segments than a reader expects.
		parts := strings.Split(key, ".")
		tableIdx := -1
		for i, p := range parts {
			if isDependencyTable(p) {
				tableIdx = i
			}
		}
		if tableIdx < 0 || tableIdx+1 >= len(parts) {
			continue
		}
		name := unquoteTomlKey(parts[tableIdx+1])
		if name == "" {
			continue
		}
		field := ""
		if tableIdx+2 < len(parts) {
			field = unquoteTomlKey(parts[tableIdx+2])
		}

		e := found[name]
		e.dev = parts[tableIdx] == "dev-dependencies"
		if e.line == 0 {
			e.line = doc.Line(key)
		}

		v, _ := doc.Get(key)
		switch field {
		case "":
			// Either `serde = "1.0"` or `serde = { … }`.
			applyCargoValue(&e, v)
		case "version":
			applyCargoValue(&e, v)
		case "optional":
			if b, ok := v.(bool); ok {
				e.optional = b
			}
		case "path":
			if s, ok := v.(string); ok {
				e.pathDep = s
			}
		}

		if _, seen := found[name]; !seen {
			order = append(order, name)
		}
		found[name] = e
	}

	// Sorted, not file order. Two Cargo.toml files that declare the same
	// dependencies in a different order must produce byte-identical graphs.
	sortStrings(order)

	out := make([]Declared, 0, len(order))
	for _, name := range order {
		e := found[name]
		out = append(out, Declared{
			Ecosystem: "cargo",
			Name:      name,
			Version:   e.version,
			IsRange:   e.isRange,
			// Every dependency named in a manifest is direct by definition; the
			// lockfile is what proves transitivity, and the merge prefers it.
			Direct:     true,
			Local:      e.pathDep != "",
			PathDep:    e.pathDep,
			SourcePath: rel,
			Line:       e.line,
			Dev:        e.dev,
			Optional:   e.optional,
		})
	}
	return Result{Declared: out, OwnLicence: own}, nil
}

// applyCargoValue reads a version requirement written either as a bare string
// or as an inline table.
//
// EVERY version in a Cargo.toml is a requirement, never a resolution, so
// IsRange is always true here — including for a bare "1.0". Cargo's default
// requirement semantics are caret-compatible, so `serde = "1.0"` means
// ">=1.0.0, <2.0.0" and not "exactly 1.0". Reporting it as an exact version
// would make the tool claim knowledge of a resolution it does not have, which
// is the one error this product cannot make.
func applyCargoValue(e *cargoEntry, v any) {
	switch t := v.(type) {
	case string:
		e.version = cleanVersion(t)
		e.isRange = true
	case map[string]any:
		if s, ok := t["version"].(string); ok {
			e.version = cleanVersion(s)
			e.isRange = true
		}
		if s, ok := t["path"].(string); ok {
			e.pathDep = s
		}
		if b, ok := t["optional"].(bool); ok {
			e.optional = b
		}
		// A git dependency carries `git` plus `tag`/`rev`/`branch` and often no
		// `version` at all. Those are not versions, so none is invented: the
		// entry keeps an empty Version and the scanner reports UNDETERMINED,
		// which is exactly what it is. Guessing "main" as a version would put a
		// fabricated string in the evidence for a finding.
	}
}

// cargoLocked is one resolved package from Cargo.lock. It is a package-level
// type rather than a local one so that the sort helper can take it: a named
// type and an identical anonymous struct type are assignable but not identical,
// so `[]locked` does not satisfy a `[]struct{…}` parameter.
type cargoLocked struct {
	name    string
	version string
	local   bool
	line    int
}

// ParseLockfile reads Cargo.lock.
//
// It also computes which packages are direct, from the lockfile alone: every
// `[[package]]` with no `source` is a local crate, and the packages it lists in
// its `dependencies` array are the direct ones. That is exact, and it does not
// depend on the manifest being present or readable.
func (Cargo) ParseLockfile(rel string, data []byte) (Result, error) {
	doc, err := parseTOML(data, cargoLockLimit)
	if err != nil {
		return Result{}, cerr.Wrap(cerr.EParse001, err, rel, describeParseError(err))
	}

	var pkgs []cargoLocked
	direct := map[string]bool{}

	for _, prefix := range doc.ArrayPrefixes() {
		if !strings.HasPrefix(prefix, "package.") {
			continue
		}
		name := doc.String(prefix + ".name")
		if name == "" {
			continue
		}
		source := doc.String(prefix + ".source")
		pkgs = append(pkgs, cargoLocked{
			name:    name,
			version: doc.String(prefix + ".version"),
			local:   source == "",
			line:    doc.Line(prefix + ".name"),
		})
		if source != "" {
			continue
		}
		// A package with no `source` is a local crate — the root package, or a
		// workspace member. Its `dependencies` array names what it depends on,
		// and those are direct for the project as a whole.
		//
		// Local crates are NOT counted separately as "roots". An earlier draft
		// did that, which meant a virtual workspace (where every member is
		// source-less but there is no root) was treated as having a root with
		// an empty dependency list, so every real dependency was reported as
		// transitive. The union of the local crates' lists is exact for both
		// shapes and needs no such distinction.
		for _, dep := range doc.Strings(prefix + ".dependencies") {
			// Cargo writes "name" when the name is unambiguous and
			// "name version" when two versions of it are in the graph. A crate
			// name never contains a space, so the last space is the separator.
			if i := strings.LastIndexByte(dep, ' '); i > 0 {
				direct[dep[:i]] = true
			} else {
				direct[dep] = true
			}
		}
	}

	// A Cargo.lock with no [[package]] at all is not a Cargo.lock. Refusing is
	// correct: an empty result would look like a project with no dependencies,
	// which is the most dangerous possible answer this tool can give.
	if len(pkgs) == 0 {
		return Result{}, cerr.New(cerr.EParse001, rel, "no [[package]] entries")
	}

	// Sorted by name then version so that the graph does not depend on the
	// order Cargo happened to write the file in.
	sortCargoLocked(pkgs)

	// When no local crate declares any dependency there is nothing to derive
	// direct-ness from, so everything is provisionally direct and the manifest
	// merge refines it. The fallback leans towards over-reporting directness on
	// purpose: "direct" is what the fix suggestions surface, and when the
	// answer is unknown, surfacing too much is safer than hiding a dependency
	// behind a label that means "not your problem".
	known := len(direct) > 0

	out := make([]Declared, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, Declared{
			Ecosystem:  "cargo",
			Name:       p.name,
			Version:    p.version,
			IsRange:    false, // a lockfile records a resolution, never a range
			Direct:     !known || direct[p.name],
			Local:      p.local,
			SourcePath: rel,
			Line:       p.line,
		})
	}
	return Result{Declared: out}, nil
}

// sortCargoLocked orders packages by name, then version. Insertion sort, for
// the same reason as sortStrings: these lists are short, and a stable sort with
// no allocation keeps the hot path free of surprises.
func sortCargoLocked(pkgs []cargoLocked) {
	for i := 1; i < len(pkgs); i++ {
		for j := i; j > 0; j-- {
			a, b := pkgs[j-1], pkgs[j]
			if a.name < b.name || (a.name == b.name && a.version <= b.version) {
				break
			}
			pkgs[j-1], pkgs[j] = pkgs[j], pkgs[j-1]
		}
	}
}
