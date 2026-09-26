// Package parsers reads dependency declarations from ecosystem manifests and
// lockfiles.
//
// # THE RULE THAT SHAPES THIS PACKAGE
//
// A manifest declares *ranges*; a lockfile records *resolved versions*. A
// verdict about a range is a verdict about a project that may not exist, so
// when a lockfile exists for an ecosystem the manifest is ignored for version
// resolution — and a manifest-only dependency is marked MEDIUM confidence with
// a note telling the user to pin. That downgrade is deliberate: a range-based
// verdict is genuinely less certain, and saying so is the product working
// correctly.
//
// Manifests are still read for one purpose: to distinguish direct from
// transitive dependencies, which the fix suggestions use.
//
// Every parser is pure: bytes in, declarations out. It never touches the
// filesystem, never executes anything, and never fetches metadata from the
// network (there is no network in the scanner).
package parsers

import (
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/safejson"
)

// Declared is one dependency as found in a manifest or lockfile.
type Declared struct {
	Ecosystem string
	Name      string
	Version   string // a resolved version, or a range
	IsRange   bool   // true when Version is a range rather than a resolution
	Direct    bool
	// LicenceRaw is the licence this *dependency* declares for itself, in the
	// file that declares it. It is empty far more often than not: npm's
	// lockfile carries a `license` per package, while Cargo, poetry and go.sum
	// carry none. Empty means "not stated here", which is not the same as
	// "no licence" — the scanner resolves the real answer from vendored
	// licence files, and UNDETERMINED is a legitimate outcome.
	//
	// It is NEVER set from the project's own licence. See Result.OwnLicence.
	LicenceRaw string
	SourcePath string // project-relative
	Line       int    // best-effort line number for evidence
	Dev        bool
	Optional   bool
	// Local marks a declaration that is part of the project rather than a
	// dependency of it: a Cargo `[[package]]` with no `source`, a workspace
	// member. The scanner excludes these from the dependency graph because the
	// project's own tree is scanned directly — counting them would
	// double-count the project's licences and, worse, let the project block
	// itself.
	Local bool
	// PathDep is set when the declaration points at a directory rather than a
	// registry, e.g. Cargo's `dep = { path = "../other" }`. The parsers are
	// pure and cannot resolve it, so the scanner does: a path inside the root
	// is a workspace member whose licence the tree scan already covers, while
	// a path outside the root is a directory INV-4 forbids reading and must
	// become UNDETERMINED rather than being silently dropped. Those two cases
	// look identical at parse time, which is why the raw path travels.
	PathDep string
}

// ID builds the stable dependency identifier.
func (d Declared) ID() string {
	if d.Version == "" {
		return d.Ecosystem + ":" + d.Name
	}
	return d.Ecosystem + ":" + d.Name + "@" + d.Version
}

// Result is what a parser returns.
type Result struct {
	Declared []Declared
	// OwnLicence is the licence the manifest declares for the *project itself*
	// — npm's `license`, Cargo's `[package].license`, pyproject's
	// `[project].license`. It is the project's own fact and it travels here,
	// separately from the dependencies, because it is a different fact.
	//
	// An earlier draft stamped this onto every Declared in the file, so that a
	// project declaring MIT while depending on an AGPL package had every
	// dependency labelled MIT. That is a false SHIP produced by a parser
	// trying to be helpful, and it is the single most dangerous kind of bug
	// this tool can have: it fails in the direction of reassurance.
	OwnLicence string
	// Fallback is set when a lockfile could not be parsed and the manifest was
	// used instead. The caller turns it into a graph.Warning and an
	// Undetermined record, so the user is told the graph is weaker than it
	// looks. It is never a silent smaller graph.
	Fallback bool
	Warning  *cerr.Error
}

// Parser reads one ecosystem.
type Parser interface {
	Ecosystem() string
	// ManifestNames are the files that declare dependencies.
	ManifestNames() []string
	// LockfileNames are the files that resolve them, in preference order.
	LockfileNames() []string
	ParseManifest(rel string, data []byte) (Result, error)
	ParseLockfile(rel string, data []byte) (Result, error)
}

// All returns every parser, in a fixed order so that scanning is deterministic.
func All() []Parser {
	return []Parser{NPM{}, PyPI{}, GoMod{}, Cargo{}}
}

// ByEcosystem returns the parser for an ecosystem name.
func ByEcosystem(name string) (Parser, bool) {
	for _, p := range All() {
		if p.Ecosystem() == name {
			return p, true
		}
	}
	return nil, false
}

// ── shared helpers ───────────────────────────────────────────────────────────

// isRange reports whether a version string is a range rather than a resolution.
// Ranges carry the operators and wildcards that npm, PEP 508, Cargo and Go all
// use; a plain `1.2.3` does not.
func isRange(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if strings.ContainsAny(v, "^~*<>=|") {
		return true
	}
	if strings.EqualFold(v, "latest") || strings.EqualFold(v, "any") {
		return true
	}
	// A caret-style range in a PEP 508 specifier such as `>=1.0,<2.0` is caught
	// by the operator check above.
	return false
}

// cleanVersion strips the operators from a range so the version field is at
// least readable. It is used only for display; IsRange records the truth.
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	// A range like `>=1.0,<2.0` keeps only the first clause, which is the one a
	// reader recognises.
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	// Then strip whatever operator run is left. Trimming a fixed list of
	// prefixes one at a time leaves a leading operator behind on `==1.0`
	// (`=` is trimmed once, leaving `=1.0`), and a version field that reads
	// "=1.0" looks like a bug in the tool rather than a range in the file.
	v = strings.TrimLeft(v, "=<>!~^ ")
	return strings.TrimSpace(v)
}

// parseJSONObject is the shared JSON entry point, so that every JSON parser in
// this package goes through safejson and none of them reaches for encoding/json.
func parseJSONObject(data []byte) (safejson.Object, error) {
	return safejson.DecodeObject(data, safejson.Limits{MaxBytes: 8 << 20})
}

// describeParseError extracts the short phrase a parse error message expects.
// It unwraps a cerr so that a nested typed error does not produce a message
// inside a message, and falls back to the raw text for the hand-written syntax
// errors that safeyaml, safejson and the TOML reader return.
func describeParseError(err error) string {
	if e, ok := cerr.As(err); ok {
		return e.Message()
	}
	return err.Error()
}

// sortDeclared orders declarations by ecosystem, name, then version.
//
// Every parser sorts its own output rather than leaving it to the caller. The
// reason is INV-6: the same tree must produce the same verdict, and a parser
// that emits declarations in file order or map order makes the verdict depend
// on how a lockfile happened to be written.
func sortDeclared(d []Declared) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0; j-- {
			a, b := d[j-1], d[j]
			if a.Ecosystem < b.Ecosystem {
				break
			}
			if a.Ecosystem == b.Ecosystem && a.Name < b.Name {
				break
			}
			if a.Ecosystem == b.Ecosystem && a.Name == b.Name && a.Version <= b.Version {
				break
			}
			d[j-1], d[j] = d[j], d[j-1]
		}
	}
}

// jsonString reads a string member, tolerating a number or a bool written where
// a string was expected, because real lockfiles do that.
func jsonString(o safejson.Object, key string) string {
	v, ok := o.Get(key)
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case int64:
		return itoa(t)
	case float64:
		return trimFloat(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	}
	return ""
}

// jsonObjectMember returns an object member, or the zero Object.
func jsonObjectMember(o safejson.Object, key string) safejson.Object {
	v, ok := o.Get(key)
	if !ok {
		return safejson.Object{}
	}
	ob, _ := v.(safejson.Object)
	return ob
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func trimFloat(v float64) string {
	whole := int64(v)
	frac := int64((v - float64(whole)) * 1000)
	if frac == 0 {
		return itoa(whole)
	}
	return itoa(whole) + "." + itoa(frac)
}
