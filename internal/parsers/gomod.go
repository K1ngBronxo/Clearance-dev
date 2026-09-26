package parsers

import (
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// GoMod reads go.mod.
//
// GO HAS NO SEPARATE LOCKFILE, AND go.sum IS NOT ONE.
//
// Since Go 1.17 the main module's go.mod lists every module in the pruned
// module graph at its selected exact version, with `// indirect` marking the
// ones no package in the main module imports directly. It is therefore both the
// declaration and the resolution, and LockfileNames is empty because there is
// no second file to prefer.
//
// go.sum is deliberately not read. It is a checksum file, and it legitimately
// holds hashes for module versions the build no longer uses — go.sum has to be
// able to verify the go.mod files of older versions while the module graph is
// being resolved. Reading it would invent dependencies that are not in the
// build, and a finding about code the user does not ship is a false positive
// with exactly the same weight as a false negative. ParseLockfile exists only
// to refuse, so that anyone who later wires go.sum in gets a loud error instead
// of a phantom graph.
//
// go.mod records no licences, and the module cache lives outside the project
// root, which INV-4 forbids reading. A Go dependency's licence therefore
// resolves from a vendored `vendor/<module>/LICENSE` when one is present, and
// is otherwise UNDETERMINED with a note. `go mod vendor` is the fix, and the
// note says so.
type GoMod struct{}

func (GoMod) Ecosystem() string { return "go" }

func (GoMod) ManifestNames() []string { return []string{"go.mod"} }

// LockfileNames is empty on purpose. See the type comment: go.mod is both the
// declaration and the resolution, and go.sum is a checksum file rather than a
// lockfile.
func (GoMod) LockfileNames() []string { return nil }

// goReplace is the target of a `replace` directive.
type goReplace struct {
	path    string // the replacement module path, or a local directory
	version string
	local   bool
}

func (GoMod) ParseManifest(rel string, data []byte) (Result, error) {
	own := ""
	var out []Declared
	seen := map[string]bool{}

	// `replace` is read, not ignored. A replaced module means the code that
	// actually gets built is the replacement, so the replacement's licence is
	// the one that governs. Ignoring the directive would produce a graph that
	// names a module nobody is shipping — and a verdict about it.
	repls := map[string]goReplace{}
	replsExact := map[string]goReplace{}

	lines := strings.Split(string(data), "\n")

	// PASS 1 — collect `replace` directives.
	//
	// This is a separate pass because a `require` line almost always appears
	// ABOVE the `replace` line that governs it. An earlier draft collected
	// replacements in the same pass as the requires, so the map was still empty
	// when each declaration was built and no replacement was ever applied. It
	// failed silently and the graph named the original module — a wrong answer
	// with no error attached, which is the worst kind. Two passes, not one.
	inBlock := ""
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		switch {
		case line == "require (" || line == "require(":
			inBlock = "require"
		case line == "replace (" || line == "replace(":
			inBlock = "replace"
		case inBlock != "" && line == ")":
			inBlock = ""
		case inBlock == "replace":
			if key, keyVer, repl, ok := parseGoReplace(line); ok {
				storeReplace(repls, replsExact, key, keyVer, repl)
			}
		case strings.HasPrefix(line, "replace "):
			if key, keyVer, repl, ok := parseGoReplace(strings.TrimPrefix(line, "replace ")); ok {
				storeReplace(repls, replsExact, key, keyVer, repl)
			}
		}
	}

	// PASS 2 — requires, and the project's own licence comment.
	inBlock = ""
	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		// A whole-line comment. This is where the project's licence lives, and
		// it is the *project's* licence: assigning it to every dependency would
		// label an AGPL dependency "MIT" in a module that declares MIT.
		if strings.HasPrefix(line, "//") {
			if v := goCommentValue(line, "license"); v != "" {
				own = v
			} else if v := goCommentValue(line, "licence"); v != "" {
				own = v
			}
			continue
		}

		switch {
		case line == "require (" || line == "require(":
			inBlock = "require"
		case line == "replace (" || line == "replace(":
			inBlock = "replace"
		case inBlock != "" && line == ")":
			inBlock = ""

		case inBlock == "require":
			// The raw line reaches parseGoRequire rather than a
			// comment-stripped one, because `// indirect` is the marker that
			// decides whether the dependency is direct. Stripping comments
			// first and then looking for the marker would never find it.
			name, ver, indirect := parseGoRequire(line)
			if name != "" && !seen[name] {
				seen[name] = true
				out = append(out, goDeclared(rel, name, ver, indirect, lineNo, repls, replsExact))
			}

		case strings.HasPrefix(line, "require "):
			name, ver, indirect := parseGoRequire(strings.TrimPrefix(line, "require "))
			if name != "" && !seen[name] {
				seen[name] = true
				out = append(out, goDeclared(rel, name, ver, indirect, lineNo, repls, replsExact))
			}
		}
		// `exclude` and `retract` are deliberately ignored: an exclude narrows
		// the graph rather than adding to it, and a retracted version cannot be
		// selected, so neither can introduce a dependency that is not already
		// named by a require directive.
	}

	sortDeclared(out)
	return Result{Declared: out, OwnLicence: own}, nil
}

// ParseLockfile refuses. See the type comment: go.sum is a checksum file, and
// reading it would invent module versions that are no longer in the build.
func (GoMod) ParseLockfile(rel string, _ []byte) (Result, error) {
	return Result{}, cerr.New(cerr.EParse001, rel,
		"go.sum is a checksum file, not a resolution file; go.mod is authoritative")
}

func storeReplace(byPath, byExact map[string]goReplace, key, keyVer string, repl goReplace) {
	if keyVer != "" {
		byExact[key+"@"+keyVer] = repl
		return
	}
	byPath[key] = repl
}

func goDeclared(rel, name, ver string, indirect bool, line int, repls, replsExact map[string]goReplace) Declared {
	d := Declared{
		Ecosystem:  "go",
		Name:       name,
		Version:    ver,
		IsRange:    false, // a go.mod require always names an exact version
		Direct:     !indirect,
		SourcePath: rel,
		Line:       line,
	}
	repl, ok := replsExact[name+"@"+ver]
	if !ok {
		repl, ok = repls[name]
	}
	if !ok {
		return d
	}
	// The replacement is what gets built, so it becomes the dependency's
	// identity. Its version is preferred when it has one; a local replacement
	// has none, so the original version is left in place as the closest thing
	// to a version that exists.
	if repl.local {
		d.Local = true
		d.PathDep = repl.path
		return d
	}
	d.Name = repl.path
	if repl.version != "" {
		d.Version = repl.version
	}
	return d
}

// parseGoRequire reads `module/path v1.2.3` with an optional `// indirect`.
func parseGoRequire(s string) (name, version string, indirect bool) {
	indirect = strings.Contains(s, "// indirect")
	if i := strings.Index(s, "//"); i >= 0 {
		s = s[:i]
	}
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return "", "", indirect
	}
	return fields[0], fields[1], indirect
}

// parseGoReplace reads `old [version] => new [version]` or `old => ./local`.
// It returns the key the replacement applies to, the version the key pins (if
// any), and the replacement.
func parseGoReplace(s string) (key, keyVersion string, repl goReplace, ok bool) {
	i := strings.Index(s, "=>")
	if i < 0 {
		return "", "", goReplace{}, false
	}
	left := strings.Fields(strings.TrimSpace(s[:i]))
	if len(left) == 0 {
		return "", "", goReplace{}, false
	}
	right := strings.Fields(stripGoTrailingComment(strings.TrimSpace(s[i+2:])))
	if len(right) == 0 {
		return "", "", goReplace{}, false
	}

	key = left[0]
	if len(left) > 1 {
		keyVersion = left[1]
	}

	repl.path = right[0]
	if isLocalPath(right[0]) {
		repl.local = true
		return key, keyVersion, repl, true
	}
	if len(right) > 1 {
		repl.version = right[1]
	}
	return key, keyVersion, repl, true
}

// isLocalPath reports whether a replacement target is a directory rather than a
// module path. A module path always begins with a domain component; a directory
// begins with a dot, a separator, or a drive letter.
func isLocalPath(p string) bool {
	switch {
	case p == "":
		return false
	case strings.HasPrefix(p, "./"), strings.HasPrefix(p, "../"):
		return true
	case strings.HasPrefix(p, ".\\"), strings.HasPrefix(p, "..\\"):
		return true
	case strings.HasPrefix(p, "/"), strings.HasPrefix(p, "\\"):
		return true
	case len(p) >= 2 && p[1] == ':': // C:\dir
		return true
	}
	return false
}

// stripGoTrailingComment removes a `//` comment from a directive line. It is
// used only where the comment carries no meaning; require and replace lines are
// passed raw so that `// indirect` survives.
func stripGoTrailingComment(s string) string {
	if i := strings.Index(s, "//"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// goCommentValue extracts `// license: MIT` style values.
func goCommentValue(line, key string) string {
	l := strings.ToLower(line)
	idx := strings.Index(l, key+":")
	if idx < 0 {
		idx = strings.Index(l, key+" =")
	}
	if idx < 0 {
		return ""
	}
	rest := line[idx:]
	if i := strings.IndexAny(rest, ":="); i >= 0 {
		return strings.TrimSpace(rest[i+1:])
	}
	return ""
}
