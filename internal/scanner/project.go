package scanner

import (
	"strings"

	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/parsers"
	"github.com/clearance-dev/clearance/internal/safefs"
)

// project is one directory that declares dependencies for one ecosystem.
//
// The key is (directory, ecosystem), not directory alone. A repository may hold
// package.json and go.mod side by side, and each needs its own manifest and
// lockfile resolution; treating them as a single project would silently apply
// one ecosystem's versions to the other.
type project struct {
	Dir      string // project-relative, "." at the root
	Parser   parsers.Parser
	Manifest string // project-relative path, "" when none was found
	Lockfile string // project-relative path, "" when none

	// UnsupportedLockfiles are lockfiles the parser recognises and refuses to
	// parse (pnpm-lock.yaml, yarn.lock). Their presence is REPORTED rather than
	// ignored: falling back to the manifest without saying so would make a
	// weaker scan look like a normal one.
	UnsupportedLockfiles []string
}

// dependencyDirMarkers are path fragments that mean "this is inside a
// dependency, not a project".
//
// This check is load-bearing because the walk deliberately does NOT skip
// node_modules — vendored licences live there and they are exactly what this
// tool must read. Without this exclusion, every one of the tens of thousands of
// package.json files inside node_modules would be treated as a project root,
// and the graph would fill with nonsense.
var dependencyDirMarkers = []string{
	"node_modules/",
	"vendor/",
	"third_party/",
	"bower_components/",
	"site-packages/",
	"dist-packages/",
	"jspm_packages/",
}

// insideDependencyDir reports whether a project-relative path lies inside a
// dependency directory.
func insideDependencyDir(rel string) bool {
	p := "/" + strings.ReplaceAll(rel, "\\", "/") + "/"
	for _, m := range dependencyDirMarkers {
		if strings.Contains(p, "/"+m) {
			return true
		}
	}
	return false
}

// findProjects returns the project roots in the tree, in a deterministic order.
func findProjects(entries []safefs.WalkEntry) []project {
	byKey := map[string]*project{}
	var order []string

	for _, e := range entries {
		if e.IsDir || insideDependencyDir(e.Rel) {
			continue
		}
		base := e.Base()
		dir := e.Dir()

		for _, p := range parsers.All() {
			if nameInList(p.ManifestNames(), e, base) {
				pr := ensure(&byKey, &order, dir, p)
				if pr.Manifest == "" || betterName(p.ManifestNames(), pr.Manifest, e.Rel) {
					pr.Manifest = e.Rel
				}
			}
			if nameInList(p.LockfileNames(), e, base) {
				pr := ensure(&byKey, &order, dir, p)
				if pr.Lockfile == "" || betterName(p.LockfileNames(), pr.Lockfile, e.Rel) {
					pr.Lockfile = e.Rel
				}
			}
			if d, ok := p.(unsupportedLockfileDeclarer); ok {
				if nameInList(d.UnsupportedLockfiles(), e, base) {
					pr := ensure(&byKey, &order, dir, p)
					pr.UnsupportedLockfiles = append(pr.UnsupportedLockfiles, e.Rel)
				}
			}
		}
	}

	out := make([]project, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	// Sorted by directory then ecosystem, so a scan of the same tree always
	// reports projects in the same order (INV-6).
	sortProjects(out)
	return out
}

// unsupportedLockfileDeclarer is implemented by a parser that recognises a
// lockfile format it deliberately does not parse.
type unsupportedLockfileDeclarer interface {
	UnsupportedLockfiles() []string
}

func ensure(byKey *map[string]*project, order *[]string, dir string, p parsers.Parser) *project {
	key := dir + "\x00" + p.Ecosystem()
	if pr, ok := (*byKey)[key]; ok {
		return pr
	}
	pr := &project{Dir: dir, Parser: p}
	(*byKey)[key] = pr
	*order = append(*order, key)
	return pr
}

// nameInList reports whether an entry matches one of a parser's declared names.
//
// A name may be a bare base name ("package.json", matched at any depth, which
// is what makes a monorepo work) or a relative path ("vendor/modules.txt",
// matched exactly or as a suffix).
func nameInList(names []string, e safefs.WalkEntry, base string) bool {
	for _, n := range names {
		if strings.Contains(n, "/") {
			if e.Rel == n || strings.HasSuffix(e.Rel, "/"+n) {
				return true
			}
			continue
		}
		if base == n {
			return true
		}
	}
	return false
}

// betterName reports whether candidate should replace current, judging by the
// parser's declared preference order. package-lock.json is preferred over
// npm-shrinkwrap.json because that is the order the parser lists them in.
func betterName(names []string, current, candidate string) bool {
	rank := func(p string) int {
		b := p
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			b = p[i+1:]
		}
		for i, n := range names {
			if n == b {
				return i
			}
		}
		return len(names)
	}
	return rank(candidate) < rank(current)
}

func sortProjects(ps []project) {
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0; j-- {
			a, b := ps[j-1], ps[j]
			if a.Dir < b.Dir || (a.Dir == b.Dir && a.Parser.Ecosystem() <= b.Parser.Ecosystem()) {
				break
			}
			ps[j-1], ps[j] = ps[j], ps[j-1]
		}
	}
}

// applyIgnore drops entries matched by a config ignore rule.
//
// When a rule removes more than half the tree it is reported with E-SCAN-020.
// That threshold exists because the most likely way to get a wrong SHIP is to
// ignore the dependencies, and a rule that excludes most of a project is far
// more likely to be a mistake than an intention.
func applyIgnore(entries []safefs.WalkEntry, in *config.Intent, g *graph.Graph) []safefs.WalkEntry {
	if in == nil {
		return entries
	}
	removed := map[string]int{}
	kept := make([]safefs.WalkEntry, 0, len(entries))
	files := 0

	for _, e := range entries {
		if e.IsDir {
			kept = append(kept, e)
			continue
		}
		files++
		if rule, matched := in.IgnoreMatches(e.Rel); matched {
			removed[rule.Path]++
			continue
		}
		kept = append(kept, e)
	}

	for _, pattern := range sortedKeys(removed) {
		n := removed[pattern]
		if files > 0 && n*2 > files {
			g.Warnings = append(g.Warnings, graph.Warning{
				Code:    "E-SCAN-020",
				Message: "Ignore rule '" + pattern + "' excluded " + percent(n, files) + " of files. This may be hiding dependencies.",
			})
		}
	}
	return kept
}

func percent(n, total int) string {
	if total == 0 {
		return "0%"
	}
	return itoaInt(int64(n*100/total)) + "%"
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func itoaInt(n int64) string {
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
