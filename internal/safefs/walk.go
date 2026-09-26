package safefs

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// WalkEntry is one file or directory discovered by the walk.
type WalkEntry struct {
	Rel       string      // project-relative, forward slashes, canonical
	Size      int64       // 0 for directories
	Mode      os.FileMode // the mode as reported by Lstat
	IsDir     bool
	IsSymlink bool // the entry itself was a symlink; Rel is the resolved path
	Depth     int
}

// Base returns the final path element.
func (e WalkEntry) Base() string {
	if i := strings.LastIndexByte(e.Rel, '/'); i >= 0 {
		return e.Rel[i+1:]
	}
	return e.Rel
}

// Dir returns the parent path, or "." at the root.
func (e WalkEntry) Dir() string {
	if i := strings.LastIndexByte(e.Rel, '/'); i >= 0 {
		return e.Rel[:i]
	}
	return "."
}

// Skip records something the walk refused to do, with the typed error that
// documents it. The scanner turns each Skip into a graph.Warning, so a user can
// always see exactly what was not read. An incomplete scan is trustworthy only
// when it is *visibly* incomplete.
type Skip struct {
	Err *cerr.Error
}

// Code returns the error code for the skip.
func (s Skip) Code() cerr.Code {
	if s.Err == nil {
		return ""
	}
	return s.Err.Code()
}

// Message returns the rendered user-facing message.
func (s Skip) Message() string {
	if s.Err == nil {
		return ""
	}
	return s.Err.Message()
}

// skipDirs are directories whose contents are never a licence source. Each
// entry has a reason; a directory that is skipped without a reason is a bug.
//
// NOTE what is NOT in this list: `node_modules`. Vendored licences live there
// and they are exactly what this tool must read. Only the *cache* subdirectory
// is skipped, and nested `node_modules` directories are depth-bounded below.
var skipDirs = map[string]string{
	".git":          "packed object store; huge and irrelevant",
	".hg":           "version control internals",
	".svn":          "version control internals",
	".bzr":          "version control internals",
	"__pycache__":   "compiled bytecode, not source",
	".pytest_cache": "test runner cache",
	".mypy_cache":   "type checker cache",
	".ruff_cache":   "linter cache",
	".tox":          "test environment",
	".eggs":         "build artefact",
	".next":         "generated output; the source carries the licence",
	".nuxt":         "generated output",
	".svelte-kit":   "generated output",
	".parcel-cache": "bundler cache",
	".turbo":        "build cache",
	".gradle":       "build cache",
	".terraform":    "provider binaries; enormous",
}

// skipSuffixDirs are skipped only when they appear as a *child of
// node_modules* or of a package cache, where they are unambiguously build
// output rather than a project's own source directory.
var skipNestedInModules = map[string]string{
	".cache": "package-manager cache",
}

// venvMarkers identify a Python virtualenv. A directory named `env` or `venv`
// is only skipped when one of these is present, because `env` is otherwise a
// perfectly ordinary source directory name — and skipping a source directory
// hides dependencies, which is the failure mode this tool exists to prevent.
var venvMarkers = []string{"pyvenv.cfg", "Scripts", "bin/activate", "lib/python3"}

// Walk traverses the root, applying every bound, and returns the complete
// inventory plus the list of skips.
//
// DETERMINISM (INV-6): entries are returned sorted by Rel bytewise. Directory
// reads are sorted by os.ReadDir, and the final slice is sorted again, so the
// order does not depend on the filesystem's enumeration order. Nothing
// downstream may re-sort or iterate a map.
func (r *Root) Walk() ([]WalkEntry, []Skip, error) {
	var (
		entries []WalkEntry
		skips   []Skip
	)

	// visited holds canonical directory paths already descended into, so that a
	// symlink cycle is detected by identity rather than by a depth guess.
	visited := map[string]bool{r.abs: true}

	type frame struct {
		abs   string
		rel   string
		depth int
	}

	// Depth-first, explicit stack — no recursion, so a 24-deep tree cannot blow
	// the goroutine stack and the depth bound is trivially enforced.
	stack := []frame{{abs: r.abs, rel: "", depth: 0}}

	for len(stack) > 0 {
		// Pop from the end.
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		r.dirsVisited.Add(1)
		if cur.depth > int(r.maxDepthSeen.Load()) {
			r.maxDepthSeen.Store(int64(cur.depth))
		}

		if cur.depth > r.limits.MaxDepth {
			skips = append(skips, Skip{Err: cerr.New(cerr.EScan008, displayRel(cur.rel), itoa(int64(r.limits.MaxDepth)))})
			continue
		}

		dirents, err := os.ReadDir(cur.abs)
		if err != nil {
			if os.IsPermission(err) {
				skips = append(skips, Skip{Err: cerr.Wrap(cerr.EScan007, err, displayRel(cur.rel))})
				continue
			}
			// A directory that vanished mid-walk is not an error worth stopping
			// for; record it and move on.
			skips = append(skips, Skip{Err: cerr.Wrap(cerr.EScan007, err, displayRel(cur.rel))})
			continue
		}

		for _, de := range dirents {
			name := de.Name()
			childAbs := filepath.Join(cur.abs, name)
			childRel := name
			if cur.rel != "" {
				childRel = cur.rel + "/" + name
			}
			depth := cur.depth + 1

			// ── Lstat first: never let the OS follow a symlink for us ────────
			st, err := os.Lstat(childAbs)
			if err != nil {
				skips = append(skips, Skip{Err: cerr.Wrap(cerr.EScan007, err, childRel)})
				continue
			}
			isLink := st.Mode()&os.ModeSymlink != 0

			// ── Symlink policy (INV-4) ──────────────────────────────────────
			//
			// Resolve, then containment-check. A check against the link rather
			// than the target is bypassable by the link, so the order is fixed.
			if isLink {
				resolved, rerr := filepath.EvalSymlinks(childAbs)
				if rerr != nil {
					// A dangling symlink or a cycle reported by the OS.
					skips = append(skips, Skip{Err: cerr.New(cerr.EScan005, childRel)})
					continue
				}
				resolved = filepath.Clean(resolved)
				if err := r.checkContained(childRel, resolved); err != nil {
					skips = append(skips, Skip{Err: cerr.New(cerr.EScan004, childRel, resolved)})
					continue
				}
				// Contained. Re-stat the target and continue as if it were a
				// normal entry, but remember that it was a link.
				tst, terr := os.Stat(resolved)
				if terr != nil {
					skips = append(skips, Skip{Err: cerr.Wrap(cerr.EScan007, terr, childRel)})
					continue
				}
				if tst.IsDir() {
					if visited[resolved] {
						skips = append(skips, Skip{Err: cerr.New(cerr.EScan005, childRel)})
						continue
					}
					visited[resolved] = true
					if reason, skip := r.shouldSkipDir(childRel, resolved, tst); skip {
						_ = reason
						skips = append(skips, Skip{Err: cerr.New(cerr.EScan005, childRel)})
						continue
					}
					stack = append(stack, frame{abs: resolved, rel: childRel, depth: depth})
					entries = append(entries, WalkEntry{Rel: childRel, Mode: tst.Mode(), IsDir: true, IsSymlink: true, Depth: depth})
					continue
				}
				entries = append(entries, WalkEntry{Rel: childRel, Size: tst.Size(), Mode: tst.Mode(), IsDir: false, IsSymlink: true, Depth: depth})
				continue
			}

			// ── Directory ────────────────────────────────────────────────────
			if st.IsDir() {
				if _, skip := r.shouldSkipDir(childRel, childAbs, st); skip {
					r.filesSkipped.Add(1)
					continue
				}
				if visited[childAbs] {
					skips = append(skips, Skip{Err: cerr.New(cerr.EScan005, childRel)})
					continue
				}
				visited[childAbs] = true
				stack = append(stack, frame{abs: childAbs, rel: childRel, depth: depth})
				entries = append(entries, WalkEntry{Rel: childRel, Mode: st.Mode(), IsDir: true, Depth: depth})
				continue
			}

			// ── Regular file ─────────────────────────────────────────────────
			if !st.Mode().IsRegular() {
				// Sockets, FIFOs, devices. Never interesting, and reading one
				// could block forever, which is a denial of service against the
				// scanner rather than against the user.
				r.filesSkipped.Add(1)
				continue
			}
			if !r.chargeFile() {
				skips = append(skips, Skip{Err: cerr.New(cerr.EScan003, itoa(int64(r.limits.MaxFiles)), "more")})
				// Budget exhausted: stop the whole walk rather than emitting
				// one skip per remaining file.
				sortWalk(entries, skips)
				return entries, skips, nil
			}
			entries = append(entries, WalkEntry{Rel: childRel, Size: st.Size(), Mode: st.Mode(), Depth: depth})
		}
	}

	sortWalk(entries, skips)
	return entries, skips, nil
}

// shouldSkipDir decides whether a directory is walked. It returns the reason
// (for the caller's diagnostics) and whether to skip.
func (r *Root) shouldSkipDir(rel, abs string, st os.FileInfo) (string, bool) {
	base := rel
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		base = rel[i+1:]
	}

	// 1. The flat skip list.
	if reason, ok := skipDirs[base]; ok {
		return reason, true
	}

	// 2. Build/cache directories, but only when nested inside node_modules,
	//    where they are unambiguously package-manager output.
	if strings.Contains(rel, "node_modules/") {
		if reason, ok := skipNestedInModules[base]; ok {
			return reason, true
		}
	}

	// 3. Nested node_modules: allow the first, refuse to descend into a second.
	//    A package that vendors its own dependencies can nest without bound,
	//    and the terms that matter are already recorded one level up.
	if base == "node_modules" && strings.Count(rel, "node_modules") >= 2 {
		return "nested node_modules beyond the first level", true
	}

	// 4. Virtualenvs — but only when they actually look like one. Skipping a
	//    directory merely *named* env/venv would hide real source, and hiding
	//    dependencies is the failure this tool exists to prevent.
	if base == ".venv" || base == "venv" || base == "env" || base == ".env-dir" {
		if looksLikeVenv(abs) {
			return "python virtualenv; duplicates the lockfile", true
		}
	}

	// 5. Generated output. `dist`, `build`, `target` and `out` are skipped
	//    because the source that produced them carries the licence. They are
	//    listed last so that an explicit skipDirs entry always wins.
	if base == "dist" || base == "build" || base == "target" || base == "out" {
		return "generated build output; the source carries the licence", true
	}

	return "", false
}

// looksLikeVenv probes for the markers a real virtualenv has and a source
// directory named `env` does not.
func looksLikeVenv(abs string) bool {
	for _, m := range venvMarkers {
		if _, err := os.Lstat(filepath.Join(abs, filepath.FromSlash(m))); err == nil {
			return true
		}
	}
	return false
}

func sortWalk(entries []WalkEntry, skips []Skip) {
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Rel < entries[j].Rel })
	sort.SliceStable(skips, func(i, j int) bool {
		if skips[i].Code() != skips[j].Code() {
			return skips[i].Code() < skips[j].Code()
		}
		return skips[i].Message() < skips[j].Message()
	})
}

// displayRel renders an empty rel path (the root) as "." for messages.
func displayRel(rel string) string {
	if rel == "" {
		return "."
	}
	return rel
}
