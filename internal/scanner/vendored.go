package scanner

import (
	"path"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/safefs"
)

// attachVendoredLicences reads the licence files that ship inside dependencies.
//
// This is the part of the scan a dependency-list tool cannot do. A lockfile
// records what a package's licence *claims* to be; the LICENSE file inside
// node_modules/foo records what it *is*. When those disagree, the more
// restrictive one governs, and that disagreement is a finding this tool exists
// to produce.
//
// The two facts are stored as two dependencies rather than one, because they
// can only be compared if both survive. The package keeps its declared licence;
// the vendored file becomes a KindVendored dependency in the same Scope with
// Metadata["declared_licence"] naming the claim. internal/policy/crosscheck.go
// reads exactly that shape — check 2 of crossCheck, which selects on
// Licence.Source == "vendored_file" and reads that metadata key.
func (s *scan) attachVendoredLicences(entries []safefs.WalkEntry) {
	for _, e := range entries {
		if e.IsDir || e.Rel == "" || !IsLicenceFileName(e.Base()) {
			continue
		}

		if e.Dir() == "." {
			// The project's own licence. A manifest declaration is the project's
			// explicit statement, so this only fills a gap rather than
			// overriding one.
			if s.g.ProjectLicence == "" {
				if spdx, _, ok := s.recogniseFile(e.Rel); ok {
					s.g.ProjectLicence = spdx
				}
			}
			continue
		}

		if !insideDependencyDir(e.Rel) {
			// A licence in a sub-project directory belongs to that sub-project,
			// whose own manifest scan already covers it.
			continue
		}
		s.attachOne(e)
	}
}

// attachOne handles a single vendored licence file.
func (s *scan) attachOne(e safefs.WalkEntry) {
	spdx, conf, recognised := s.recogniseFile(e.Rel)
	if !recognised {
		// E-SCAN-011 exists for exactly this: text we could not identify. A
		// warning saying a human should read it is the honest outcome. Guessing
		// would attach another licence's obligations to this dependency and
		// produce a confident verdict about the wrong terms.
		s.warn(cerr.EScan011, e.Rel, "Unrecognised licence text at '"+e.Rel+"'. A human should read it.")
		return
	}

	idx, found := s.ownerOf(e.Rel)
	if !found {
		// A vendored directory nobody claimed. It is still a unit carrying
		// terms, so it is a dependency in its own right rather than being
		// dropped for want of a manifest entry.
		s.g.Add(graph.Dependency{
			ID:        graph.LocalID(graph.KindVendored, e.Rel),
			Kind:      graph.KindVendored,
			Name:      path.Dir(e.Rel),
			Ecosystem: "local",
			Licence: graph.LicenceRef{
				SPDX: spdx, Raw: spdx, Source: "vendored_file",
				Resolved: true, Confidence: conf,
			},
			Evidence: []graph.Evidence{{Path: e.Rel}},
		})
		return
	}

	pkg := &s.g.Dependencies[idx]

	// The package had no declared licence, so the vendored file is the only
	// evidence there is. Adopt it. This is the case vendoring exists for, and
	// leaving it unresolved would report UNDETERMINED for a dependency whose
	// licence is sitting right there on disk.
	if !pkg.Licence.Resolved || pkg.Licence.SPDX == "" {
		pkg.Licence = graph.LicenceRef{
			SPDX: spdx, Raw: spdx, Source: "vendored_file",
			Resolved: true, Confidence: conf,
		}
		pkg.Evidence = append(pkg.Evidence, graph.Evidence{Path: e.Rel})
		return
	}

	// The package declared a licence and a vendored file says something else.
	// Both facts are recorded, in the same scope, so that the
	// declared-vs-actual check can compare them. Merging them into one
	// dependency would destroy precisely the disagreement worth reporting.
	s.g.Add(graph.Dependency{
		ID:        graph.LocalID(graph.KindVendored, e.Rel),
		Kind:      graph.KindVendored,
		Name:      pkg.Name,
		Version:   pkg.Version,
		Ecosystem: pkg.Ecosystem,
		Scope:     pkg.Scope,
		Direct:    pkg.Direct,
		Licence: graph.LicenceRef{
			SPDX: spdx, Raw: spdx, Source: "vendored_file",
			Resolved: true, Confidence: conf,
		},
		Evidence: []graph.Evidence{{Path: e.Rel}},
		Metadata: map[string]string{
			"declared_licence": pkg.Licence.SPDX,
			"declared_source":  pkg.Licence.Source,
		},
	})
}

// ownerOf finds the package dependency that owns a vendored licence file.
//
// Matching is by longest name prefix after the dependency-directory marker is
// stripped, which covers npm ("node_modules/@scope/pkg"), Go
// ("vendor/github.com/org/repo") and Cargo ("vendor/crate") without needing a
// rule per ecosystem. Longest wins, so "github.com/org/repo" beats
// "github.com/org" when both happen to be dependencies.
//
// Scope is checked first, so that in a monorepo the licence under
// "packages/a/node_modules/foo" attaches to the package in scope "packages/a"
// rather than to an identically named dependency in scope "packages/b".
func (s *scan) ownerOf(rel string) (int, bool) {
	rest := rel
	for _, m := range dependencyDirMarkers {
		if i := strings.Index(rest, m); i >= 0 {
			rest = rest[i+len(m):]
			break
		}
	}
	if rest == "" {
		return -1, false
	}
	scope := s.containingScope(rel)

	// Two passes: prefer a dependency in the containing scope, then fall back
	// to the whole tree. The fallback matters for a vendored directory that
	// sits above every manifest, such as a root-level node_modules in a
	// monorepo whose packages are the manifests.
	if idx, ok := s.matchOwner(rest, scope, true); ok {
		return idx, true
	}
	return s.matchOwner(rest, scope, false)
}

// matchOwner finds the longest dependency name that prefixes rest. When
// requireScope is set, only dependencies in the containing scope are considered.
func (s *scan) matchOwner(rest, scope string, requireScope bool) (int, bool) {
	best, bestLen := -1, 0
	for i := range s.g.Dependencies {
		d := s.g.Dependencies[i]
		if d.Kind != graph.KindPackage || d.Name == "" {
			continue
		}
		if requireScope && d.Scope != scope {
			continue
		}
		if !(rest == d.Name || strings.HasPrefix(rest, d.Name+"/")) {
			continue
		}
		if len(d.Name) > bestLen {
			best, bestLen = i, len(d.Name)
		}
	}
	return best, best >= 0
}

// containingScope returns the deepest project directory that contains a path,
// or "" when none does.
func (s *scan) containingScope(rel string) string {
	best := ""
	for _, p := range s.projects {
		dir := p.Dir
		if dir == "." {
			dir = ""
		}
		if dir == "" {
			if best == "" {
				best = "."
			}
			continue
		}
		if rel == dir || strings.HasPrefix(rel, dir+"/") {
			if len(dir) > len(best) {
				best = dir
			}
		}
	}
	if best == "" {
		return "."
	}
	return best
}

// recogniseFile reads a licence file and identifies it.
func (s *scan) recogniseFile(rel string) (spdx, confidence string, ok bool) {
	data, err := s.root.ReadFile(rel, s.opts.licenceLimit())
	if err != nil {
		// A licence file that cannot be read is recorded as a problem, never
		// assumed to be permissive. ReadFile already applies the size and
		// permission limits and returns a typed error naming which was hit.
		s.warnErr(err, rel)
		return "", "", false
	}
	return Recognise(string(data))
}
