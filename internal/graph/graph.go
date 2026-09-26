// Package graph holds the dependency-graph types.
//
// WHY THIS PACKAGE EXISTS (a deliberate refinement of the plan's layout)
//
// PLAN/01-ARCHITECTURE/10-repo-structure.md places `Dependency` and
// `DependencyGraph` inside `internal/scanner` (L1). But the layer table in
// PLAN/01-ARCHITECTURE/01-system-architecture.md §1.1 is normative and says:
//
//	L3 Decision | may import L2 (types), L0 | may NEVER import L1
//
// with the rationale "a decision layer that reads the filesystem is
// untestable". If the graph types lived in L1, `policy.Evaluate` would have to
// import L1 to name its own parameter type, and the purity boundary would be
// breached on day one.
//
// So the types move here, to a package with NO imports beyond the standard
// library and no I/O of any kind. `scanner` (L1) constructs a Graph; `policy`
// (L3) consumes one. Neither knows about the other. This is the same trade-off
// the plan made for `corpus` (types) vs `scanner` (reading), applied one level
// down.
//
// Recorded in LOGS.md as D-002.
package graph

import (
	"fmt"
	"sort"
	"strings"
)

// Kind classifies what a dependency is. Weights are code (Principle 4), so a
// weight file is a first-class Dependency with the same obligation pipeline.
type Kind string

const (
	KindPackage     Kind = "package"      // an ecosystem package
	KindVendored    Kind = "vendored"     // a vendored directory with its own licence
	KindWeights     Kind = "weights"      // a model weight file
	KindUpstreamCLI Kind = "upstream_cli" // a third-party service reached via its CLI
	KindAsset       Kind = "asset"        // a brand asset (name, logo, typeface)
	KindModelCard   Kind = "model_card"   // a model card carrying licence terms
)

// WeightKinds are the kinds counted as "weight files" in the verdict summary.
func (k Kind) IsWeights() bool { return k == KindWeights }

// Evidence is where something was observed. It is mandatory on every
// Dependency and every Undetermined: a claim with no location is an opinion.
type Evidence struct {
	Path      string `json:"path"` // project-relative, always
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
	Excerpt   string `json:"excerpt,omitempty"` // <= 200 chars, the quoted clause
	SHA256    string `json:"sha256,omitempty"`  // content hash, for reproducibility
}

// LicenceRef is what we know about a dependency's licence.
type LicenceRef struct {
	SPDX       string `json:"spdx"`       // "Apache-2.0", "AGPL-3.0-only", "LicenseRef-*"
	Raw        string `json:"raw"`        // the literal string found ("see LICENSE")
	Source     string `json:"source"`     // manifest | lockfile | vendored_file | model_card | weight_metadata
	Expression bool   `json:"expression"` // is SPDX an expression ("MIT OR Apache-2.0")?
	Resolved   bool   `json:"resolved"`   // did we confidently identify it?

	// Family is filled from the corpus after resolution. It is empty until
	// then; the policy engine never reads it from the scanner, because the
	// scanner must not know what a licence family means.
	Family string `json:"family,omitempty"`

	// Permissiveness is 1..5, filled from the corpus. Used only by the
	// code-vs-weights divergence check.
	Permissiveness int `json:"permissiveness,omitempty"`

	// Confidence of the resolution itself, before any corpus opinion.
	Confidence string `json:"confidence,omitempty"`
}

// Dependency is one unit carrying terms.
type Dependency struct {
	ID        string `json:"id"` // stable: "npm:firecrawl@1.2.3"
	Kind      Kind   `json:"kind"`
	Name      string `json:"name"`
	Version   string `json:"version"`   // "" if unknown
	Ecosystem string `json:"ecosystem"` // npm | pypi | go | cargo | local | weights

	Licence  LicenceRef `json:"licence"`
	Evidence []Evidence `json:"evidence"`

	// Metadata holds ecosystem-specific extras. It is rendered only where a
	// renderer explicitly asks for a key, so adding a key is not a schema break.
	Metadata map[string]string `json:"metadata,omitempty"`

	Direct bool `json:"direct"` // direct vs transitive; used by fix suggestions

	// Scope groups a dependency with its siblings from the same source, so the
	// code-vs-weights divergence check can ask "same repository scope?".
	// Empty means "the project root".
	Scope string `json:"scope,omitempty"`
}

// SortKey is the explicit, total ordering used everywhere a dependency list is
// emitted. Map iteration order must never reach output (INV-6).
func (d Dependency) SortKey() string {
	return string(d.Kind) + "\x00" + d.Name + "\x00" + d.Version + "\x00" + d.ID
}

// Undetermined is the honest gap: a first-class output, never a silent pass.
type Undetermined struct {
	ID        string     `json:"id"`
	Kind      Kind       `json:"kind"`
	Reason    string     `json:"reason"` // machine code, e.g. "licence_file_unreadable"
	Detail    string     `json:"detail"` // human sentence
	Evidence  []Evidence `json:"evidence"`
	ErrorCode string     `json:"error_code"` // e.g. "E-PARSE-002"
}

// SortKey gives Undetermined a stable order: by (kind, id).
func (u Undetermined) SortKey() string { return string(u.Kind) + "\x00" + u.ID }

// Warning is a WARN or DEGRADE event that is not itself an Undetermined: a
// skipped symlink, a lockfile newer than its manifest, a broad ignore rule.
type Warning struct {
	Code     string     `json:"code"`
	Message  string     `json:"message"`
	Path     string     `json:"path,omitempty"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

// Stats records what the walk actually did, so the verdict can state its own
// completeness.
type Stats struct {
	FilesSeen    int   `json:"files_seen"`
	FilesSkipped int   `json:"files_skipped"`
	BytesRead    int64 `json:"bytes_read"`
	DirsVisited  int   `json:"dirs_visited"`
	MaxDepthSeen int   `json:"max_depth_seen"`
	Truncated    bool  `json:"truncated"`
}

// Graph is the scanner's complete output.
//
// Every slice is sorted before the Graph is returned. Nothing downstream sorts
// anything, and nothing downstream iterates a map.
type Graph struct {
	Root string `json:"root"`
	// ProjectLicence is the licence the project declares for itself, read from
	// the root manifest or a root LICENSE file. It is empty when nothing in
	// the tree declares one, which is itself a finding worth reporting.
	//
	// It is deliberately NOT propagated onto Dependencies. An earlier draft of
	// the parsers stamped the project's own licence onto every dependency it
	// returned, so a project declaring MIT while depending on an AGPL package
	// had every dependency labelled MIT — a false SHIP produced by a parser
	// being helpful. The two are separate facts and they live in separate
	// fields.
	ProjectLicence string         `json:"project_licence,omitempty"`
	Dependencies   []Dependency   `json:"dependencies"`
	Undetermined   []Undetermined `json:"undetermined"`
	Warnings       []Warning      `json:"warnings"`
	Stats          Stats          `json:"stats"`
}

// Normalise sorts every slice in the Graph. It is idempotent and it is the
// last thing the scanner does before returning. Calling it twice is harmless;
// failing to call it is a determinism bug.
func (g *Graph) Normalise() {
	sort.SliceStable(g.Dependencies, func(i, j int) bool {
		return g.Dependencies[i].SortKey() < g.Dependencies[j].SortKey()
	})
	sort.SliceStable(g.Undetermined, func(i, j int) bool {
		return g.Undetermined[i].SortKey() < g.Undetermined[j].SortKey()
	})
	sort.SliceStable(g.Warnings, func(i, j int) bool {
		if g.Warnings[i].Code != g.Warnings[j].Code {
			return g.Warnings[i].Code < g.Warnings[j].Code
		}
		if g.Warnings[i].Path != g.Warnings[j].Path {
			return g.Warnings[i].Path < g.Warnings[j].Path
		}
		return g.Warnings[i].Message < g.Warnings[j].Message
	})
}

// Find returns the dependency with the given ID, or false.
func (g *Graph) Find(id string) (Dependency, bool) {
	for _, d := range g.Dependencies {
		if d.ID == id {
			return d, true
		}
	}
	return Dependency{}, false
}

// CountWeights returns how many dependencies are weight files.
func (g *Graph) CountWeights() int {
	n := 0
	for _, d := range g.Dependencies {
		if d.Kind.IsWeights() {
			n++
		}
	}
	return n
}

// CountUpstreamCLIs returns how many dependencies are third-party service CLIs.
func (g *Graph) CountUpstreamCLIs() int {
	n := 0
	for _, d := range g.Dependencies {
		if d.Kind == KindUpstreamCLI {
			n++
		}
	}
	return n
}

// Add appends a dependency, replacing any existing entry with the same ID.
// Replacement (rather than duplication) is how the merge step lets a lockfile
// override a manifest: the lockfile entry is added last and wins.
func (g *Graph) Add(d Dependency) {
	for i := range g.Dependencies {
		if g.Dependencies[i].ID == d.ID {
			g.Dependencies[i] = d
			return
		}
	}
	g.Dependencies = append(g.Dependencies, d)
}

// PackageID builds the stable identifier for an ecosystem package.
func PackageID(ecosystem, name, version string) string {
	if version == "" {
		return ecosystem + ":" + name
	}
	return ecosystem + ":" + name + "@" + version
}

// LocalID builds the stable identifier for a local artefact (a vendored
// directory, a weight file, an asset). The path is project-relative and is
// normalised to forward slashes so an ID is identical on Windows and Linux.
func LocalID(kind Kind, relPath string) string {
	return string(kind) + ":" + strings.ReplaceAll(relPath, "\\", "/")
}

// Validate reports structural problems that would make a Graph untrustworthy.
// It is called by the scanner before returning and by tests. It never repairs:
// a Graph that fails Validate is a bug in the scanner.
func (g *Graph) Validate() error {
	seen := make(map[string]bool, len(g.Dependencies))
	for _, d := range g.Dependencies {
		if d.ID == "" {
			return fmt.Errorf("graph: dependency %q has no id", d.Name)
		}
		if seen[d.ID] {
			return fmt.Errorf("graph: duplicate dependency id %q", d.ID)
		}
		seen[d.ID] = true
		if len(d.Evidence) == 0 {
			return fmt.Errorf("graph: dependency %q has no evidence", d.ID)
		}
		for _, e := range d.Evidence {
			if e.Path == "" {
				return fmt.Errorf("graph: dependency %q has evidence with no path", d.ID)
			}
			if strings.HasPrefix(e.Path, "/") || strings.Contains(e.Path, "..") {
				return fmt.Errorf("graph: dependency %q has evidence path outside the root: %q", d.ID, e.Path)
			}
		}
	}
	for _, u := range g.Undetermined {
		if u.ID == "" {
			return fmt.Errorf("graph: undetermined entry with no id")
		}
		if u.Reason == "" {
			return fmt.Errorf("graph: undetermined %q has no reason", u.ID)
		}
		if u.ErrorCode == "" {
			return fmt.Errorf("graph: undetermined %q has no error code", u.ID)
		}
	}
	return nil
}
