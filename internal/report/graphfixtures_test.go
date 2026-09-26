package report

import (
	"github.com/clearance-dev/clearance/internal/graph"
)

// Graph fixtures for the SBOM exporters.
//
// The exporters take two inputs — a Verdict and a *graph.Graph — and join them
// by dependency id. A golden over a nil graph would pin the empty case and
// nothing else, so each fixture gets a graph whose dependencies match the ids
// its findings name, plus at least one clean dependency that no finding
// touches. That last component is deliberate: it is the case where the join
// must produce a component with no verdict properties at all, which is the
// easiest thing to get wrong when the join is written the other way round.

// dep is a terse dependency constructor for the fixtures.
func dep(
	id string, kind graph.Kind, name, version, ecosystem string,
	spdx, raw string, resolved, direct bool,
) graph.Dependency {
	return graph.Dependency{
		ID:        id,
		Kind:      kind,
		Name:      name,
		Version:   version,
		Ecosystem: ecosystem,
		Licence: graph.LicenceRef{
			SPDX:     spdx,
			Raw:      raw,
			Source:   "lockfile",
			Resolved: resolved,
		},
		Evidence: []graph.Evidence{{Path: "package-lock.json", LineStart: 1, LineEnd: 1}},
		Direct:   direct,
	}
}

// graphFor returns the graph that belongs beside the named fixture.
//
// The returned graph is Normalise()d, exactly as the scanner returns it, so the
// SBOM goldens pin the exporter's own ordering rather than inheriting a
// conveniently pre-sorted literal.
func graphFor(name string) *graph.Graph {
	g := &graph.Graph{Root: "acme-web"}
	switch name {
	case "ship":
		g.Dependencies = []graph.Dependency{
			dep("cargo:serde@1.0.0", graph.KindPackage, "serde", "1.0.0", "cargo", "MIT OR Apache-2.0", "", true, false),
			dep("npm:@mendable/firecrawl-js@1.2.3", graph.KindPackage, "@mendable/firecrawl-js", "1.2.3", "npm", "MIT", "", true, true),
			dep("weights:models/embed.bin", graph.KindWeights, "models/embed.bin", "", "weights", "Apache-2.0", "", true, true),
		}

	case "conditional":
		g.Dependencies = []graph.Dependency{
			dep("cargo:leftpad@1.0.0", graph.KindPackage, "leftpad", "1.0.0", "cargo", "", "custom notice", false, false),
			dep("npm:@mendable/firecrawl-js@1.2.3", graph.KindPackage, "@mendable/firecrawl-js", "1.2.3", "npm", "MIT", "", true, true),
			dep("pypi:torch@2.4.0", graph.KindPackage, "torch", "2.4.0", "pypi", "BSD-3-Clause", "", true, true),
		}

	case "blocked":
		g.Dependencies = []graph.Dependency{
			dep("cargo:serde@1.0.0", graph.KindPackage, "serde", "1.0.0", "cargo", "MIT OR Apache-2.0", "", true, false),
			dep("npm:some-agpl-lib@3.0.0", graph.KindPackage, "some-agpl-lib", "3.0.0", "npm", "AGPL-3.0-only", "", true, true),
			dep("npm:tiny-mit@1.0.0", graph.KindPackage, "tiny-mit", "1.0.0", "npm", "MIT", "", true, true),
			dep("weights:models/llama-3.1-8b.bin", graph.KindWeights, "models/llama-3.1-8b.bin", "", "weights", "", "Llama-3.1-Community", true, false),
		}

	case "undetermined":
		g.Dependencies = []graph.Dependency{
			dep("npm:leftpad@1.0.0", graph.KindPackage, "leftpad", "1.0.0", "npm", "", "", false, true),
			dep("weights:models/x.bin", graph.KindWeights, "models/x.bin", "", "weights", "", "", false, false),
		}

	case "edge":
		g.Dependencies = []graph.Dependency{
			dep("local:orphan.dat", graph.KindAsset, "orphan.dat", "", "local", "", "", false, false),
			dep("npm:no-cite@1.0.0", graph.KindPackage, "no-cite", "1.0.0", "npm", "MIT", "", true, true),
			dep("npm:no-evidence@1.0.0", graph.KindPackage, "no-evidence", "1.0.0", "npm", "MIT", "", true, true),
		}
	}

	g.Normalise()
	return g
}
