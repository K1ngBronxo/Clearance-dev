package scanner

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/clearance-dev/clearance/internal/graph"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

// writeTree materialises a map of project-relative path to contents.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

const mitText = `MIT License

Copyright (c) 2024 Someone

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED.
`

const apacheText = `                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   Licensed under the Apache License, Version 2.0 (the "License");
`

func scanTree(t *testing.T, files map[string]string) *graph.Graph {
	t.Helper()
	root := writeTree(t, files)
	g, err := Scan(root, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return g
}

func findDep(t *testing.T, g *graph.Graph, id string) graph.Dependency {
	t.Helper()
	if d, ok := g.Find(id); ok {
		return d
	}
	var have []string
	for _, d := range g.Dependencies {
		have = append(have, d.ID)
	}
	t.Fatalf("no dependency %q; have %v", id, have)
	return graph.Dependency{}
}

func hasWarning(g *graph.Graph, code string) bool {
	for _, w := range g.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// ── the core path ────────────────────────────────────────────────────────────

// TestScanNPMProject is the end-to-end case the whole product is built around:
// a manifest, a lockfile and a vendored licence, producing a graph with a
// resolved licence and evidence for every dependency.
func TestScanNPMProject(t *testing.T) {
	g := scanTree(t, map[string]string{
		"package.json": `{
		  "name": "app",
		  "version": "1.0.0",
		  "license": "MIT",
		  "dependencies": {"left-pad": "^1.3.0"}
		}`,
		"package-lock.json": `{
		  "name": "app",
		  "lockfileVersion": 3,
		  "packages": {
		    "": {"name": "app", "version": "1.0.0", "license": "MIT"},
		    "node_modules/left-pad": {"version": "1.3.0", "license": "MIT"}
		  }
		}`,
		"node_modules/left-pad/package.json": `{"name":"left-pad","version":"1.3.0"}`,
		"node_modules/left-pad/LICENSE":      mitText,
	})

	// The lockfile resolves, so it wins over the manifest.
	dep := findDep(t, g, "npm:left-pad@1.3.0")
	if dep.Licence.SPDX != "MIT" || !dep.Licence.Resolved {
		t.Errorf("left-pad licence = (%q, Resolved=%v), want (MIT, true)", dep.Licence.SPDX, dep.Licence.Resolved)
	}
	if dep.Licence.Source != "lockfile" {
		t.Errorf("licence source = %q, want lockfile", dep.Licence.Source)
	}
	if !dep.Direct {
		t.Error("left-pad is a direct dependency")
	}
	if len(dep.Evidence) == 0 || dep.Evidence[0].Path == "" {
		t.Error("every dependency must carry evidence (INV-1)")
	}

	// The project's own licence comes from the manifest.
	if g.ProjectLicence != "MIT" {
		t.Errorf("ProjectLicence = %q, want MIT", g.ProjectLicence)
	}

	// A package.json inside node_modules must NOT be treated as a project.
	if len(g.Dependencies) > 2 {
		for _, d := range g.Dependencies {
			if d.Kind == graph.KindPackage && strings.Contains(d.Name, "left-pad") && d.Scope != "." {
				t.Errorf("a dependency was discovered with scope %q; node_modules is not a project root", d.Scope)
			}
		}
	}

	if err := g.Validate(); err != nil {
		t.Errorf("graph failed Validate: %v", err)
	}
}

// TestVendoredLicenceIsASeparateFact is the signature capability. The lockfile
// claims MIT; the LICENSE file on disk says Apache-2.0. Both must survive as
// separate dependencies in the same scope, because the more restrictive one
// governs and the disagreement is the finding.
func TestVendoredLicenceIsASeparateFact(t *testing.T) {
	g := scanTree(t, map[string]string{
		"package.json": `{"name":"app","license":"MIT","dependencies":{"sneaky":"1.0.0"}}`,
		"package-lock.json": `{
		  "lockfileVersion": 3,
		  "packages": {
		    "": {"name": "app"},
		    "node_modules/sneaky": {"version": "1.0.0", "license": "MIT"}
		  }
		}`,
		"node_modules/sneaky/LICENSE": apacheText,
	})

	declared := findDep(t, g, "npm:sneaky@1.0.0")
	if declared.Licence.SPDX != "MIT" {
		t.Errorf("declared licence = %q, want MIT", declared.Licence.SPDX)
	}

	vendored := findDep(t, g, "vendored:node_modules/sneaky/LICENSE")
	if vendored.Kind != graph.KindVendored {
		t.Errorf("vendored kind = %q, want vendored", vendored.Kind)
	}
	if vendored.Licence.SPDX != "Apache-2.0" {
		t.Errorf("vendored licence = %q, want Apache-2.0", vendored.Licence.SPDX)
	}
	if vendored.Licence.Source != "vendored_file" {
		t.Errorf("vendored source = %q, want vendored_file (policy selects on this)", vendored.Licence.Source)
	}
	// This metadata key is the contract with policy/crosscheck.go check 2.
	if got := vendored.Metadata["declared_licence"]; got != "MIT" {
		t.Errorf("declared_licence = %q, want MIT", got)
	}
	if vendored.Scope != declared.Scope {
		t.Errorf("vendored scope %q != declared scope %q; the comparison is per-scope", vendored.Scope, declared.Scope)
	}
}

// TestVendoredLicenceFillsAnUnresolvedLicence: when a lockfile records no
// licence, the vendored file is the only evidence there is. Leaving it
// unresolved would report UNDETERMINED for a dependency whose licence is
// sitting right there on disk.
func TestVendoredLicenceFillsAnUnresolvedLicence(t *testing.T) {
	g := scanTree(t, map[string]string{
		"package.json":                 `{"name":"app","dependencies":{"mystery":"1.0.0"}}`,
		"package-lock.json":            `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/mystery":{"version":"1.0.0"}}}`,
		"node_modules/mystery/LICENSE": mitText,
	})
	dep := findDep(t, g, "npm:mystery@1.0.0")
	if !dep.Licence.Resolved || dep.Licence.SPDX != "MIT" {
		t.Errorf("licence = (%q, Resolved=%v), want (MIT, true) from the vendored file", dep.Licence.SPDX, dep.Licence.Resolved)
	}
	if dep.Licence.Source != "vendored_file" {
		t.Errorf("licence source = %q, want vendored_file", dep.Licence.Source)
	}
}

// TestUnrecognisedLicenceTextIsAWarningNotAGuess: recognition prefers to fail.
// A wrong identification would attach another licence's obligations to this
// dependency.
func TestUnrecognisedLicenceTextIsAWarningNotAGuess(t *testing.T) {
	g := scanTree(t, map[string]string{
		"package.json":      `{"name":"app","dependencies":{"weird":"1.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/weird":{"version":"1.0.0"}}}`,
		"node_modules/weird/LICENSE": `You may use this software only on Tuesdays.
Contact legal@example.com for terms.`,
	})
	if !hasWarning(g, "E-SCAN-011") {
		t.Error("unrecognised licence text must produce E-SCAN-011 so a human reads it")
	}
	dep := findDep(t, g, "npm:weird@1.0.0")
	if dep.Licence.Resolved {
		t.Errorf("licence resolved to %q; unrecognised text must stay unresolved", dep.Licence.SPDX)
	}
}

// TestUnknownLicenceStringStaysUnresolved covers the common real value
// "SEE LICENSE IN COPYING", which is a pointer rather than an identifier.
func TestUnknownLicenceStringStaysUnresolved(t *testing.T) {
	g := scanTree(t, map[string]string{
		"package.json":      `{"name":"app","dependencies":{"p":"1.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/p":{"version":"1.0.0","license":"SEE LICENSE IN COPYING"}}}`,
	})
	dep := findDep(t, g, "npm:p@1.0.0")
	if dep.Licence.Resolved {
		t.Errorf("resolved %q from a pointer value", dep.Licence.SPDX)
	}
	if dep.Licence.Raw != "SEE LICENSE IN COPYING" {
		t.Errorf("Raw = %q; the original text must survive for the report", dep.Licence.Raw)
	}
}

// TestSPDXExpressionIsRecordedFaithfully: whether "OR" lets you choose the
// permissive branch is a question about obligations, so the scanner records the
// expression and does not interpret it.
func TestSPDXExpressionIsRecordedFaithfully(t *testing.T) {
	g := scanTree(t, map[string]string{
		"package.json":      `{"name":"app","dependencies":{"dual":"1.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/dual":{"version":"1.0.0","license":"MIT OR Apache-2.0"}}}`,
	})
	dep := findDep(t, g, "npm:dual@1.0.0")
	if dep.Licence.SPDX != "MIT OR Apache-2.0" {
		t.Errorf("SPDX = %q, want the expression verbatim", dep.Licence.SPDX)
	}
	if !dep.Licence.Expression {
		t.Error("Expression must be true so the policy layer knows to interpret it")
	}
}

// ── ecosystem coverage ───────────────────────────────────────────────────────

func TestScanGoModule(t *testing.T) {
	g := scanTree(t, map[string]string{
		"go.mod": `// license: Apache-2.0
module example.com/app

go 1.23

require (
	github.com/direct/pkg v1.2.3
	github.com/indirect/pkg v0.9.0 // indirect
)
`,
	})
	if g.ProjectLicence != "Apache-2.0" {
		t.Errorf("ProjectLicence = %q, want Apache-2.0", g.ProjectLicence)
	}
	d := findDep(t, g, "go:github.com/direct/pkg@v1.2.3")
	if !d.Direct {
		t.Error("a require without // indirect is direct")
	}
	if d.Licence.Resolved {
		t.Error("go.mod records no licence for a dependency, so it must stay unresolved")
	}
	i := findDep(t, g, "go:github.com/indirect/pkg@v0.9.0")
	if i.Direct {
		t.Error("// indirect must be honoured")
	}
}

func TestScanCargoProject(t *testing.T) {
	g := scanTree(t, map[string]string{
		"Cargo.toml": `[package]
name = "app"
version = "0.1.0"
license = "MIT OR Apache-2.0"

[dependencies]
serde = "1.0"
`,
		"Cargo.lock": `version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
`,
	})
	if g.ProjectLicence != "MIT OR Apache-2.0" {
		t.Errorf("ProjectLicence = %q, want MIT OR Apache-2.0", g.ProjectLicence)
	}
	// The lockfile wins, so the version is the resolution, not the requirement.
	d := findDep(t, g, "cargo:serde@1.0.200")
	if d.Licence.Resolved {
		t.Error("Cargo.lock records no licence, so it must stay unresolved")
	}
	if d.Licence.Source != "lockfile" {
		t.Errorf("licence source = %q, want lockfile", d.Licence.Source)
	}
	// The root crate is part of the project, not a dependency of it.
	if _, ok := g.Find("cargo:app@0.1.0"); ok {
		t.Error("the root crate must not appear as a dependency of itself")
	}
}

func TestScanPyPIProject(t *testing.T) {
	g := scanTree(t, map[string]string{
		"pyproject.toml": `[project]
name = "app"
license = "MIT"
dependencies = ["requests>=2.0"]
`,
	})
	if g.ProjectLicence != "MIT" {
		t.Errorf("ProjectLicence = %q, want MIT", g.ProjectLicence)
	}
	// A pyproject records the *project's* licence, never a dependency's. So the
	// dependency must stay unresolved, and the project's own MIT declaration
	// must not be stamped onto it — that would be a false SHIP.
	d := findDep(t, g, "pypi:requests@2.0")
	if d.Licence.Resolved {
		t.Errorf("dependency licence resolved to %q from the project's own declaration", d.Licence.SPDX)
	}
	if d.Licence.Raw != "" {
		t.Errorf("dependency LicenceRaw = %q; the project's licence must not be stamped onto a dependency", d.Licence.Raw)
	}
}

// ── refusals and honesty ─────────────────────────────────────────────────────

func TestScanWithoutAManifestIsRefused(t *testing.T) {
	root := writeTree(t, map[string]string{"README.md": "hello"})
	if _, err := Scan(root, Options{}); err == nil {
		t.Fatal("a tree with no dependency manifest must be refused (E-SCAN-009), not reported as an empty graph")
	}
}

// TestUnsupportedLockfileIsReported: falling back to the manifest without
// saying so would make a weaker scan look like a normal one.
func TestUnsupportedLockfileIsReported(t *testing.T) {
	g := scanTree(t, map[string]string{
		"package.json":   `{"name":"app","dependencies":{"a":"^1.0.0"}}`,
		"pnpm-lock.yaml": "lockfileVersion: '6.0'\n",
	})
	if !hasWarning(g, "E-PARSE-001") {
		t.Error("an unsupported lockfile must produce a warning, not a silent fallback")
	}
	// The manifest is still used, with range versions and a note.
	d := findDep(t, g, "npm:a@1.0.0")
	if d.Metadata["version_is_requirement"] != "true" {
		t.Error("a range version must be marked as a requirement in metadata")
	}
}

func TestSymlinkEscapeIsSkippedWithAWarning(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","dependencies":{"a":"1.0.0"}}`,
		"outside.txt":  "secret",
	})
	// A symlink pointing at a directory outside the root. Creating a symlink
	// needs privileges on Windows, so the test degrades to a skip rather than
	// failing for an environment reason.
	outside := t.TempDir()
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("cannot create a symlink in this environment: %v", err)
	}
	// Windows without SeCreateSymbolicLinkPrivilege can report success from
	// Symlink and create nothing, so the returned error is not sufficient
	// evidence that the fixture exists. Verify it, or the test would assert
	// against a file that is not there.
	if _, err := os.Lstat(link); err != nil {
		t.Skipf("symlink was not actually created in this environment: %v", err)
	}

	g, err := Scan(root, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !hasWarning(g, "E-SCAN-004") {
		t.Error("a symlink resolving outside the root must produce E-SCAN-004, never be followed silently")
	}
}

// TestPathDependencyOutsideRootIsUndetermined: INV-4 forbids reading outside
// the root, so the licence is genuinely unknown. It must appear in the graph
// rather than being silently dropped.
func TestPathDependencyOutsideRootIsUndetermined(t *testing.T) {
	g := scanTree(t, map[string]string{
		"Cargo.toml": `[package]
name = "app"
version = "0.1.0"

[dependencies]
sibling = { path = "../sibling" }
`,
	})
	d := findDep(t, g, "cargo:sibling")
	if d.Metadata["outside_root"] != "true" {
		t.Errorf("metadata = %v; a path dependency outside the root must be flagged", d.Metadata)
	}
	if d.Licence.Resolved {
		t.Error("a licence outside the root cannot be read, so it must stay unresolved")
	}
}

// ── invariants ───────────────────────────────────────────────────────────────

// TestScanIsDeterministic guards INV-6 at the scanner boundary: two scans of
// the same tree must produce byte-identical graphs.
func TestScanIsDeterministic(t *testing.T) {
	files := map[string]string{
		"package.json": `{"name":"app","license":"MIT","dependencies":{"z":"1.0.0","a":"2.0.0","m":"3.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"name":"app"},
		  "node_modules/z":{"version":"1.0.0","license":"MIT"},
		  "node_modules/a":{"version":"2.0.0","license":"MIT"},
		  "node_modules/m":{"version":"3.0.0","license":"MIT"}}}`,
		"node_modules/z/LICENSE": mitText,
		"node_modules/a/LICENSE": apacheText,
		"go.mod":                 "module x\n\nrequire github.com/p/q v1.0.0\n",
	}
	root := writeTree(t, files)

	var first *graph.Graph
	for i := 0; i < 3; i++ {
		g, err := Scan(root, Options{})
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if i == 0 {
			first = g
			continue
		}
		if !reflect.DeepEqual(first, g) {
			t.Fatalf("scan %d differs from scan 0:\n first deps = %v\n  run%d deps = %v",
				i, first.Dependencies, i, g.Dependencies)
		}
	}

	// And the order is the documented total order, not file order.
	for i := 1; i < len(first.Dependencies); i++ {
		if first.Dependencies[i-1].SortKey() > first.Dependencies[i].SortKey() {
			t.Errorf("dependencies are not in SortKey order at %d: %q > %q",
				i, first.Dependencies[i-1].SortKey(), first.Dependencies[i].SortKey())
		}
	}
}

// TestEveryDependencyHasEvidence is INV-1 at the scanner boundary. A dependency
// with no location is a claim nobody can check.
func TestEveryDependencyHasEvidence(t *testing.T) {
	g := scanTree(t, map[string]string{
		"package.json": `{"name":"app","dependencies":{"a":"1.0.0","b":"2.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"name":"app"},
		  "node_modules/a":{"version":"1.0.0"},"node_modules/b":{"version":"2.0.0"}}}`,
		"node_modules/a/LICENSE": mitText,
	})
	for _, d := range g.Dependencies {
		if len(d.Evidence) == 0 {
			t.Errorf("dependency %q has no evidence", d.ID)
		}
		for _, e := range d.Evidence {
			if e.Path == "" {
				t.Errorf("dependency %q has evidence with no path", d.ID)
			}
			if strings.HasPrefix(e.Path, "/") || strings.Contains(e.Path, "..") {
				t.Errorf("dependency %q has an evidence path outside the root: %q", d.ID, e.Path)
			}
		}
	}
}

// TestStatsAreRecorded: a verdict has to be able to state its own completeness.
func TestStatsAreRecorded(t *testing.T) {
	g := scanTree(t, map[string]string{
		"package.json": `{"name":"app","dependencies":{"a":"1.0.0"}}`,
	})
	if g.Stats.FilesSeen == 0 {
		t.Error("Stats.FilesSeen must be recorded so the verdict can state its completeness")
	}
	if g.Root == "" {
		t.Error("Graph.Root must be set")
	}
}

// ── recognition unit tests ───────────────────────────────────────────────────

func TestRecognise(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{"mit", mitText, "MIT"},
		{"apache", apacheText, "Apache-2.0"},
		{"agpl", "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n", "AGPL-3.0-only"},
		{"lgpl", "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n", "LGPL-3.0-only"},
		{"gpl3", "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n", "GPL-3.0-only"},
		{"gpl2", "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n", "GPL-2.0-only"},
		{"sspl", "Server Side Public License\nVersion 1\n", "SSPL-1.0"},
		{"elastic", "Elastic License 2.0\n", "Elastic-2.0"},
		{"mpl", "Mozilla Public License Version 2.0\n", "MPL-2.0"},
		{"bsd3", "Redistribution and use in source and binary forms, with or without modification.\nNeither the name of the copyright holder may be used.\n", "BSD-3-Clause"},
		{"bsd2", "Redistribution and use in source and binary forms, with or without modification.\n", "BSD-2-Clause"},
		{"ccbync", "Attribution-NonCommercial 4.0 International\n", "CC-BY-NC-4.0"},
		{"ccby", "Creative Commons Attribution 4.0 International\n", "CC-BY-4.0"},
		{"isc", "Permission to use, copy, modify, and/or distribute this software for any purpose\nwith or without fee is hereby granted.\n", "ISC"},
		{"unlicense", "This is free and unencumbered software released into the public domain.\n", "Unlicense"},
		// Text that must NOT be identified.
		{"empty", "", ""},
		{"proprietary", "All rights reserved. Contact sales@example.com for a licence.", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, ok := Recognise(tc.text)
			if tc.want == "" {
				if ok {
					t.Errorf("Recognise identified %q from text it should not have matched", got)
				}
				return
			}
			if !ok {
				t.Fatalf("Recognise did not match %s text", tc.want)
			}
			if got != tc.want {
				t.Errorf("Recognise = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRecogniseFoldsTypographicPunctuation: a licence that has been through a

// ── E-SCAN-015: the stale-lockfile window ────────────────────────────────────

// staleLockfileTree writes the smallest npm project whose manifest and lockfile
// both parse, which is the precondition the rule needs.
func staleLockfileTree(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","license":"MIT","dependencies":{"left-pad":"^1.3.0"}}`,
		"package-lock.json": `{"name":"app","lockfileVersion":3,"packages":{` +
			`"":{"name":"app","version":"1.0.0","license":"MIT"},` +
			`"node_modules/left-pad":{"version":"1.3.0","license":"MIT"}}}`,
	})
}

// staleLockfileWarning returns the message of the E-SCAN-015 warning, or "" when
// the scan did not produce one.
func staleLockfileWarning(g *graph.Graph) string {
	for _, w := range g.Warnings {
		if w.Code == "E-SCAN-015" {
			return w.Message
		}
	}
	return ""
}

// TestStaleLockfileWindow pins the three cases the window exists to separate.
//
// # WHY THIS TEST SETS TIMESTAMPS INSTEAD OF OBSERVING THEM
//
// E-SCAN-015 is the only rule in this package whose input is a file's
// modification time, and modification times are not reproducible: git does not
// preserve them, so a checkout writes every file at once and the difference
// between any two of them is a property of the checkout rather than of the
// project. This is not hypothetical. On a pristine worktree, three of this
// repository's own fixtures reported a stale lockfile, because git wrote
// package.json exactly one millisecond after package-lock.json — so the fixture
// suite passed or failed depending on the order git happened to write files in.
//
// A test that observes timestamps inherits that non-determinism. This one
// controls them: os.Chtimes sets both instants, and what is asserted is the
// rule, not the filesystem. The fixture suite then asserts the rule's silence,
// which is the state every checked-out project is in.
//
// # WHAT EACH CASE IS FOR
//
// The first three cases are the ones that were failing in practice; the fourth
// is the finding the rule exists to make; the fifth pins the DIRECTION, which
// the two disagreed about until the taxonomy row was corrected. A lockfile
// written after its manifest is the healthy
// state after `npm install`, and warning there would fire on almost every
// project that had recently resolved its dependencies — which is how a warning
// teaches its readers to stop reading warnings.
func TestStaleLockfileWindow(t *testing.T) {
	// A fixed instant, so the rule cannot depend on when the test runs.
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		// delta is the manifest's modification time relative to the lockfile's.
		delta time.Duration
		want  bool
		why   string
	}{
		{
			name:  "the same timestamp is a checkout, not a stale lockfile",
			delta: 0,
			want:  false,
			why:   "a clone writes both files at once, so there is nothing to report",
		},
		{
			name:  "one millisecond newer is still a checkout",
			delta: time.Millisecond,
			want:  false,
			why: "git writes files in index order, so a manifest a millisecond " +
				"after its lockfile is a property of the checkout, not a fact " +
				"about the project",
		},
		{
			name:  "the window boundary itself is quiet",
			delta: staleLockfileWindow,
			want:  false,
			why:   "the comparison is strict, so the boundary belongs to the quiet side",
		},
		{
			name:  "a manifest past the window is a stale lockfile",
			delta: staleLockfileWindow + time.Second,
			want:  true,
			why: "the lockfile is about to be trusted and no longer reflects the " +
				"manifest, so the user is told before they read a verdict from it",
		},
		{
			name:  "a lockfile written after its manifest is never stale",
			delta: -time.Hour,
			want:  false,
			why: "this is the normal state after a dependency resolution, and it " +
				"is the direction the taxonomy described until it was corrected",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := staleLockfileTree(t)

			manifestTime := base.Add(tc.delta)
			for rel, when := range map[string]time.Time{
				"package.json":      manifestTime,
				"package-lock.json": base,
			} {
				abs := filepath.Join(root, filepath.FromSlash(rel))
				if err := os.Chtimes(abs, when, when); err != nil {
					t.Fatalf("setting the mtime of %s: %v", rel, err)
				}
			}

			g, err := Scan(root, Options{})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}

			msg := staleLockfileWarning(g)
			if tc.want && msg == "" {
				t.Fatalf("no E-SCAN-015 warning. %s", tc.why)
			}
			if !tc.want && msg != "" {
				t.Fatalf("E-SCAN-015 fired when it must not: %s\nMessage: %s",
					tc.why, msg)
			}
			if !tc.want {
				return
			}
			// The message names the manifest first because the manifest is the
			// file that moved. A message naming the lockfile first would tell
			// the reader the opposite of what happened, and the taxonomy
			// example does the same, so the two are pinned together.
			if !strings.Contains(msg, "'package.json' is newer than 'package-lock.json'") {
				t.Errorf("the warning names the files in the wrong order: %s\n"+
					"The manifest is the one that was edited; a message that "+
					"reversed them would report the healthy state as the fault.", msg)
			}
		})
	}
}

// word processor must still match, or the tool reports an unresolved licence on
// an ordinary MIT file.
func TestRecogniseFoldsTypographicPunctuation(t *testing.T) {
	smart := "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\u00a0of this software.\nTHE SOFTWARE IS PROVIDED \u201cAS IS\u201d, WITHOUT WARRANTY OF ANY KIND.\n"
	if got, _, ok := Recognise(smart); !ok || got != "MIT" {
		t.Errorf("Recognise(smart quotes) = (%q, %v), want (MIT, true)", got, ok)
	}
}

func TestIsLicenceFileName(t *testing.T) {
	yes := []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "LICENSE-MIT", "LICENSE-APACHE",
		"licence", "COPYING", "COPYING.txt", "NOTICE", "UNLICENSE", "LICENSE.Apache-2.0"}
	no := []string{"LICENSEE.md", "main.go", "README.md", "license_check.py", "package.json"}
	for _, n := range yes {
		if !IsLicenceFileName(n) {
			t.Errorf("IsLicenceFileName(%q) = false, want true", n)
		}
	}
	for _, n := range no {
		if IsLicenceFileName(n) {
			t.Errorf("IsLicenceFileName(%q) = true, want false", n)
		}
	}
}

// TestLicenceRefFromString covers the manifest/lockfile licence vocabulary.
func TestLicenceRefFromString(t *testing.T) {
	cases := []struct {
		raw      string
		wantSPDX string
		wantOK   bool
		wantExpr bool
	}{
		{"MIT", "MIT", true, false},
		{"mit", "MIT", true, false},
		{"Apache-2.0", "Apache-2.0", true, false},
		{"MIT OR Apache-2.0", "MIT OR Apache-2.0", true, true},
		{"(MIT OR GPL-3.0-only)", "(MIT OR GPL-3.0-only)", true, true},
		{"SEE LICENSE IN COPYING", "", false, false},
		{"", "", false, false},
	}
	for _, tc := range cases {
		got := LicenceRefFromString(tc.raw, "manifest")
		if got.Resolved != tc.wantOK {
			t.Errorf("LicenceRefFromString(%q).Resolved = %v, want %v", tc.raw, got.Resolved, tc.wantOK)
		}
		if tc.wantOK && got.SPDX != tc.wantSPDX {
			t.Errorf("LicenceRefFromString(%q).SPDX = %q, want %q", tc.raw, got.SPDX, tc.wantSPDX)
		}
		if got.Expression != tc.wantExpr {
			t.Errorf("LicenceRefFromString(%q).Expression = %v, want %v", tc.raw, got.Expression, tc.wantExpr)
		}
	}
}
