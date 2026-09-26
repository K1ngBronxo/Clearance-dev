package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// This file asserts *structure* on the machine-readable formats, on top of the
// byte-for-byte goldens.
//
// A golden pins stability. It does not, on its own, prove the bytes are a valid
// document: a golden captured from a broken renderer is a test that enforces
// the breakage. So every machine format is also unmarshalled and checked
// against the properties an external consumer depends on — the SARIF version
// and rule/result consistency, the CycloneDX spec fields and bom-ref graph, and
// the SPDX identifier and relationship integrity.
//
// The field-name assertions deliberately go through map[string]any rather than
// the package's own structs. Decoding into the implementation's structs would
// pass even if both the struct tags and the output were wrong in the same way;
// reading the wire keys by name is what proves the document on disk.

// jsonMap unmarshals b into a generic map, failing the test if it is not JSON.
func jsonMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, b)
	}
	return m
}

// ─── JSON canonical contract ────────────────────────────────────────────────

func TestJSONStructure(t *testing.T) {
	valid := map[string]bool{
		string(verdict.Ship): true, string(verdict.ShipConditional): true,
		string(verdict.DoNotShip): true, string(verdict.Undetermined): true,
	}

	for _, fx := range allFixtures() {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			b, err := MarshalJSON(fx.v)
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}
			m := jsonMap(t, b)

			if got := m["schema_version"]; got != float64(1) {
				t.Errorf("schema_version = %v, want 1", got)
			}
			class, _ := m["verdict"].(string)
			if !valid[class] {
				t.Errorf("verdict = %q, which is not one of the four classes", class)
			}

			// The arrays must be present and must never be null: a consumer
			// must not have to null-check (normalise's whole job).
			for _, key := range []string{"blockers", "conditions", "notes", "undetermined"} {
				raw, ok := m[key]
				if !ok {
					t.Errorf("%q is absent; every array must be present", key)
					continue
				}
				if raw == nil {
					t.Errorf("%q is null; it must be []", key)
					continue
				}
				if _, ok := raw.([]any); !ok {
					t.Errorf("%q is %T, want an array", key, raw)
				}
			}

			if _, ok := m["summary"].(map[string]any); !ok {
				t.Errorf("summary is %T, want an object", m["summary"])
			}
			if _, ok := m["meta"].(map[string]any); !ok {
				t.Errorf("meta is %T, want an object", m["meta"])
			}

			// A trailing newline is part of the contract (the comment on
			// Encoder.Encode says so); a golden would catch its loss, but
			// asserting it here says why it matters.
			if !bytes.HasSuffix(b, []byte("\n")) {
				t.Error("JSON output does not end with a newline")
			}
		})
	}
}

// TestJSONEmptyArraysAreNotNull pins the exact bytes for the empty case, since
// `null` and `[]` are the same to a human and different to a program.
func TestJSONEmptyArraysAreNotNull(t *testing.T) {
	b, err := MarshalJSON(fixtureShip())
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	for _, key := range []string{"blockers", "conditions", "notes", "undetermined"} {
		if bytes.Contains(b, []byte(`"`+key+`": null`)) {
			t.Errorf("%q rendered as null; it must be []", key)
		}
		if !bytes.Contains(b, []byte(`"`+key+`": []`)) {
			t.Errorf("%q did not render as []; the empty-array contract is not held", key)
		}
	}
}

// ─── SARIF 2.1.0 ────────────────────────────────────────────────────────────

func TestSARIFStructure(t *testing.T) {
	for _, fx := range allFixtures() {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			b, err := MarshalSARIF(fx.v)
			if err != nil {
				t.Fatalf("MarshalSARIF: %v", err)
			}

			// Wire-level field names first: these are the names GitHub reads.
			raw := jsonMap(t, b)
			if got := raw["$schema"]; got != SARIFSchema {
				t.Errorf("$schema = %v, want %q", got, SARIFSchema)
			}
			if got := raw["version"]; got != SARIFVersion {
				t.Errorf("version = %v, want %q", got, SARIFVersion)
			}
			runsRaw, ok := raw["runs"].([]any)
			if !ok || len(runsRaw) != 1 {
				t.Fatalf("runs = %T with %d entries, want exactly one", raw["runs"], len(runsRaw))
			}

			// Typed decode for the relational assertions.
			var doc sarifLog
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatalf("decode into sarifLog: %v", err)
			}
			run := doc.Runs[0]
			if run.Tool.Driver.Name != "clearance" {
				t.Errorf("driver.name = %q, want clearance", run.Tool.Driver.Name)
			}
			if run.Tool.Driver.Version == "" {
				t.Error("driver.version is empty; SARIF requires a non-empty version")
			}
			if run.Tool.Driver.InformationURI == "" {
				t.Error("driver.informationUri is empty")
			}

			// Rules must be declared before they are referenced, and sorted so
			// a consumer diffing runs sees an empty diff.
			ruleIndex := map[string]int{}
			for i, r := range run.Tool.Driver.Rules {
				if r.ID == "" {
					t.Errorf("rules[%d] has an empty id", i)
				}
				if r.Name == "" {
					t.Errorf("rule %q has an empty name", r.ID)
				}
				if r.ShortDescription.Text == "" {
					t.Errorf("rule %q has an empty shortDescription.text", r.ID)
				}
				if r.HelpURI == "" {
					t.Errorf("rule %q has an empty helpUri", r.ID)
				}
				if i > 0 && run.Tool.Driver.Rules[i-1].ID >= r.ID {
					t.Errorf("rules are not sorted by id: %q then %q",
						run.Tool.Driver.Rules[i-1].ID, r.ID)
				}
				if _, dup := ruleIndex[r.ID]; dup {
					t.Errorf("rule %q is declared twice", r.ID)
				}
				ruleIndex[r.ID] = i
			}

			levels := map[string]bool{"error": true, "warning": true, "note": true, "none": true}
			for i, res := range run.Results {
				idx, ok := ruleIndex[res.RuleID]
				if !ok {
					t.Errorf("results[%d].ruleId %q has no matching rule", i, res.RuleID)
					continue
				}
				if res.RuleIndex != idx {
					t.Errorf("results[%d].ruleIndex = %d, want %d (rule %q)",
						i, res.RuleIndex, idx, res.RuleID)
				}
				if !levels[res.Level] {
					t.Errorf("results[%d].level = %q, not a SARIF level", i, res.Level)
				}
				if res.Message.Text == "" {
					t.Errorf("results[%d] has an empty message", i)
				}
				// A location, when present, must name a non-empty relative URI.
				for j, loc := range res.Locations {
					uri := loc.PhysicalLocation.ArtifactLocation.URI
					if uri == "" {
						t.Errorf("results[%d].locations[%d] has an empty uri", i, j)
					}
					if strings.HasPrefix(uri, "/") || strings.Contains(uri, "\\") {
						t.Errorf("results[%d].locations[%d].uri = %q, not a relative forward-slashed path", i, j, uri)
					}
					if reg := loc.PhysicalLocation.Region; reg != nil && reg.StartLine <= 0 {
						t.Errorf("results[%d].locations[%d] has a region with startLine %d", i, j, reg.StartLine)
					}
				}
			}
		})
	}
}

// TestSARIFLevelsMatchTheBand pins the §4 mapping: a blocker is `error`, a
// condition is `warning`, a note is `note`.
//
// The expected level is derived from the band each finding actually sits in —
// not from its declared severity — because the confidence gate moves findings
// between bands. The conditional fixture is the case that matters: its LOW
// BLOCK sits in Notes, so it must be `note` even though its declared severity
// is BLOCK. Asserting "every conditional-fixture result is warning" would be
// asserting the gate does not work.
func TestSARIFLevelsMatchTheBand(t *testing.T) {
	bandLevel := map[policy.Severity]string{
		policy.SeverityBlock:     "error",
		policy.SeverityCondition: "warning",
		policy.SeverityNote:      "note",
	}

	for _, fx := range allFixtures() {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			want := map[string]string{}
			for band, fs := range map[policy.Severity][]policy.Finding{
				policy.SeverityBlock:     fx.v.Blockers,
				policy.SeverityCondition: fx.v.Conditions,
				policy.SeverityNote:      fx.v.Notes,
			} {
				for _, f := range fs {
					want[f.Kind] = bandLevel[band]
				}
			}
			for _, r := range sarifResults(fx.v) {
				exp, ok := want[r.RuleID]
				if !ok {
					continue // an undetermined result; checked separately below
				}
				if r.Level != exp {
					t.Errorf("result %q has level %q, want %q (band the finding sits in)",
						r.RuleID, r.Level, exp)
				}
			}
		})
	}
}

// TestSARIFLevelsAreTotal covers the specific fixtures whose level the band
// mapping must get right, including the gated case.
func TestSARIFLevelsAreTotal(t *testing.T) {
	// Every blocker in the blocked fixture is an error.
	for _, r := range sarifResults(fixtureBlocked()) {
		if r.RuleID == "copyleft.network" && r.Level != "error" {
			t.Errorf("blocker rule %q level = %q, want error", r.RuleID, r.Level)
		}
	}

	// The conditional fixture's gated LOW finding must be a note, not a
	// warning, because Fold placed it in Notes.
	for _, r := range sarifResults(fixtureConditional()) {
		if r.RuleID == "licence.ambiguous" && r.Level != "note" {
			t.Errorf("gated LOW rule %q level = %q, want note", r.RuleID, r.Level)
		}
	}

	// An undetermined entry is a warning with its own rule id — never the
	// condition rule, so dismissing one cannot dismiss the other (INV-7).
	und := sarifResults(fixtureUndetermined())
	if len(und) != 2 {
		t.Fatalf("undetermined fixture produced %d results, want 2", len(und))
	}
	for _, r := range und {
		if r.Level != "warning" {
			t.Errorf("undetermined result %q has level %q, want warning", r.RuleID, r.Level)
		}
		if !strings.HasPrefix(r.RuleID, "clearance.undetermined.") {
			t.Errorf("undetermined result ruleId = %q, want the clearance.undetermined.* namespace", r.RuleID)
		}
	}
	if und[0].RuleID == und[1].RuleID {
		t.Errorf("two undetermined entries share ruleId %q; distinct reasons need distinct rules", und[0].RuleID)
	}
}

// ─── CycloneDX 1.5 ──────────────────────────────────────────────────────────

func TestCycloneDXStructure(t *testing.T) {
	for _, fx := range allFixtures() {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			g := graphFor(fx.name)
			b, err := MarshalCycloneDX(fx.v, g)
			if err != nil {
				t.Fatalf("MarshalCycloneDX: %v", err)
			}

			raw := jsonMap(t, b)
			if got := raw["bomFormat"]; got != "CycloneDX" {
				t.Errorf("bomFormat = %v, want CycloneDX", got)
			}
			if got := raw["specVersion"]; got != "1.5" {
				t.Errorf("specVersion = %v, want 1.5", got)
			}
			serial, _ := raw["serialNumber"].(string)
			if !strings.HasPrefix(serial, "urn:uuid:") {
				t.Errorf("serialNumber = %q, want a urn:uuid: prefix", serial)
			}
			if !isUUIDShaped(strings.TrimPrefix(serial, "urn:uuid:")) {
				t.Errorf("serialNumber %q is not UUID-shaped", serial)
			}
			if raw["version"] != float64(1) {
				t.Errorf("version = %v, want 1", raw["version"])
			}

			var doc cdxBOM
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatalf("decode into cdxBOM: %v", err)
			}
			if len(doc.Metadata.Tools) == 0 || doc.Metadata.Tools[0].Name != "clearance" {
				t.Errorf("metadata.tools = %+v, want a clearance entry", doc.Metadata.Tools)
			}
			if doc.Metadata.Component.Type != "application" {
				t.Errorf("metadata.component.type = %q, want application", doc.Metadata.Component.Type)
			}
			if doc.Metadata.Component.Name == "" {
				t.Error("metadata.component.name is empty")
			}

			// Every component must be addressable and uniquely identified.
			refs := map[string]bool{}
			for i, c := range doc.Components {
				if c.BOMRef == "" {
					t.Errorf("components[%d] has an empty bom-ref", i)
				}
				if c.Name == "" {
					t.Errorf("components[%d] (%s) has an empty name", i, c.BOMRef)
				}
				if c.Type == "" {
					t.Errorf("components[%d] (%s) has an empty type", i, c.BOMRef)
				}
				if refs[c.BOMRef] {
					t.Errorf("bom-ref %q appears twice", c.BOMRef)
				}
				refs[c.BOMRef] = true
			}

			// Every dependency link must name the root or a real component.
			for i, d := range doc.Dependencies {
				if d.Ref != doc.Metadata.Component.Name && !refs[d.Ref] {
					t.Errorf("dependencies[%d].ref = %q, which is neither the root nor a component", i, d.Ref)
				}
				for _, dep := range d.DependsOn {
					if !refs[dep] {
						t.Errorf("dependencies[%d] dependsOn %q, which is not a component", i, dep)
					}
				}
			}

			// The document-level verdict property is the reason the export
			// exists; losing it would make the SBOM say nothing about shipping.
			if !hasProperty(doc.Properties, "clearance:verdict", string(fx.v.Verdict)) {
				t.Errorf("document properties do not carry clearance:verdict = %q", fx.v.Verdict)
			}
		})
	}
}

// TestCycloneDXComponentTypes pins the type mapping, including the reason this
// exporter exists: a weight file is a machine-learning-model, not a library.
func TestCycloneDXComponentTypes(t *testing.T) {
	b, err := MarshalCycloneDX(fixtureBlocked(), graphFor("blocked"))
	if err != nil {
		t.Fatalf("MarshalCycloneDX: %v", err)
	}
	var doc cdxBOM
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	types := map[string]string{}
	for _, c := range doc.Components {
		types[c.BOMRef] = c.Type
	}
	want := map[string]string{
		"weights:models/llama-3.1-8b.bin": "machine-learning-model",
		"npm:some-agpl-lib@3.0.0":         "library",
	}
	for ref, wantType := range want {
		if got := types[ref]; got != wantType {
			t.Errorf("component %q type = %q, want %q", ref, got, wantType)
		}
	}
}

// TestCycloneDXSeverityIsEffective pins the join: the component for a blocked
// dependency must carry BLOCK, and a component no finding touches must carry no
// severity property at all.
func TestCycloneDXSeverityIsEffective(t *testing.T) {
	b, err := MarshalCycloneDX(fixtureBlocked(), graphFor("blocked"))
	if err != nil {
		t.Fatalf("MarshalCycloneDX: %v", err)
	}
	var doc cdxBOM
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, c := range doc.Components {
		switch c.BOMRef {
		case "npm:some-agpl-lib@3.0.0":
			if !hasProperty(c.Properties, "clearance:severity", "BLOCK") {
				t.Errorf("blocked component has no clearance:severity=BLOCK: %+v", c.Properties)
			}
		case "cargo:serde@1.0.0":
			for _, p := range c.Properties {
				if p.Name == "clearance:severity" {
					t.Errorf("clean component %q carries a severity property", c.BOMRef)
				}
			}
		}
	}
}

// ─── SPDX 2.3 ───────────────────────────────────────────────────────────────

func TestSPDXStructure(t *testing.T) {
	spdxIDRe := func(s string) bool {
		if !strings.HasPrefix(s, "SPDXRef-") {
			return false
		}
		for _, r := range strings.TrimPrefix(s, "SPDXRef-") {
			ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '.' || r == '-'
			if !ok {
				return false
			}
		}
		return len(s) > len("SPDXRef-")
	}

	for _, fx := range allFixtures() {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			g := graphFor(fx.name)
			b, err := MarshalSPDX(fx.v, g)
			if err != nil {
				t.Fatalf("MarshalSPDX: %v", err)
			}

			raw := jsonMap(t, b)
			if got := raw["spdxVersion"]; got != "SPDX-2.3" {
				t.Errorf("spdxVersion = %v, want SPDX-2.3", got)
			}
			if got := raw["dataLicense"]; got != "CC0-1.0" {
				t.Errorf("dataLicense = %v, want CC0-1.0", got)
			}
			if got := raw["SPDXID"]; got != "SPDXRef-DOCUMENT" {
				t.Errorf("SPDXID = %v, want SPDXRef-DOCUMENT", got)
			}
			if ns, _ := raw["documentNamespace"].(string); ns == "" {
				t.Error("documentNamespace is empty; SPDX requires one")
			}

			var doc spdxDoc
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatalf("decode into spdxDoc: %v", err)
			}
			if doc.Name == "" {
				t.Error("name is empty")
			}
			if len(doc.CreationInfo.Creators) == 0 {
				t.Error("creationInfo.creators is empty")
			}

			// Every SPDXID must be well-formed and every relationship must
			// point at an element that exists.
			defined := map[string]bool{}
			for i, p := range doc.Packages {
				if !spdxIDRe(p.SPDXID) {
					t.Errorf("packages[%d].SPDXID = %q, not a valid SPDXRef id", i, p.SPDXID)
				}
				if p.Name == "" {
					t.Errorf("packages[%d] (%s) has an empty name", i, p.SPDXID)
				}
				if defined[p.SPDXID] {
					t.Errorf("SPDXID %q is defined twice", p.SPDXID)
				}
				defined[p.SPDXID] = true
			}
			defined[doc.SPDXID] = true

			var describes, contains int
			for i, r := range doc.Relationships {
				if !defined[r.SPDXElementID] {
					t.Errorf("relationships[%d].spdxElementId = %q, which is not defined", i, r.SPDXElementID)
				}
				if !defined[r.RelatedSPDXElement] {
					t.Errorf("relationships[%d].relatedSpdxElement = %q, which is not defined", i, r.RelatedSPDXElement)
				}
				switch r.RelationshipType {
				case "DESCRIBES":
					describes++
				case "CONTAINS":
					contains++
				}
			}
			if describes == 0 {
				t.Error("no DESCRIBES relationship; the document has no subject")
			}
			if contains != len(doc.Packages)-1 {
				t.Errorf("CONTAINS relationships = %d, want one per non-root package (%d)",
					contains, len(doc.Packages)-1)
			}
		})
	}
}

// TestSPDXConcludedLicence pins the declared/concluded pair for the one case
// the corpus knows: a resolved SPDX identifier appears as both, and a licence
// with no SPDX identifier is NOASSERTION with the raw text in the comment.
func TestSPDXConcludedLicence(t *testing.T) {
	b, err := MarshalSPDX(fixtureBlocked(), graphFor("blocked"))
	if err != nil {
		t.Fatalf("MarshalSPDX: %v", err)
	}
	var doc spdxDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, p := range doc.Packages {
		switch p.Name {
		case "some-agpl-lib":
			if p.LicenseConcluded != "AGPL-3.0-only" {
				t.Errorf("some-agpl-lib licenseConcluded = %q, want AGPL-3.0-only", p.LicenseConcluded)
			}
		case "models/llama-3.1-8b.bin":
			if p.LicenseConcluded != "NOASSERTION" {
				t.Errorf("custom-licence package licenseConcluded = %q, want NOASSERTION", p.LicenseConcluded)
			}
			if !strings.Contains(p.Comment, "Llama-3.1-Community") {
				t.Errorf("custom-licence package comment does not name the raw licence: %q", p.Comment)
			}
		}
	}
}

// ─── helpers for the assertions above ───────────────────────────────────────

func hasProperty(props []cdxProperty, name, value string) bool {
	for _, p := range props {
		if p.Name == name && p.Value == value {
			return true
		}
	}
	return false
}

// isUUIDShaped checks 8-4-4-4-12 lowercase hex with the version and variant
// nibbles documentUUID sets.
func isUUIDShaped(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return false
	}
	for i, want := range []int{8, 4, 4, 4, 12} {
		if len(parts[i]) != want {
			return false
		}
		for _, r := range parts[i] {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				return false
			}
		}
	}
	return parts[2][0] == '5' && strings.ContainsRune("89ab", rune(parts[3][0]))
}

// ─── determinism (INV-6) ────────────────────────────────────────────────────

// TestDeterminism renders every fixture twice through every format and asserts
// the bytes are identical. This is the test that pins INV-6 for this package:
// nothing in a renderer may depend on map iteration order, the clock, or any
// other state that differs between two calls on the same input.
func TestDeterminism(t *testing.T) {
	for _, fx := range allFixtures() {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			g := graphFor(fx.name)
			for _, r := range renderers() {
				r := r
				t.Run(r.name, func(t *testing.T) {
					first, err := r.render(fx.v, g)
					if err != nil {
						t.Fatalf("first render: %v", err)
					}
					second, err := r.render(fx.v, g)
					if err != nil {
						t.Fatalf("second render: %v", err)
					}
					if !bytes.Equal(first, second) {
						t.Errorf("render is not deterministic: two calls differ\n--- first ---\n%s\n--- second ---\n%s",
							first, second)
					}
				})
			}
		})
	}
}

// TestDeterministicZeroesTheClock pins the helper's contract: the only two
// non-deterministic fields are zeroed, and everything else is untouched.
func TestDeterministicZeroesTheClock(t *testing.T) {
	v := fixtureBlocked()
	v.Meta.ScannedAt = 1234567890
	v.Meta.DurationMS = 999

	b, err := Deterministic(v)
	if err != nil {
		t.Fatalf("Deterministic: %v", err)
	}
	m := jsonMap(t, b)
	meta, _ := m["meta"].(map[string]any)
	if meta["scanned_at"] != float64(0) {
		t.Errorf("scanned_at = %v, want 0", meta["scanned_at"])
	}
	if meta["duration_ms"] != float64(0) {
		t.Errorf("duration_ms = %v, want 0", meta["duration_ms"])
	}
	// The decision itself must survive: zeroing the clock may not change the
	// verdict.
	if m["verdict"] != string(v.Verdict) {
		t.Errorf("verdict changed to %v; zeroing the clock must not change the decision", m["verdict"])
	}
	// Deterministic must not mutate its argument (it takes Verdict by value).
	if v.Meta.ScannedAt != 1234567890 {
		t.Error("Deterministic mutated its input")
	}
}

// ─── the confidence gate (INV-2) ────────────────────────────────────────────

// TestLowConfidenceNeverBlocks is the product's core invariant, asserted
// through the fold and then through the human rendering.
func TestLowConfidenceNeverBlocks(t *testing.T) {
	low := policy.Finding{
		ID:           "f-low",
		DependencyID: "npm:agpl-thing@1.0.0",
		Kind:         "copyleft.network",
		Severity:     policy.SeverityBlock,
		Confidence:   policy.ConfidenceLow,
		Title:        "Looks like a block, but the tool is not sure",
		Reason:       "The clause is ambiguous.",
		Licence:      "AGPL-3.0-only",
	}

	v := verdict.Fold(verdict.Input{Findings: []policy.Finding{low}})

	if v.Verdict == verdict.DoNotShip {
		t.Fatal("a LOW-confidence BLOCK produced DO NOT SHIP; INV-2 is broken")
	}
	if len(v.Blockers) != 0 {
		t.Errorf("a LOW-confidence finding reached Blockers: %+v", v.Blockers)
	}
	if len(v.Notes) != 1 {
		t.Fatalf("a LOW-confidence finding should be a NOTE; got %d notes", len(v.Notes))
	}

	var buf bytes.Buffer
	if err := WriteHuman(&buf, v, Options{}); err != nil {
		t.Fatalf("WriteHuman: %v", err)
	}
	out := buf.String()

	// The finding must appear under NOTES, not under BLOCKERS.
	if !strings.Contains(out, "NOTES") {
		t.Errorf("the gated finding is not rendered under NOTES:\n%s", out)
	}
	if strings.Contains(out, "\nBLOCKERS\n") {
		t.Errorf("a LOW-confidence finding produced a BLOCKERS section:\n%s", out)
	}

	// The head line carries the DECLARED severity, and the gate line beneath
	// explains why it is filed lower. That pairing is the documented design
	// (see the comment on writeFindings): the tag says what the corpus
	// asserted, the gate says what the tool decided. What must never happen is
	// the gate line going missing, because then a `[BLOCK]` under NOTES reads
	// as a cleared blocker.
	if !strings.Contains(out, "[BLOCK]") {
		t.Errorf("the declared severity is not shown on the head line:\n%s", out)
	}
	if !strings.Contains(out, "severity BLOCK → NOTE because confidence is LOW") {
		t.Errorf("the human renderer did not explain the gate:\n%s", out)
	}
}

// TestMediumConfidenceBecomesCondition pins the middle rung of the gate, and
// that the opt-in flag is the only thing that promotes it back to a blocker.
func TestMediumConfidenceBecomesCondition(t *testing.T) {
	med := policy.Finding{
		ID:           "f-med",
		DependencyID: "pypi:torch@2.4.0",
		Kind:         "network.disclosure",
		Severity:     policy.SeverityBlock,
		Confidence:   policy.ConfidenceMedium,
		Reason:       "Ambiguous clause.",
		Licence:      "BSD-3-Clause",
	}

	v := verdict.Fold(verdict.Input{Findings: []policy.Finding{med}})
	if v.Verdict != verdict.ShipConditional {
		t.Errorf("MEDIUM BLOCK verdict = %q, want SHIP_CONDITIONAL", v.Verdict)
	}
	if len(v.Blockers) != 0 || len(v.Conditions) != 1 {
		t.Errorf("MEDIUM BLOCK placed as blockers=%d conditions=%d, want 0/1",
			len(v.Blockers), len(v.Conditions))
	}

	// The flag exists for callers who accept the ambiguity; there is no
	// equivalent for LOW, which is the point.
	promoted := verdict.Fold(verdict.Input{
		Findings:            []policy.Finding{med},
		AllowMediumBlockers: true,
	})
	if promoted.Verdict != verdict.DoNotShip {
		t.Errorf("with AllowMediumBlockers, verdict = %q, want DO_NOT_SHIP", promoted.Verdict)
	}
}

// TestHighConfidenceBlockStillBlocks is the control for the two tests above: if
// this ever stops producing DO NOT SHIP, the gate has been over-applied.
func TestHighConfidenceBlockStillBlocks(t *testing.T) {
	high := policy.Finding{
		ID:           "f-high",
		DependencyID: "npm:agpl-thing@1.0.0",
		Kind:         "copyleft.network",
		Severity:     policy.SeverityBlock,
		Confidence:   policy.ConfidenceHigh,
		Reason:       "Clear clause.",
		Licence:      "AGPL-3.0-only",
	}
	v := verdict.Fold(verdict.Input{Findings: []policy.Finding{high}})
	if v.Verdict != verdict.DoNotShip {
		t.Errorf("HIGH BLOCK verdict = %q, want DO_NOT_SHIP", v.Verdict)
	}
}

// ─── Write dispatch ─────────────────────────────────────────────────────────

// TestWriteDispatch pins that the single entry point routes to the same bytes
// as the format-specific writer, and refuses a format it does not render.
func TestWriteDispatch(t *testing.T) {
	v := fixtureBlocked()

	cases := []struct {
		format Format
		want   func() ([]byte, error)
	}{
		{FormatHuman, func() ([]byte, error) {
			var b bytes.Buffer
			err := WriteHuman(&b, v, Options{})
			return b.Bytes(), err
		}},
		{FormatMarkdown, func() ([]byte, error) {
			var b bytes.Buffer
			err := WriteMarkdown(&b, v, Options{})
			return b.Bytes(), err
		}},
		{FormatJSON, func() ([]byte, error) { return MarshalJSON(v) }},
		{FormatSARIF, func() ([]byte, error) { return MarshalSARIF(v) }},
	}

	for _, c := range cases {
		var got bytes.Buffer
		if err := Write(&got, v, c.format, Options{}); err != nil {
			t.Errorf("Write(%s): %v", c.format, err)
			continue
		}
		want, err := c.want()
		if err != nil {
			t.Fatalf("reference render for %s: %v", c.format, err)
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Errorf("Write(%s) disagrees with the format-specific writer", c.format)
		}
		if !c.format.Valid() {
			t.Errorf("%s should be Valid", c.format)
		}
	}

	// A format the package cannot render must be refused, not approximated.
	//
	// This pins the CODE and the MESSAGE, not merely "an error occurred". The
	// refusal used to reuse E-RENDER-001, whose message is "Cannot write to
	// '%s': permission denied." — so an unknown format reported a permission
	// problem that had not happened, and a test that asserted only "returns a
	// non-nil error" passed on that wrong message. That is how it survived.
	err := Write(&bytes.Buffer{}, v, Format("yaml"), Options{})
	if err == nil {
		t.Fatal("Write accepted an unknown format; it must refuse rather than approximate")
	}
	var ce *cerr.Error
	if !errors.As(err, &ce) {
		t.Fatalf("Write returned %T, want a *cerr.Error", err)
	}
	if ce.Code() != cerr.ERender007 {
		t.Errorf("Write unknown-format code = %q, want %q", ce.Code(), cerr.ERender007)
	}
	if msg := ce.Error(); !strings.Contains(msg, "Unsupported output format 'yaml'") {
		t.Errorf("Write unknown-format message = %q, want it to name 'yaml' as unsupported", msg)
	}
	if strings.Contains(ce.Error(), "permission denied") {
		t.Errorf("Write unknown-format message claims a permission problem: %q", ce.Error())
	}
}

// TestFormatsAndSBOMFormats pins the closed sets and their order.
func TestFormatsAndSBOMFormats(t *testing.T) {
	want := []Format{FormatHuman, FormatJSON, FormatMarkdown, FormatSARIF}
	got := Formats()
	if len(got) != len(want) {
		t.Fatalf("Formats() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Formats()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	for _, f := range want {
		if !f.Valid() {
			t.Errorf("%q should be Valid", f)
		}
	}
	if Format("yaml").Valid() {
		t.Error(`Format("yaml") should not be Valid`)
	}

	sbom := SBOMFormats()
	if len(sbom) != 2 || sbom[0] != SBOMCycloneDX || sbom[1] != SBOMSPDX {
		t.Errorf("SBOMFormats() = %v, want [cyclonedx spdx]", sbom)
	}
	if SBOMFormat("swid").Valid() {
		t.Error(`SBOMFormat("swid") should not be Valid`)
	}
}

// TestWriteSBOMRejectsUnknownDialect pins that the SBOM entry point refuses a
// dialect it does not export, and refuses it with the documented code and an
// honest message.
//
// This test found a real defect: WriteSBOM used to call
// cerr.New(ERender005, string(f)), but E-RENDER-005's message template takes no
// placeholder, so cerr.New panicked (ArgCount 0 != 1) and the refusal path was
// unreachable. The dialect is now refused under E-RENDER-007 ("Unsupported
// output format '%s'"), which is the code for an unrecognised format — not
// E-RENDER-005, whose meaning is that the SBOM renderer itself failed.
func TestWriteSBOMRejectsUnknownDialect(t *testing.T) {
	err := WriteSBOM(&bytes.Buffer{}, fixtureShip(), graphFor("ship"), SBOMFormat("swid"))
	if err == nil {
		t.Fatal("WriteSBOM accepted an unknown dialect; it must refuse rather than approximate")
	}
	var ce *cerr.Error
	if !errors.As(err, &ce) {
		t.Fatalf("WriteSBOM returned %T, want a *cerr.Error", err)
	}
	if ce.Code() != cerr.ERender007 {
		t.Errorf("WriteSBOM error code = %q, want %q", ce.Code(), cerr.ERender007)
	}
	if msg := ce.Error(); !strings.Contains(msg, "Unsupported output format 'swid'") {
		t.Errorf("WriteSBOM unknown-dialect message = %q, want it to name 'swid' as unsupported", msg)
	}
}
