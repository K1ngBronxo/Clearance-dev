// SBOM export: CycloneDX 1.5 and SPDX 2.3.
//
// The framing is the important part:
//
//	> An SBOM is an *input* to a verdict, not the output.
//
// Clearance does not compete with Syft, CycloneDX or SPDX. It reads a
// dependency graph and it exports one. What makes the export worth having is
// the `properties` array: an ordinary SBOM says *what* is in the build, and
// these say *whether you may ship it*.
//
// # THE RULE THIS FILE OBEYS
//
// An exporter adds no facts. Every component comes from the graph, every
// verdict field comes from the verdict, and the join between them is by
// dependency id. If a value cannot be read out of one of the two inputs it is
// omitted — never inferred. That is the same rule the statement renderer
// follows, and for the same reason: an export that could contain a fact the
// verdict does not is an export that can disagree with the verdict.
//
// # DETERMINISM
//
// INV-6 applies here as much as anywhere. The two obvious sources of
// non-determinism are the serial number and the timestamp:
//
//   - CycloneDX's `serialNumber` is a `urn:uuid:`, and the spec's example shows
//     a random one. A random one would make two runs on identical input produce
//     different bytes, so the UUID here is derived from the content instead —
//     see documentUUID. It is a real UUID, it is stable, and it changes when
//     the content changes, which is what a serial number is for.
//   - `timestamp` is read from `Meta.ScannedAt`, which the interface layer
//     injects. The exporter never reads the clock; a renderer that called
//     time.Now() would be a renderer that produced a different document every
//     second, and would also be a renderer that could not be tested.
package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// SBOMFormat names an SBOM dialect.
type SBOMFormat string

const (
	// SBOMCycloneDX is CycloneDX 1.5, the MVP export (§2).
	SBOMCycloneDX SBOMFormat = "cyclonedx"
	// SBOMSPDX is SPDX 2.3 JSON (§3).
	SBOMSPDX SBOMFormat = "spdx"
)

// Valid reports whether f is a dialect this build exports.
func (f SBOMFormat) Valid() bool {
	return f == SBOMCycloneDX || f == SBOMSPDX
}

// SBOMFormats lists every dialect, for the usage text and for flag validation.
func SBOMFormats() []SBOMFormat { return []SBOMFormat{SBOMCycloneDX, SBOMSPDX} }

// WriteSBOM renders the graph and verdict as an SBOM in dialect f.
func WriteSBOM(w io.Writer, v verdict.Verdict, g *graph.Graph, f SBOMFormat) error {
	switch f {
	case SBOMCycloneDX:
		return WriteCycloneDX(w, v, g)
	case SBOMSPDX:
		return WriteSPDX(w, v, g)
	}
	// An unknown dialect is an unsupported output format, refused under
	// E-RENDER-007 (exit 2) — the same refusal the CLI makes for a bad --sbom,
	// not E-RENDER-005 ("SBOM generation failed"), which would report a
	// renderer bug where the truth is an unrecognised format.
	//
	// The dialect argument is passed because E-RENDER-007's template takes one.
	// E-RENDER-005's takes none, and passing one to it used to panic inside
	// cerr.New (ArgCount 0 != 1), which made this documented refusal path
	// unreachable; TestWriteSBOMRejectsUnknownDialect is what found that.
	return cerr.New(cerr.ERender007, string(f))
}

// ─── the shared component model ─────────────────────────────────────────────

// component is one dependency plus the verdict attached to it.
//
// Both dialects are rendered from this, so that a fix to the join — a finding
// that should attach to a component and does not — is a fix to both. Writing
// the join twice would be writing the same bug twice.
type component struct {
	Dep graph.Dependency

	// Findings are the verdict's findings whose DependencyID matches this
	// dependency. Sorted by (severity weight desc, kind).
	Findings []policy.Finding

	// Undetermined is set when the dependency could not be classified.
	Undetermined *graph.Undetermined
}

// effectiveSeverity is the strongest severity attached to a component, in its
// EFFECTIVE form.
//
// It reads the verdict's bands, not the findings' declared severities, for the
// reason the fixture harness was fixed for: a MEDIUM-confidence BLOCK is
// declared BLOCK and lands in Conditions, and reporting it as a BLOCK here
// would put a block in the SBOM for a verdict that says conditional.
func (c component) effectiveSeverity(v verdict.Verdict) (policy.Severity, bool) {
	bands := []struct {
		severity policy.Severity
		findings []policy.Finding
	}{
		{policy.SeverityBlock, v.Blockers},
		{policy.SeverityCondition, v.Conditions},
		{policy.SeverityNote, v.Notes},
	}
	for _, b := range bands {
		for _, f := range b.findings {
			if f.DependencyID == c.Dep.ID {
				return b.severity, true
			}
		}
	}
	return "", false
}

// buildComponents joins the graph to the verdict, in a deterministic order.
func buildComponents(v verdict.Verdict, g *graph.Graph) []component {
	if g == nil {
		return nil
	}

	// An index by dependency id, so the join is O(deps + findings) rather than
	// O(deps × findings). The graph is sorted before the loop, so the output
	// order is the graph's order and not the map's (INV-6).
	byDep := map[string][]policy.Finding{}
	for _, band := range [][]policy.Finding{v.Blockers, v.Conditions, v.Notes} {
		for _, f := range band {
			byDep[f.DependencyID] = append(byDep[f.DependencyID], f)
		}
	}
	unknown := map[string]*graph.Undetermined{}
	for i := range v.Undetermined {
		u := &v.Undetermined[i]
		unknown[u.ID] = u
	}

	deps := append([]graph.Dependency(nil), g.Dependencies...)
	sort.SliceStable(deps, func(i, j int) bool { return deps[i].SortKey() < deps[j].SortKey() })

	out := make([]component, 0, len(deps))
	for _, d := range deps {
		c := component{Dep: d, Findings: byDep[d.ID], Undetermined: unknown[d.ID]}
		sort.SliceStable(c.Findings, func(i, j int) bool {
			if c.Findings[i].Severity.Weight() != c.Findings[j].Severity.Weight() {
				return c.Findings[i].Severity.Weight() > c.Findings[j].Severity.Weight()
			}
			return c.Findings[i].Kind < c.Findings[j].Kind
		})
		out = append(out, c)
	}
	return out
}

// documentUUID derives a stable UUID from the document's content.
//
// CycloneDX requires `serialNumber` to be a `urn:uuid:`, and the spec's example
// shows a random one. A random one would break INV-6 — two runs on identical
// input would differ — and it would also make the export un-diffable, which is
// the main thing anyone does with an SBOM in CI.
//
// The construction is a UUIDv4-shaped value whose 128 bits are the first 16
// bytes of a SHA-256 over the content, with the version and variant nibbles set
// as the RFC requires. It is not a *cryptographic* UUIDv5 (which hashes a
// namespace plus a name); it is a content-addressed identifier wearing the
// format the schema demands, and the difference is stated here rather than
// implied.
//
// The version nibble is set to 5 rather than 4 on purpose: a v4 UUID claims to
// be random, and this one is not.
func documentUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	h := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// componentSeed is the string the document's UUID is derived from.
//
// It covers the project, the corpus version and every component id, so that the
// serial number changes when the build's contents change and not otherwise. It
// deliberately excludes the timestamp: two runs of the same build an hour apart
// are the same build.
func componentSeed(v verdict.Verdict, comps []component) string {
	var b strings.Builder
	b.WriteString("clearance\x00")
	b.WriteString(v.Project)
	b.WriteString("\x00")
	b.WriteString(v.Meta.CorpusVersion)
	b.WriteString("\x00")
	for _, c := range comps {
		b.WriteString(c.Dep.ID)
		b.WriteString("\x00")
	}
	return b.String()
}

// purl builds a Package URL for a dependency, or "" when the ecosystem has no
// purl type.
//
// The purl spec defines a type per ecosystem and the mapping is not guessable:
// npm, pypi, golang, cargo, and *nothing* for a local weight file or a detected
// upstream tool. An invented type would be a broken link in every consumer that
// resolves it, so an unmappable dependency simply carries no purl.
func purl(d graph.Dependency) string {
	var typ string
	switch strings.ToLower(d.Ecosystem) {
	case "npm":
		typ = "npm"
	case "pypi":
		typ = "pypi"
	case "go":
		typ = "golang"
	case "cargo":
		typ = "cargo"
	default:
		return ""
	}
	if d.Name == "" {
		return ""
	}
	p := "pkg:" + typ + "/" + purlEscape(d.Name)
	if d.Version != "" {
		p += "@" + purlEscape(d.Version)
	}
	return p
}

// purlEscape percent-encodes the characters purl forbids in a name or version.
//
// A scoped npm package (`@mendable/firecrawl-js`) is the case that matters: the
// `@` and `/` are legal in the purl name segment as given, but a `%` or a
// space would corrupt the identifier for every consumer downstream.
func purlEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '%' || r == ' ' || r == '#' || r == '?' || r == '[' || r == ']':
			b.WriteString(fmt.Sprintf("%%%02X", r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ─── CycloneDX 1.5 ──────────────────────────────────────────────────────────

type cdxBOM struct {
	BOMFormat    string        `json:"bomFormat"`
	SpecVersion  string        `json:"specVersion"`
	SerialNumber string        `json:"serialNumber"`
	Version      int           `json:"version"`
	Metadata     cdxMetadata   `json:"metadata"`
	Components   []cdxComp     `json:"components"`
	Dependencies []cdxDepLink  `json:"dependencies,omitempty"`
	Properties   []cdxProperty `json:"properties,omitempty"`
}

type cdxMetadata struct {
	Timestamp  string         `json:"timestamp,omitempty"`
	Tools      []cdxTool      `json:"tools"`
	Component  cdxMetaComp    `json:"component"`
	Licenses   []cdxLicenseCh `json:"licenses,omitempty"`
	Properties []cdxProperty  `json:"properties,omitempty"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxMetaComp struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxComp struct {
	Type       string         `json:"type"`
	BOMRef     string         `json:"bom-ref"`
	Name       string         `json:"name"`
	Version    string         `json:"version,omitempty"`
	PURL       string         `json:"purl,omitempty"`
	Licenses   []cdxLicenseCh `json:"licenses,omitempty"`
	Properties []cdxProperty  `json:"properties,omitempty"`
}

// cdxLicenseCh is CycloneDX's license choice. Exactly one of ID and Name is
// set: `id` for an SPDX identifier, `name` for a licence that has none — a
// custom community licence, or a weight file whose licence was written in
// prose. Emitting a `name` that looks like an SPDX id would tell a consumer to
// resolve an identifier that does not exist.
type cdxLicenseCh struct {
	License cdxLicense `json:"license"`
}

type cdxLicense struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxDepLink struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// WriteCycloneDX renders §2.
func WriteCycloneDX(w io.Writer, v verdict.Verdict, g *graph.Graph) error {
	b, err := MarshalCycloneDX(v, g)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// MarshalCycloneDX builds the CycloneDX document.
func MarshalCycloneDX(v verdict.Verdict, g *graph.Graph) ([]byte, error) {
	comps := buildComponents(v, g)

	doc := cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + documentUUID(componentSeed(v, comps)),
		Version:      1,
		Metadata: cdxMetadata{
			Tools: []cdxTool{{
				Vendor:  "Clearance",
				Name:    "clearance",
				Version: toolVersionOrUnknown(v),
			}},
			Component: cdxMetaComp{
				Type:    "application",
				Name:    projectNameOrUnknown(v),
				Version: "0.0.0",
			},
		},
	}

	if ts := timestampFor(v); ts != "" {
		doc.Metadata.Timestamp = ts
	}

	// The corpus version is a property of the document rather than of any
	// component, because it qualifies every verdict in it. A consumer reading
	// `clearance:severity` on a component needs to know which corpus said so.
	if v.Meta.CorpusVersion != "" {
		doc.Metadata.Properties = append(doc.Metadata.Properties, cdxProperty{
			Name: "clearance:corpus-version", Value: v.Meta.CorpusVersion,
		})
		doc.Metadata.Properties = append(doc.Metadata.Properties, cdxProperty{
			Name: "clearance:corpus-signed", Value: boolString(v.Meta.CorpusSigned),
		})
	}
	doc.Properties = append(doc.Properties, cdxProperty{
		Name: "clearance:verdict", Value: string(v.Verdict),
	})
	if v.Meta.IntentHash != "" {
		doc.Properties = append(doc.Properties, cdxProperty{
			Name: "clearance:intent-hash", Value: v.Meta.IntentHash,
		})
	}

	for _, c := range comps {
		doc.Components = append(doc.Components, cdxComponent(c, v))
	}

	// The dependency graph, as one link per component. The root's ref is the
	// project name, matching metadata.component.name, so a consumer can walk
	// from the application down.
	if len(doc.Components) > 0 {
		root := cdxDepLink{Ref: doc.Metadata.Component.Name}
		for _, c := range comps {
			if c.Dep.Direct {
				root.DependsOn = append(root.DependsOn, c.Dep.ID)
			}
		}
		sort.Strings(root.DependsOn)
		doc.Dependencies = append(doc.Dependencies, root)

		for _, c := range comps {
			doc.Dependencies = append(doc.Dependencies, cdxDepLink{Ref: c.Dep.ID})
		}
	}

	return marshalDoc(&doc)
}

// cdxComponent renders one component.
func cdxComponent(c component, v verdict.Verdict) cdxComp {
	out := cdxComp{
		Type:   cdxComponentType(c.Dep.Kind),
		BOMRef: c.Dep.ID,
		Name:   c.Dep.Name,
		PURL:   purl(c.Dep),
	}
	if c.Dep.Version != "" {
		out.Version = c.Dep.Version
	}

	if lic := cdxLicenseFor(c.Dep); lic != nil {
		out.Licenses = []cdxLicenseCh{{License: *lic}}
	}

	out.Properties = append(out.Properties, cdxProperty{
		Name: "clearance:kind", Value: string(c.Dep.Kind),
	})

	if sev, ok := c.effectiveSeverity(v); ok {
		out.Properties = append(out.Properties, cdxProperty{
			Name: "clearance:severity", Value: string(sev),
		})
	}
	// Two different confidences, and they are named apart on purpose.
	//
	// `Licence.Confidence` is how sure the SCANNER is that it identified the
	// licence — it is set by the resolution chain and its values are lowercase
	// ("high", "lockfile-verified"). `Finding.Confidence` is how sure the
	// DECISION layer is that the clause applies — uppercase, and the input to
	// the gate that decides whether a finding may block. Emitting both under
	// the name `clearance:confidence` would tell a consumer that a HIGH
	// licence resolution and a HIGH clause interpretation are the same fact on
	// the same scale, which they are not.
	if c.Dep.Licence.Confidence != "" {
		out.Properties = append(out.Properties, cdxProperty{
			Name:  "clearance:licence-resolution-confidence",
			Value: c.Dep.Licence.Confidence,
		})
	}
	if c.Dep.Licence.Source != "" {
		out.Properties = append(out.Properties, cdxProperty{
			Name: "clearance:licence-source", Value: c.Dep.Licence.Source,
		})
	}
	// The declared-vs-actual distinction is the one SPDX models natively and
	// CycloneDX does not, so here it becomes an explicit property. When the two
	// disagree the disagreement IS the finding, and losing it in the export
	// would lose the point of exporting.
	if declared := c.Dep.Metadata["declared_licence"]; declared != "" {
		out.Properties = append(out.Properties, cdxProperty{
			Name: "clearance:declared-licence", Value: declared,
		})
	}
	if c.Undetermined != nil {
		out.Properties = append(out.Properties, cdxProperty{
			Name: "clearance:undetermined", Value: c.Undetermined.Reason,
		})
	}
	for _, f := range c.Findings {
		out.Properties = append(out.Properties, cdxProperty{
			Name: "clearance:finding-id", Value: f.Kind,
		})
		if f.Confidence != "" {
			out.Properties = append(out.Properties, cdxProperty{
				Name:  "clearance:finding-confidence",
				Value: string(f.Confidence),
			})
		}
		if f.Citation.URL != "" {
			out.Properties = append(out.Properties, cdxProperty{
				Name: "clearance:finding-citation", Value: f.Citation.URL,
			})
		}
	}

	return out
}

// cdxComponentType maps a dependency kind onto a CycloneDX component type.
//
// `machine-learning-model` is the reason this export exists as more than a
// formality: CycloneDX 1.5 added the type, and a weight file is not a library.
// Before that type existed, every SBOM producer had to call a model file a
// library, which is the same category error that makes licence scanners miss
// the licence that actually governs the weights.
//
// An unknown kind maps to `library`, which is CycloneDX's default and the least
// wrong answer, rather than being omitted — a component missing from the SBOM
// is a component the consumer does not know is in the build.
func cdxComponentType(k graph.Kind) string {
	switch k {
	case graph.KindWeights:
		return "machine-learning-model"
	case graph.KindAsset:
		return "data"
	case graph.KindUpstreamCLI:
		// CycloneDX has no "external service" type. `application` is the
		// closest: the thing is a program, it is not in the build, and calling
		// it a library would suggest its code was linked in.
		return "application"
	default:
		return "library"
	}
}

// cdxLicenseFor renders a dependency's licence as a license choice.
//
// Returns nil when nothing is known. An absent `licenses` array says "unknown",
// which is true; an entry saying `{"name": ""}` would be a malformed document.
func cdxLicenseFor(d graph.Dependency) *cdxLicense {
	if !d.Licence.Resolved {
		return nil
	}
	if d.Licence.SPDX != "" {
		return &cdxLicense{ID: d.Licence.SPDX}
	}
	// A licence with no SPDX identifier. `Raw` is what the source said.
	if strings.TrimSpace(d.Licence.Raw) != "" {
		return &cdxLicense{Name: strings.TrimSpace(d.Licence.Raw)}
	}
	return nil
}

// ─── SPDX 2.3 ───────────────────────────────────────────────────────────────

type spdxDoc struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      spdxCreation   `json:"creationInfo"`
	Packages          []spdxPackage  `json:"packages,omitempty"`
	Relationships     []spdxRelation `json:"relationships,omitempty"`
	Comment           string         `json:"comment,omitempty"`
}

type spdxCreation struct {
	Created  string   `json:"created,omitempty"`
	Creators []string `json:"creators"`
	Comment  string   `json:"comment,omitempty"`
}

type spdxPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo,omitempty"`
	DownloadLocation string `json:"downloadLocation"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`

	// The pair that makes SPDX worth exporting to. `declared` is what the
	// manifest said; `concluded` is what Clearance found by reading the file.
	// When they differ, the difference is the finding — which is exactly what
	// the interop spec §3 says.
	LicenseDeclared  string `json:"licenseDeclared"`
	LicenseConcluded string `json:"licenseConcluded"`

	// Comment carries the verdict where a component is blocked or unknown.
	// SPDX has no field for "this component's licence is fine but its platform
	// terms are not", so the sentence goes where a human will read it.
	Comment string `json:"comment,omitempty"`

	ExternalRefs []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelation struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// WriteSPDX renders §3.
func WriteSPDX(w io.Writer, v verdict.Verdict, g *graph.Graph) error {
	b, err := MarshalSPDX(v, g)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// MarshalSPDX builds the SPDX document.
func MarshalSPDX(v verdict.Verdict, g *graph.Graph) ([]byte, error) {
	comps := buildComponents(v, g)
	docID := "SPDXRef-DOCUMENT"
	rootID := "SPDXRef-RootPackage"

	doc := spdxDoc{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            docID,
		Name:              projectNameOrUnknown(v),
		DocumentNamespace: "https://clearance.dev/spdx/" + documentUUID(componentSeed(v, comps)),
		CreationInfo: spdxCreation{
			Creators: []string{
				"Tool: clearance-" + toolVersionOrUnknown(v),
			},
			Comment: "Generated by Clearance. The licence conclusions are readings of " +
				"the published licence text, not legal advice.",
		},
	}
	if ts := timestampFor(v); ts != "" {
		doc.CreationInfo.Created = ts
	}
	if v.Meta.CorpusVersion != "" {
		doc.CreationInfo.Comment += " Corpus v" + v.Meta.CorpusVersion + "."
	}

	// The root package, so the document has a subject. SPDX requires the
	// relationship below to name something that exists.
	doc.Packages = append(doc.Packages, spdxPackage{
		SPDXID:           rootID,
		Name:             projectNameOrUnknown(v),
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		LicenseDeclared:  "NOASSERTION",
		LicenseConcluded: "NOASSERTION",
		Comment:          "Clearance verdict: " + string(v.Verdict),
	})
	doc.Relationships = append(doc.Relationships, spdxRelation{
		SPDXElementID:      docID,
		RelationshipType:   "DESCRIBES",
		RelatedSPDXElement: rootID,
	})

	for i, c := range comps {
		id := spdxIDFor(i, c.Dep.ID)
		doc.Packages = append(doc.Packages, spdxPackage{
			SPDXID:           id,
			Name:             c.Dep.Name,
			VersionInfo:      c.Dep.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseDeclared:  spdxDeclared(c.Dep),
			LicenseConcluded: spdxConcluded(c.Dep),
			Comment:          spdxComment(c, v),
			ExternalRefs:     spdxRefs(c.Dep),
		})
		doc.Relationships = append(doc.Relationships, spdxRelation{
			SPDXElementID:      rootID,
			RelationshipType:   "CONTAINS",
			RelatedSPDXElement: id,
		})
	}

	return marshalDoc(&doc)
}

// spdxIDFor builds an SPDXID.
//
// SPDX requires an SPDXID to match `SPDXRef-[a-zA-Z0-9.-]+`, so a dependency id
// containing `:`, `@` or `/` cannot be used verbatim — and every dependency id
// contains at least one of them. The index keeps the identifier short and
// unique; the dependency's real id goes in the package name's external
// reference, where a consumer can read it.
func spdxIDFor(i int, depID string) string {
	var b strings.Builder
	b.WriteString("SPDXRef-Package-")
	b.WriteString(fmt.Sprintf("%04d", i+1))
	// A short content hash suffix so two exports of the same graph produce the
	// same identifiers even if the order ever changed.
	sum := sha256.Sum256([]byte(depID))
	b.WriteString("-")
	b.WriteString(hex.EncodeToString(sum[:3]))
	return b.String()
}

// spdxDeclared is what the manifest said, or NOASSERTION.
func spdxDeclared(d graph.Dependency) string {
	if v := strings.TrimSpace(d.Metadata["declared_licence"]); v != "" {
		return v
	}
	if d.Licence.Resolved && d.Licence.SPDX != "" {
		// Nothing declared anything different, so the resolved value is also
		// what was declared. Saying NOASSERTION here would imply the manifest
		// was silent, which is not the same fact.
		return d.Licence.SPDX
	}
	return "NOASSERTION"
}

// spdxConcluded is what Clearance found by reading.
//
// A licence with no SPDX identifier cannot be written as one — SPDX's
// `licenseConcluded` accepts `LicenseRef-` identifiers and the special value
// `NOASSERTION`, and inventing an SPDX id for a custom community licence would
// be the fabrication the product exists to avoid. So a non-SPDX licence is
// reported as NOASSERTION and named in the package comment.
func spdxConcluded(d graph.Dependency) string {
	if !d.Licence.Resolved {
		return "NOASSERTION"
	}
	if d.Licence.SPDX != "" {
		return d.Licence.SPDX
	}
	return "NOASSERTION"
}

// spdxComment carries the verdict for a component.
func spdxComment(c component, v verdict.Verdict) string {
	var parts []string

	if raw := strings.TrimSpace(c.Dep.Licence.Raw); raw != "" && c.Dep.Licence.SPDX == "" {
		parts = append(parts, "Licence text: "+raw)
	}
	if c.Undetermined != nil {
		parts = append(parts, "Unclassified ("+c.Undetermined.Reason+"): "+c.Undetermined.Detail)
	}
	if sev, ok := c.effectiveSeverity(v); ok {
		parts = append(parts, "Clearance verdict: "+string(sev))
	}
	for _, f := range c.Findings {
		s := f.Kind
		if f.Citation.URL != "" {
			s += " (" + f.Citation.URL + ")"
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ". ") + "."
}

// spdxRefs emits the purl as an SPDX external reference, which is how a
// consumer resolves a package back to its registry.
func spdxRefs(d graph.Dependency) []spdxExternalRef {
	p := purl(d)
	if p == "" {
		return nil
	}
	return []spdxExternalRef{{
		ReferenceCategory: "PACKAGE-MANAGER",
		ReferenceType:     "purl",
		ReferenceLocator:  p,
	}}
}

// ─── shared helpers ─────────────────────────────────────────────────────────

// marshalDoc encodes any of the export documents with the settings every JSON
// output in this package uses.
func marshalDoc(doc any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, cerr.Wrap(cerr.ERender005, err)
	}
	return buf.Bytes(), nil
}

// timestampFor renders Meta.ScannedAt as RFC 3339, or "" when it is unset.
//
// It returns "" rather than a zero time, because `0001-01-01T00:00:00Z` is a
// lie a consumer would believe. Both dialects make the field optional.
func timestampFor(v verdict.Verdict) string {
	if v.Meta.ScannedAt <= 0 {
		return ""
	}
	return time.Unix(v.Meta.ScannedAt, 0).UTC().Format(time.RFC3339)
}

// toolVersionOrUnknown is the version string for the export documents.
//
// Both dialects require a non-empty creator version, so an unset one is
// reported honestly rather than omitted.
func toolVersionOrUnknown(v verdict.Verdict) string {
	if v.Meta.ToolVersion == "" {
		return "0.0.0-unknown"
	}
	return v.Meta.ToolVersion
}

// projectNameOrUnknown is the document's subject name.
func projectNameOrUnknown(v verdict.Verdict) string {
	if strings.TrimSpace(v.Project) == "" {
		return "unnamed-project"
	}
	return v.Project
}

// boolString renders a bool for a property value, which must be a string.
func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
