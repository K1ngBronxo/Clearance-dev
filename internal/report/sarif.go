// The SARIF renderer: the GitHub code-scanning form.
//
// PLAN/02-SPECIFICATIONS/03-verdict-output-spec.md §4 is the contract. SARIF
// 2.1.0, uploaded by the GitHub Action so that findings appear in the Security
// tab and annotate the diff.
//
// # WHY THIS RENDERER IS BUILT DIFFERENTLY FROM THE OTHER TWO
//
// The human and Markdown renderers are read by a person and can be judged by a
// person. A SARIF file is read by a *program* — GitHub's ingestion service —
// and it either parses or it does not. That changes what correctness means:
//
//   - The shape is fixed by an external schema. §4 requires validation against
//     the official schema in CI, and a document that violates it is rejected
//     wholesale: one bad `region` and the entire run is discarded, not just the
//     finding. So this file is conservative to the point of being dull. No
//     optional field is emitted unless the spec asks for it, and nothing is
//     emitted on a guess.
//
//   - Every rule must be declared before it is referenced. SARIF allows a
//     `ruleId` on a result with no matching entry in `tool.driver.rules`, and
//     GitHub then renders the finding with a blank title. The rules array here
//     is therefore derived from the results rather than maintained beside them
//     — see buildSARIFRules — so the two cannot drift.
//
//   - The rule index must match the rules array. SARIF results carry an
//     optional `ruleIndex`; if it is present and wrong, the finding is
//     attributed to the wrong rule. It is emitted here, and it is computed from
//     the same slice it indexes, so it cannot be wrong.
//
// # WHAT THIS RENDERER DELIBERATELY DOES NOT DO
//
// It does not emit `fixes`. SARIF has a fix mechanism and it is tempting,
// because the corpus carries `fix:` blocks. But a SARIF fix is a concrete text
// edit — `artifactChanges` with `replacements` naming a byte range in a file —
// and the corpus's fixes are prose ("swap to crawl4ai"). Emitting prose as a
// machine-applicable patch would produce a fix button in the GitHub UI that
// does nothing, or worse, one that edits the wrong range. The suggestion is
// carried in the message instead, where it is honest.
package report

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// SARIFSchema is the schema URI GitHub expects for 2.1.0. It is a literal from
// the specification, not a URL this tool fetches — INV-3 forbids the tool
// making network requests, and a renderer that fetched its own schema would
// break that on every run.
const SARIFSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// SARIFVersion is the only version this renderer emits.
const SARIFVersion = "2.1.0"

// sarifToolURI is the tool's information URI, used by GitHub to link a finding
// back to the product.
const sarifToolURI = "https://clearance.dev"

// ─── the SARIF object model ─────────────────────────────────────────────────
//
// Only the fields this renderer emits are declared. A struct with a field for
// everything SARIF allows would invite someone to populate one, and every
// additional field is another chance to produce a document the schema rejects.
// What is absent is absent because the spec's §4 example does not contain it.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifText         `json:"shortDescription"`
	FullDescription  *sarifText        `json:"fullDescription,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Help             *sarifText        `json:"help,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

// ─── rendering ──────────────────────────────────────────────────────────────

// WriteSARIF renders the verdict as SARIF 2.1.0.
func WriteSARIF(w io.Writer, v verdict.Verdict) error {
	b, err := MarshalSARIF(v)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// MarshalSARIF builds the SARIF document.
//
// It is separate from WriteSARIF so that TestSARIFValid can validate the bytes
// without a writer, and so that the Action's upload step can hash them.
func MarshalSARIF(v verdict.Verdict) ([]byte, error) {
	// The rules are collected while the results are built, rather than derived
	// from the finished results. A result carries only the message text, and a
	// rule needs three things the message does not have: the finding's own
	// title, the citation URL for helpUri, and the severity/confidence pair the
	// spec's §4 example puts in `properties`. Deriving from the results would
	// mean re-parsing the message to recover facts the verdict still has.
	b := newSARIFBuilder()
	for _, band := range []struct {
		band     sarifBand
		findings []policy.Finding
	}{
		{bandBlocker, v.Blockers},
		{bandCondition, v.Conditions},
		{bandNote, v.Notes},
	} {
		for _, f := range band.findings {
			b.add(f, band.band)
		}
	}
	for _, u := range v.Undetermined {
		b.addUndetermined(u)
	}

	// Rule indices are assigned after the rules array is final, by looking each
	// result's ruleId up in it. Assigning them during construction would make
	// the index depend on the order results happened to be built in.
	index := make(map[string]int, len(b.rules))
	for i, r := range b.rules {
		index[r.ID] = i
	}
	for i := range b.results {
		b.results[i].RuleIndex = index[b.results[i].RuleID]
	}

	version := v.Meta.ToolVersion
	if version == "" {
		// SARIF requires tool.driver.version to be a non-empty string, and
		// GitHub uses it to group runs. An empty one is a schema violation, so
		// the placeholder is the honest fallback rather than omission.
		version = "0.0.0-unknown"
	}

	doc := sarifLog{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "clearance",
				Version:        version,
				InformationURI: sarifToolURI,
				Rules:          b.rules,
			}},
			Results: b.results,
		}},
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// EscapeHTML would rewrite `&` in a citation URL as \u0026. SARIF is JSON,
	// not an HTML fragment, and the URL is rendered as a link by the consumer.
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&doc); err != nil {
		return nil, cerr.Wrap(cerr.ERender002, err)
	}
	return buf.Bytes(), nil
}

// sarifBuilder accumulates results and the rules they reference.
//
// It exists so that the rules array is a by-product of building the results
// rather than a second list kept in step by hand. The failure mode of the
// second list is quiet and specific: add a finding kind to the corpus, forget
// the rule, and GitHub renders the finding with an empty title and no help
// link. Nothing fails; the output just gets worse.
type sarifBuilder struct {
	results []sarifResult
	rules   []sarifRule
	seen    map[string]bool
}

func newSARIFBuilder() *sarifBuilder {
	return &sarifBuilder{seen: map[string]bool{}}
}

// add records one finding and its rule.
func (b *sarifBuilder) add(f policy.Finding, band sarifBand) {
	ruleID := f.Kind
	if ruleID == "" {
		// A finding with no kind cannot be attributed to a rule, and GitHub
		// would show it with a blank title. There is no honest rule id to
		// invent, so the finding is reported under a rule that says exactly
		// what happened.
		ruleID = "clearance.unattributed"
	}

	r := sarifResult{
		RuleID:  ruleID,
		Level:   band.level(),
		Message: sarifText{Text: sarifMessage(f)},
	}
	if loc, ok := sarifLocationFor(f.Evidence); ok {
		r.Locations = []sarifLocation{loc}
	}
	b.results = append(b.results, r)
	b.declareRule(ruleID, sarifRuleFor(f, ruleID, band))
}

// addUndetermined records one unclassified dependency.
func (b *sarifBuilder) addUndetermined(u graph.Undetermined) {
	ruleID := "clearance.undetermined." + u.Reason

	msg := "Unclassified: " + humaniseReason(u.Reason)
	if u.Detail != "" {
		msg += ". " + u.Detail
	}
	msg += ". Clearance does not know whether this is safe, and does not round an unknown to a pass."

	r := sarifResult{
		RuleID:  ruleID,
		Level:   bandCondition.level(),
		Message: sarifText{Text: msg},
	}
	if loc, ok := sarifLocationFor(u.Evidence); ok {
		r.Locations = []sarifLocation{loc}
	}
	b.results = append(b.results, r)

	// §4 maps UNDETERMINED to `warning` with a *distinct* rule id, and the
	// distinctness is the important part: an unknown must not be filed under
	// the same rule as a known condition, or a repository that dismisses the
	// condition rule once would silently dismiss every future unknown too.
	// INV-7 is that an unknown is its own kind of thing, and SARIF's rule
	// vocabulary is where that has to survive.
	b.declareRule(ruleID, sarifRule{
		ID:               ruleID,
		Name:             "Unclassified dependency",
		ShortDescription: sarifText{Text: "Clearance could not classify this dependency"},
		HelpURI:          sarifToolURI + "/docs/undetermined",
		Properties: map[string]string{
			"clearance.reason": u.Reason,
		},
	})
}

// declareRule adds a rule once, keeping the array sorted by id.
//
// Sorted rather than first-seen: first-seen order depends on the verdict's
// finding order, and a SARIF consumer diffs the rules array between runs. A
// stable order keeps that diff empty, which is what makes the Security tab's
// history readable.
func (b *sarifBuilder) declareRule(id string, rule sarifRule) {
	if b.seen[id] {
		return
	}
	b.seen[id] = true
	b.rules = append(b.rules, rule)
	sort.SliceStable(b.rules, func(i, j int) bool { return b.rules[i].ID < b.rules[j].ID })
}

// sarifRuleFor builds a rule from the finding that first referenced it.
//
// §4's example is the model: `id` is the machine key, `name` is the human
// title, `shortDescription` is one line, and `helpUri` is the citation — so a
// developer who clicks the finding in the Security tab lands on the licence
// clause itself. That last one is the whole reason a licence finding is worth
// putting in a code-scanning UI.
func sarifRuleFor(f policy.Finding, ruleID string, band sarifBand) sarifRule {
	name := strings.TrimSpace(f.Title)
	if name == "" {
		name = ruleID
	}

	short := name
	if short == ruleID {
		// The title was absent, so the id is all there is. A shortDescription
		// is required and must be non-empty; the id is a poor description but
		// it is a true one.
		short = ruleID
	}

	r := sarifRule{
		ID:               ruleID,
		Name:             name,
		ShortDescription: sarifText{Text: short},
		Properties:       map[string]string{},
	}
	// From the band, not from f.Severity — see sarifBand.severityName.
	r.Properties["clearance.severity"] = band.severityName()
	if f.Confidence != "" {
		r.Properties["clearance.confidence"] = string(f.Confidence)
	}
	if f.Licence != "" {
		r.Properties["clearance.licence"] = f.Licence
	}
	if f.TrapID != "" {
		r.Properties["clearance.trap"] = f.TrapID
	}
	if f.Citation.URL != "" && isWebURL(f.Citation.URL) {
		r.HelpURI = f.Citation.URL
	}
	if r.HelpURI == "" {
		// GitHub shows the rule without a link otherwise. Pointing at the
		// tool's own explanation is better than a dead end, and it is honest:
		// the finding has no citation URL of its own to offer.
		r.HelpURI = sarifToolURI + "/docs/rules/" + ruleID
	}
	return r
}

// isWebURL reports whether a string is an http(s) URL.
//
// SARIF's `helpUri` must be a URI, and a corpus citation is one only by
// convention — it is data, and the renderer does not trust its data to be
// well-formed. A citation carrying a bare hostname or a filesystem path would
// produce a document the consumer cannot resolve, so those fall back to the
// tool's own page rather than being emitted as a broken link.
func isWebURL(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// sarifBand is the severity band a finding sits in.
//
// It is a closed type rather than a string because the level must be total: §4
// maps four Clearance severities onto four SARIF levels, and a renderer that
// accepted an arbitrary level string would have to decide what to do with one
// it did not recognise. Making the band a type makes the unrecognised case
// unrepresentable, which is better than handling it.
type sarifBand int

const (
	bandBlocker sarifBand = iota
	bandCondition
	bandNote
)

// level maps a band onto §4's SARIF level table.
func (b sarifBand) level() string {
	switch b {
	case bandBlocker:
		return "error"
	case bandCondition:
		return "warning"
	}
	return "note"
}

// severityName is the Clearance severity the band corresponds to.
//
// It exists so that `properties.clearance.severity` and `level` cannot
// disagree. The first version of the rules array took the severity from the
// finding, which is the DECLARED severity — so a MEDIUM-confidence BLOCK came
// out as `"level": "warning"` beside `"clearance.severity": "BLOCK"`, and a
// consumer reading the property would have concluded the verdict blocked when
// it did not. The band is the effective severity; it is the only thing that may
// be reported as one.
func (b sarifBand) severityName() string {
	switch b {
	case bandBlocker:
		return "BLOCK"
	case bandCondition:
		return "CONDITION"
	}
	return "NOTE"
}

// sarifResults flattens the verdict's three finding bands plus the undetermined
// list into SARIF results, without the rules.
//
// The renderer does not use it — MarshalSARIF needs the rules too, and builds
// both together through sarifBuilder — but a test that wants to check the level
// mapping without parsing a document does, and so does anything that wants the
// result list alone.
func sarifResults(v verdict.Verdict) []sarifResult {
	b := newSARIFBuilder()
	for _, band := range []struct {
		band     sarifBand
		findings []policy.Finding
	}{
		{bandBlocker, v.Blockers},
		{bandCondition, v.Conditions},
		{bandNote, v.Notes},
	} {
		for _, f := range band.findings {
			b.add(f, band.band)
		}
	}
	for _, u := range v.Undetermined {
		b.addUndetermined(u)
	}
	return b.results
}

// sarifMessage builds the text GitHub shows in the annotation.
//
// # WHY IT STARTS WITH THE DEPENDENCY, NOT THE TITLE
//
// A SARIF annotation appears inline in a diff, where the surrounding context is
// a line of source. The reader's first question is "what is this about?", so
// the message opens with the dependency and its licence. An earlier version
// opened with the finding's `Title`, which is the obligation's machine name —
// "NETWORK_DISCLOSURE obligation" — and the annotation read as a fragment of a
// database row rather than a sentence about a dependency.
//
// The confidence is appended because §1.2 makes it mandatory in every
// rendering, and it is not decoration here: an annotation that says a licence
// clause applies, without saying how sure the tool is, invites a developer to
// act on a curated summary as though it were the licence text.
func sarifMessage(f policy.Finding) string {
	var b strings.Builder

	b.WriteString(displayName(f.DependencyID))
	if f.Licence != "" {
		b.WriteString(" (")
		b.WriteString(f.Licence)
		b.WriteString(")")
	}
	b.WriteString(": ")

	b.WriteString(f.Reason)

	if f.Confidence != "" {
		b.WriteString(" (confidence: ")
		b.WriteString(string(f.Confidence))
		b.WriteString(")")
	}
	if f.Fix != nil && f.Fix.Suggestion != "" {
		b.WriteString(" Suggested fix: ")
		b.WriteString(f.Fix.Suggestion)
		if f.Fix.Alternative != "" {
			b.WriteString(" (alternative: ")
			b.WriteString(f.Fix.Alternative)
			b.WriteString(")")
		}
	}
	// Collapse whitespace before returning.
	//
	// The reason is assembled from corpus text, and corpus text comes from YAML
	// block scalars — `message: >` — which fold to a string with a trailing
	// newline. That newline is invisible in the human renderer, which wraps the
	// text anyway, but in a SARIF message it becomes a literal line break in
	// the middle of a sentence: the annotation read "…is a distribution.\n
	// (confidence: HIGH)". Legal JSON, ugly annotation, and the kind of defect
	// that only shows up when you look at the output.
	return collapseSpace(b.String())
}

// collapseSpace reduces every run of whitespace to one space and trims the ends.
func collapseSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

// sarifLocationFor converts evidence into a SARIF location.
//
// Returns false when there is nothing to point at. A location with an empty URI
// is a schema violation, and a location pointing at "" would annotate the wrong
// file — so a finding with no evidence is emitted with no location at all. That
// is legal SARIF, and it is the truthful rendering: the tool has nothing to
// point at, which is a bug in the finding rather than a fact about the project.
func sarifLocationFor(ev []graph.Evidence) (sarifLocation, bool) {
	if len(ev) == 0 {
		return sarifLocation{}, false
	}
	e := ev[0]
	uri := sarifURI(e.Path)
	if uri == "" {
		return sarifLocation{}, false
	}

	loc := sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: uri},
		},
	}
	if e.LineStart > 0 {
		region := &sarifRegion{StartLine: e.LineStart}
		if e.LineEnd > e.LineStart {
			region.EndLine = e.LineEnd
		}
		loc.PhysicalLocation.Region = region
	}
	return loc, true
}

// sarifURI normalises an evidence path for SARIF.
//
// SARIF's `uri` is a URI reference and GitHub resolves it relative to the
// repository root, so it must be a relative forward-slashed path. Evidence
// paths are already project-relative (the scanner guarantees it), but they may
// use backslashes on Windows, and a backslash in a URI is invalid.
//
// A path that escapes the root is refused rather than rewritten. The scanner
// should make one impossible (INV-4), and a `../` in a SARIF artifact URI would
// tell GitHub to annotate a file outside the repository — so if one appears, the
// right answer is to drop the location, not to launder it.
func sarifURI(path string) string {
	p := strings.TrimSpace(strings.ReplaceAll(path, "\\", "/"))
	if p == "" {
		return ""
	}
	p = strings.TrimPrefix(p, "./")
	if strings.HasPrefix(p, "/") || p == ".." || strings.HasPrefix(p, "../") ||
		strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
		return ""
	}
	// A URI with a fragment or query would be parsed as such by the consumer.
	if strings.ContainsAny(p, "?#") {
		return ""
	}
	return p
}

// sarifLevelFor maps a Clearance severity to a SARIF level.
//
// It exists for callers that have a severity and not a band — the tests, and
// any future renderer of a finding outside a verdict. The renderer itself reads
// the level from the band, because the band is the effective severity while the
// severity field is the declared one.
func sarifLevelFor(s policy.Severity) string {
	switch s {
	case policy.SeverityBlock:
		return bandBlocker.level()
	case policy.SeverityCondition:
		return bandCondition.level()
	case policy.SeverityNote:
		return bandNote.level()
	}
	return "none"
}
