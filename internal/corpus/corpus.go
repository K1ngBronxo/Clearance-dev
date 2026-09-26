// Package corpus is the knowledge layer: the licence definitions, the traps,
// the platform terms and the territorial gates, loaded, verified and indexed.
//
// THE CENTRAL ARCHITECTURAL CLAIM OF THE PRODUCT (ADR-003)
//
// All judgement lives in the corpus (data), none in the code. A wrong
// interpretation is fixed by editing YAML, not by shipping a binary. This is
// the moat: a fork can copy the code; a fork cannot sign the corpus.
//
// The consequence in this package is that there is no `if licence == "AGPL"`
// anywhere. The engine asks the corpus what an AGPL dependency obliges, and the
// corpus answers with a predicate, a severity, a citation and a confidence.
package corpus

import (
	"sort"
	"strings"

	"github.com/clearance-dev/clearance/internal/cite"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/expr"
)

// SchemaVersion is the only corpus schema this binary can read. A bundle
// declaring a higher version is refused with E-CORPUS-003, because a corpus
// field this binary does not know about might be one that changes a verdict.
const SchemaVersion = 1

// MaxCorpusBytes bounds the compiled bundle (E-NET-008's 64 MiB, applied
// locally as well so that a corrupt file cannot exhaust memory).
const MaxCorpusBytes = 64 << 20

// Confidence levels. There is no zero value: a corpus entry without a
// confidence fails schema validation rather than defaulting to anything.
const (
	ConfidenceHigh   = "HIGH"
	ConfidenceMedium = "MEDIUM"
	ConfidenceLow    = "LOW"
)

// Severities, ordered by weight.
const (
	SeverityBlock     = "BLOCK"
	SeverityCondition = "CONDITION"
	SeverityNote      = "NOTE"
	SeverityInfo      = "INFO"
)

// Families, the closed set from the corpus schema spec.
const (
	FamilyPermissive      = "permissive"
	FamilyWeakCopyleft    = "weak-copyleft"
	FamilyStrongCopyleft  = "strong-copyleft"
	FamilyNetworkCopyleft = "network-copyleft"
	FamilySourceAvailable = "source-available"
	FamilyNonCommercial   = "non-commercial"
	FamilyCustom          = "custom"
)

// Families returns the closed set.
func Families() []string {
	return []string{
		FamilyPermissive, FamilyWeakCopyleft, FamilyStrongCopyleft,
		FamilyNetworkCopyleft, FamilySourceAvailable, FamilyNonCommercial,
		FamilyCustom,
	}
}

func validFamily(f string) bool {
	for _, v := range Families() {
		if f == v {
			return true
		}
	}
	return false
}

func validConfidence(c string) bool {
	return c == ConfidenceHigh || c == ConfidenceMedium || c == ConfidenceLow
}

func validSeverity(s string) bool {
	switch s {
	case SeverityBlock, SeverityCondition, SeverityNote, SeverityInfo:
		return true
	}
	return false
}

// SeverityWeight orders severities. Higher blocks harder.
func SeverityWeight(s string) int {
	switch s {
	case SeverityBlock:
		return 3
	case SeverityCondition:
		return 2
	case SeverityNote:
		return 1
	case SeverityInfo:
		return 0
	}
	return 0
}

// ConfidenceWeight orders confidence levels. Higher is stronger.
func ConfidenceWeight(c string) int {
	switch c {
	case ConfidenceHigh:
		return 2
	case ConfidenceMedium:
		return 1
	case ConfidenceLow:
		return 0
	}
	return -1
}

// DowngradeConfidence returns the next weaker level. A LOW stays LOW.
func DowngradeConfidence(c string) string {
	switch c {
	case ConfidenceHigh:
		return ConfidenceMedium
	case ConfidenceMedium:
		return ConfidenceLow
	}
	return ConfidenceLow
}

// ── entry types ──────────────────────────────────────────────────────────────

// Fix is a compatible alternative, when one is known.
type Fix struct {
	Action      string `json:"action"` // replace | rebrand | attribute | configure | remove
	Suggestion  string `json:"suggestion"`
	Alternative string `json:"alternative,omitempty"`
	Confidence  string `json:"confidence"`
}

// Obligation is one thing a licence requires, and the condition under which it
// applies.
type Obligation struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Severity   string     `json:"severity"`
	When       *expr.Expr `json:"when"`
	Message    string     `json:"message"`
	Citation   cite.Ref   `json:"citation"`
	Confidence string     `json:"confidence"`
	Fix        *Fix       `json:"fix,omitempty"`

	// EntryID is the licence entry this obligation belongs to. Filled at load.
	EntryID string `json:"-"`
}

// Trap is a documented failure mode. A trap may be attached to one licence
// entry, or be global (a property of the dependency graph rather than of a
// single licence) — the code-vs-weights divergence check is the global case.
// Trap scopes. A trap declares how it is evaluated, because the two ways are
// not interchangeable and the difference cannot be inferred from the predicate.
//
// # WHY THIS IS A DECLARED FIELD AND NOT AN INFERENCE
//
// `trap.code-weights-divergence` carries the predicate
// `dep.kind == weights AND dep.licence.family != permissive`, which reads like a
// perfectly ordinary one-dependency test. It is not one. The finding it exists
// for is a *comparison* — this repository's code is permissive while its weights
// are not — and no single dependency's facts contain that comparison. The
// predicate is only a precondition; the judgement needs the whole scope.
//
// Nothing in the expression says so. A reader cannot tell, and neither can the
// engine, so the trap states it. That is the whole reason the field exists.
const (
	// ScopeDependency means the trap's `when` is evaluated once per dependency,
	// against the same context an obligation uses: dep.*, use.*, and the
	// resolved corpus entry.
	//
	// An absent or empty value is read as this one, so a hand-written corpus is
	// not rejected for omitting the obvious field. The corpus that ships with
	// the binary states it on every trap anyway: this catalogue's one recorded
	// failure was traps that were declared and never evaluated, and "which of
	// these is live" should be answerable by reading a file rather than by
	// knowing a default.
	ScopeDependency = "dependency"

	// ScopeGraph means the trap cannot be decided from one dependency's facts,
	// so internal/policy carries a check for it and looks it up by id. The
	// corpus still supplies the severity, citation and confidence, which is the
	// split internal/policy/crosscheck.go documents: the *shape* of the check is
	// code, the *judgement* is data.
	//
	// A trap declaring this scope must be named by an engine check, and a guard
	// asserts that in both directions. Without the guard an unimplemented graph
	// trap would be silently inert — declared, cited, rendered in the corpus
	// browser, and never evaluated — which is precisely the defect this field
	// was introduced to end.
	ScopeGraph = "graph"
)

// ValidTrapScope reports whether s is a scope the engine understands.
func ValidTrapScope(s string) bool {
	return s == ScopeDependency || s == ScopeGraph
}

// Trap is a documented failure mode.
type Trap struct {
	ID         string     `json:"id"`
	Title      string     `json:"title"`
	Summary    string     `json:"summary"`
	Severity   string     `json:"severity"`
	When       *expr.Expr `json:"when"`
	Citation   cite.Ref   `json:"citation"`
	Confidence string     `json:"confidence"`
	Fix        *Fix       `json:"fix,omitempty"`

	// Scope is how the trap is evaluated: ScopeDependency or ScopeGraph.
	//
	// It is corpus-authored and, since it cannot be inferred, it is checked at
	// load time rather than defaulted silently at evaluation time.
	Scope string `json:"scope,omitempty"`

	// EntryID is empty for a global trap.
	EntryID string `json:"-"`

	// Global marks a trap loaded from corpus/traps/ rather than attached to a
	// licence entry. It is set by the loader and is not a corpus-authored
	// field.
	//
	// It does NOT mean "evaluated against the whole graph" — that is Scope, and
	// the two answer different questions. Every trap in traps/ is Global; only
	// those declaring `scope: graph` are decided by a graph check. An earlier
	// version of this comment said "evaluated against the whole graph", which
	// was read as a promise the engine never kept: nothing evaluated a global
	// trap's `when` at all.
	Global bool `json:"global,omitempty"`
}

// ScopeOf returns the trap's effective scope, resolving the default.
//
// It is nil-safe because the corpus browser and the renderers walk traps that
// may be absent.
func (t *Trap) ScopeOf() string {
	if t == nil || strings.TrimSpace(t.Scope) == "" {
		return ScopeDependency
	}
	return t.Scope
}

// IsGraphScoped reports whether the trap is decided by a graph check rather
// than by its own predicate.
func (t *Trap) IsGraphScoped() bool { return t.ScopeOf() == ScopeGraph }

// Correction records a published confidence upgrade (INV-8).
type Correction struct {
	Reason      string `json:"reason"`
	Evidence    string `json:"evidence"`
	From        string `json:"from"`
	To          string `json:"to"`
	CorrectedAt string `json:"corrected_at"`
	CorrectedBy string `json:"corrected_by"`
}

// Entry is a licence definition.
type Entry struct {
	ID             string       `json:"id"`
	SPDXID         string       `json:"spdx_id"`
	Name           string       `json:"name"`
	Family         string       `json:"family"`
	OSIApproved    bool         `json:"osi_approved"`
	FSFLibre       bool         `json:"fsf_libre"`
	Permissiveness int          `json:"permissiveness"`
	Obligations    []Obligation `json:"obligations"`
	Traps          []Trap       `json:"traps"`
	Citation       cite.Ref     `json:"citation"`
	Confidence     string       `json:"confidence"`
	LastVerified   string       `json:"last_verified"`
	Correction     *Correction  `json:"correction,omitempty"`

	// SourcePath is where this entry was read from, for diagnostics. It is not
	// part of the published payload.
	SourcePath string `json:"-"`
}

// Clause is one restrictive clause of a platform's terms.
//
// When is optional, and its absence means "applies whenever the platform is
// invoked" — because the act of invoking a platform is what inherits its terms
// (PLAN/02-SPECIFICATIONS/06-detection-spec-tos.md §5). A clause carries a
// predicate only when it applies to some uses and not others: an acceptable-use
// clause that bites only on a network-exposed service, say. The distinction is
// the same conditional-obligation model the licence entries use, applied one
// layer out.
type Clause struct {
	ID          string     `json:"id"`
	TextSummary string     `json:"text_summary"`
	Severity    string     `json:"severity"`
	When        *expr.Expr `json:"when,omitempty"`
	Citation    cite.Ref   `json:"citation"`
	Confidence  string     `json:"confidence"`
}

// Detect is how a platform is recognised in a project's source.
//
// # WHY THE SIGNAL LIST IS DATA AND NOT CODE
//
// The scanner reports facts: "this file spawns a process named X", "this file
// fetches https://Y", "this file reads the environment variable Z". What turns
// a fact into a platform is the corpus, because the corpus is the only place
// judgement lives (ADR-003) — and because the alias set is exactly the thing
// that changes when a vendor renames a package.
//
// Every list is optional, and an entry with no Detect block is still reachable
// by its own slug: a platform called `firecrawl` is recognised by the literal
// name `firecrawl` with no configuration at all. Detect exists to catch the
// spellings that do not look like the slug.
type Detect struct {
	// Bins are literal executable names, matched exactly and case-insensitively
	// against a process spawn.
	Bins []string `json:"bins,omitempty"`
	// Runners are names invoked through a package runner (npx, uvx, pipx run,
	// bunx, pnpm dlx). They are separate from Bins because `npx playwright` and
	// `playwright` are the same platform reached two ways, while
	// `npx create-react-app` is a runner invocation of a tool nobody installs.
	Runners []string `json:"runners,omitempty"`
	// Hosts are DNS names, matched against an HTTP URL in source. A subdomain
	// matches its parent: `api.firecrawl.dev` is matched by the host
	// `firecrawl.dev`.
	Hosts []string `json:"hosts,omitempty"`
	// Env are environment-variable names, matched exactly. `FOO_API_KEY` in a
	// .env.example is a declaration that the service is used.
	Env []string `json:"env,omitempty"`
	// Imports are package names, matched against the dependency graph rather
	// than against source text — so `openai` is recognised from
	// `dependencies.openai` in pyproject.toml, which is a fact the parser
	// already established and does not need a second detector to find.
	Imports []string `json:"imports,omitempty"`
	// Images are container images, matched against a Dockerfile FROM.
	Images []string `json:"images,omitempty"`
}

// Kind is what sort of thing a platform is. It is rendered in the finding
// ("firecrawl (hosted API)") and it is why the corpus can carry a binary like
// ffmpeg in the same table as a hosted service.
const (
	PlatformHostedService = "hosted-service"
	PlatformBinary        = "binary"
	PlatformPlatform      = "platform"
)

// ToSEntry is a platform's terms of service, summarised and dated.
type ToSEntry struct {
	Platform string `json:"platform"`
	// DisplayName is what the finding prints. It exists so the corpus can spell
	// "Hugging Face" while the slug stays `huggingface`.
	DisplayName string `json:"display_name"`
	// Kind is one of the Platform* constants. Empty is read as
	// PlatformHostedService, which is the common case.
	Kind    string `json:"kind,omitempty"`
	Summary string `json:"summary"`
	// Detect is how the platform is recognised. See Detect.
	Detect             *Detect  `json:"detect,omitempty"`
	RestrictiveClauses []Clause `json:"restrictive_clauses"`
	LastVerified       string   `json:"last_verified"`
	StalenessDays      int      `json:"staleness_days"`
}

// Gate is a territorial requirement.
type Gate struct {
	ID         string   `json:"id"`
	Summary    string   `json:"summary"`
	Severity   string   `json:"severity"`
	Citation   cite.Ref `json:"citation"`
	Confidence string   `json:"confidence"`
}

// TerritoryEntry is one jurisdiction's overlay on the licence terms.
type TerritoryEntry struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	Notes string `json:"notes"`
	Gates []Gate `json:"gates"`
}

// Notice is a load-time warning that appears in the verdict's notes.
type Notice struct {
	Code    string
	Message string
}

// ── the corpus ───────────────────────────────────────────────────────────────

// Corpus is the loaded, validated, indexed knowledge base.
//
// Every lookup is by a map keyed on a canonical string, and every iteration
// that reaches output goes through a sorted accessor. Nothing here iterates a
// map into a result.
type Corpus struct {
	Version       string
	SchemaVersion int
	BuiltAt       string
	Signed        bool

	// bySPDX is keyed on the normalised upper-case SPDX identifier.
	bySPDX map[string]*Entry

	// entries preserves declaration order for rendering and for the corpus
	// browser, which must be stable.
	entries []*Entry

	// globalTraps are evaluated against the whole graph.
	globalTraps []*Trap

	tos         map[string]*ToSEntry
	territories map[string]*TerritoryEntry

	// Citations is the resolution index for INV-1.
	Citations *cite.Index

	// Notices carries WARN-class findings from the load.
	Notices []Notice

	// ConfidenceRises records entries whose confidence rose relative to a
	// previous corpus version, and whether a correction justified it. Populated
	// only when LoadOptions.Previous was supplied.
	ConfidenceRises []ConfidenceRise
}

// ConfidenceRise is the audit record for one changed confidence level.
type ConfidenceRise struct {
	EntryID       string
	From          string
	To            string
	HasCorrection bool
}

// Resolve looks up a licence entry by SPDX identifier.
//
// It tries the identifier as written, then the canonical spelling, then the
// upper-case form. It never guesses: an identifier the corpus does not carry
// yields (nil, false), and the caller produces UNDETERMINED with E-POLICY-001
// rather than a default (INV-7).
func (c *Corpus) Resolve(spdx string) (*Entry, bool) {
	if c == nil {
		return nil, false
	}
	id := strings.TrimSpace(spdx)
	if id == "" {
		return nil, false
	}
	if e, ok := c.bySPDX[id]; ok {
		return e, true
	}
	norm := config.NormaliseSPDX(id)
	if e, ok := c.bySPDX[norm]; ok {
		return e, true
	}
	if e, ok := c.bySPDX[strings.ToUpper(norm)]; ok {
		return e, true
	}
	return nil, false
}

// Entries returns every licence entry in declaration order.
func (c *Corpus) Entries() []*Entry {
	if c == nil {
		return nil
	}
	return c.entries
}

// GlobalTraps returns the traps evaluated against the whole graph, sorted by ID.
func (c *Corpus) GlobalTraps() []*Trap {
	if c == nil {
		return nil
	}
	return c.globalTraps
}

// ToS looks up a platform's terms by slug.
func (c *Corpus) ToS(platform string) (*ToSEntry, bool) {
	if c == nil {
		return nil, false
	}
	t, ok := c.tos[strings.ToLower(strings.TrimSpace(platform))]
	return t, ok
}

// PlatformFor resolves a detected signal token to a platform's terms.
//
// # THE RESOLUTION ORDER, AND WHY IT IS THIS ORDER
//
//  1. The slug. A token equal to a platform's own name is that platform. This
//     is checked first because it is exact and needs no configuration, which
//     means a corpus that ships no Detect block still works for the common case.
//  2. The signal lists, in the caller's order of specificity.
//
// An empty result is not an error and is not a guess: it means the corpus has
// no terms for this token. The caller turns that into UNDETERMINED, because
// "we found a third-party tool and have no terms for it" is exactly the kind of
// unknown INV-7 forbids rounding to a pass.
//
// The signal argument names which list to consult — "bin", "runner", "host",
// "env", "import", "image" — and a token is never matched against a list it did
// not arrive from. Matching `openai` as a host would be wrong: a project can
// fetch a host called `openai` without depending on the OpenAI SDK, and the two
// inherit the same terms by coincidence rather than by fact.
func (c *Corpus) PlatformFor(token, signal string) (*ToSEntry, bool) {
	if c == nil {
		return nil, false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, false
	}
	if t, ok := c.tos[strings.ToLower(token)]; ok {
		return t, true
	}

	// Iterating the map would be non-deterministic if two entries matched, so
	// the candidate list is built from SortedToSPlatforms and the first match
	// in that order wins. A token claimed by two platforms is a corpus bug, and
	// the loader reports it as a Notice rather than letting load order decide.
	for _, slug := range c.SortedToSPlatforms() {
		t := c.tos[slug]
		if t.Detect == nil {
			continue
		}
		for _, candidate := range tokensFor(t.Detect, signal) {
			if matchToken(token, candidate, signal) {
				return t, true
			}
		}
	}
	return nil, false
}

// tokensFor selects the signal list a token arrived from.
func tokensFor(d *Detect, signal string) []string {
	switch signal {
	case "bin":
		return d.Bins
	case "runner":
		return d.Runners
	case "host":
		return d.Hosts
	case "env":
		return d.Env
	case "import":
		return d.Imports
	case "image":
		return d.Images
	}
	return nil
}

// matchToken applies the comparison rule for one signal kind.
//
// Hosts match on a label boundary, so `firecrawl.dev` matches
// `api.firecrawl.dev` but not `notfirecrawl.dev`. Imports match exactly or as a
// scoped prefix, because `@mendable/firecrawl-js` and `firecrawl-js` are the
// same SDK under two registries' naming conventions. Everything else is an
// exact case-insensitive comparison.
func matchToken(token, candidate, signal string) bool {
	if candidate == "" {
		return false
	}
	token, candidate = strings.ToLower(token), strings.ToLower(candidate)
	switch signal {
	case "host":
		return token == candidate || strings.HasSuffix(token, "."+candidate)
	case "import":
		if token == candidate {
			return true
		}
		// A scoped package: `@scope/name` ends with `/name`.
		if i := strings.LastIndexByte(token, '/'); i >= 0 {
			return token[i+1:] == candidate
		}
		return false
	}
	return token == candidate
}

// Territory looks up a jurisdiction.
func (c *Corpus) Territory(code string) (*TerritoryEntry, bool) {
	if c == nil {
		return nil, false
	}
	t, ok := c.territories[strings.ToUpper(strings.TrimSpace(code))]
	return t, ok
}

// Stats is the self-description `clearance corpus info` prints. Every number is
// computed, never asserted, because "412 clause entries" is a claim the tool
// must be able to substantiate about itself.
type Stats struct {
	Licences    int
	Obligations int
	Traps       int
	ToS         int
	Territories int
	Citations   int
}

// Stats returns the corpus's own counts.
func (c *Corpus) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	s := Stats{
		Licences:    len(c.entries),
		Traps:       len(c.globalTraps),
		ToS:         len(c.tos),
		Territories: len(c.territories),
		Citations:   c.Citations.Len(),
	}
	for _, e := range c.entries {
		s.Obligations += len(e.Obligations)
		s.Traps += len(e.Traps)
	}
	return s
}

// SortedToSPlatforms returns the platform slugs in sorted order.
func (c *Corpus) SortedToSPlatforms() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.tos))
	for k := range c.tos {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SortedTerritoryCodes returns the territory codes in sorted order.
func (c *Corpus) SortedTerritoryCodes() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.territories))
	for k := range c.territories {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SortedSPDXIDs returns every licence identifier in sorted order.
func (c *Corpus) SortedSPDXIDs() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e.SPDXID)
	}
	sort.Strings(out)
	return out
}
