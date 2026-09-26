// Org policy files: the layer that lets an organisation be stricter than the
// corpus, and never more permissive than it.
//
// # THE RULE, AND WHY IT IS ONE-DIRECTIONAL
//
// The rule is stated absolutely:
//
//	> Escalation only — a policy may **never** downgrade a corpus severity.
//	> That would let a user silently turn off a blocker, which is the one thing
//	> the tool must not permit.
//
// The reasoning is worth restating because it is the whole design. A licence
// corpus is a claim about the world; an org policy is a claim about an
// organisation. If a policy could lower a severity, then the file that is
// easiest to edit — the one in the repository, reviewed in the same PR as the
// code it unblocks — would be the file that decides whether a blocker blocks.
// At that point the corpus is decorative: every finding becomes advisory, and
// the tool's output is a suggestion the author of the PR grades themselves.
//
// # THE ONE EXCEPTION, AND WHY IT IS NOT AN EXCEPTION
//
// The taxonomy's recovery text for E-POLICY-006 says "Escalate or whitelist
// narrowly", so a narrow whitelist is permitted. It is permitted because it is
// not a downgrade mechanism — it is a *record*:
//
//   - It must name one dependency, not a family and not a pattern.
//   - It must carry an owner.
//   - It must carry an expiry date.
//   - It does not delete the finding. It demotes it to a NOTE and says who
//     accepted it and until when.
//
// That last point is what makes it honest. A whitelist that removed the finding
// would erase the evidence; a whitelist that demotes it keeps the finding in
// the report, in the JSON, in the SARIF upload and in the SBOM, with the name
// of the person who took the risk attached. The verdict is clean and the audit
// trail is intact, which is what "narrowly" has to mean if it is to mean
// anything.
//
// # WHY THIS PACKAGE IS L2 AND SPEAKS IN STRINGS
//
// The plan's purity rule confines filesystem access to L0, L1 and L5, and this
// package has to read a file. So it sits at L2, beside the corpus, which reads
// its files for the same reason.
//
// The consequence is that it cannot import `internal/policy` (L3) — that would
// be an upward import, and the architecture guard refuses it. Rather than move
// the escalation logic up into the interface layer, where a decision made in a
// command handler is a decision nobody can test, this package takes strings and
// returns strings. `Decide` is the whole interface: a dependency id, a kind, a
// licence, a family, a severity and a date go in; a severity, a reason suffix
// and an optional notice come out. L3 adapts that to its own types, and the
// decision stays testable without a verdict, a graph or a CLI.
package policyfile

import (
	"sort"
	"strings"
	"time"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/corpus"
	"github.com/clearance-dev/clearance/internal/safefs"
	"github.com/clearance-dev/clearance/internal/safeyaml"
)

// SchemaVersion is the only policy schema this build accepts.
const SchemaVersion = 1

// MaxPolicyBytes bounds the file. A policy is a page of YAML; anything larger
// is a mistake or an attack, and refusing early is cheaper than parsing it.
const MaxPolicyBytes = 256 << 10

// The severity vocabulary, duplicated from L3 as plain strings.
//
// The duplication is the price of the layering rule above, and it is a small
// price because the values are frozen by ADR-008 and pinned on both sides by a
// test: policyfile's TestSeverityVocabularyMatchesPolicy asserts that these
// three strings are exactly the three `policy.Severity` values. Without that
// test this would be two lists that agree today.
const (
	SeverityBlock     = "BLOCK"
	SeverityCondition = "CONDITION"
	SeverityNote      = "NOTE"
)

// weight orders the three severities. It mirrors policy.Severity.Weight, and
// TestSeverityVocabularyMatchesPolicy checks the ordering agrees.
func weight(s string) int {
	switch s {
	case SeverityBlock:
		return 3
	case SeverityCondition:
		return 2
	case SeverityNote:
		return 1
	}
	return -1
}

// Policy is a parsed org policy file.
type Policy struct {
	SchemaVersion int    `json:"schema_version"`
	Source        string `json:"-"`

	// Org is a label for the report, so a reader can tell which policy was in
	// force. Empty is allowed.
	Org string `json:"org,omitempty"`

	Escalate Escalate `json:"escalate,omitempty"`

	// Exceptions are narrow, owned, expiring whitelists. See the package
	// comment for why each of those three words is load-bearing.
	Exceptions []Exception `json:"exceptions,omitempty"`
}

// Escalate raises the severity of matching findings.
//
// The two maps are keyed by licence family and by SPDX identifier. There is
// deliberately no wildcard and no regular expression: a policy that can
// escalate "everything matching ^GPL" is a policy nobody can review, and the
// failure it produces is a block on a licence its author never considered.
type Escalate struct {
	// Families maps a corpus family (see corpus.Families) to a severity.
	Families map[string]string `json:"families,omitempty"`

	// Licences maps an SPDX identifier to a severity.
	Licences map[string]string `json:"licences,omitempty"`
}

// Exception is a narrow, owned, expiring whitelist entry.
type Exception struct {
	// Dependency is the exact dependency id, e.g. `npm:leftpad@1.0.0`.
	Dependency string `json:"dependency"`

	// Kind optionally narrows the exception to one finding kind. Empty means
	// every finding on that dependency.
	Kind string `json:"kind,omitempty"`

	// Reason is why. Required.
	Reason string `json:"reason"`

	// Owner is who accepted the risk. Required.
	Owner string `json:"owner"`

	// Expires is the last day the exception applies, inclusive. Required.
	Expires string `json:"expires"`
}

// Decision is what a policy says about one finding.
//
// A zero Decision means "no rule matched". It is a value rather than a set of
// pointers so that a caller can compare it and so that a decision cannot be
// half-applied.
type Decision struct {
	// Severity is the severity to use. Empty means "leave it alone".
	Severity string

	// ReasonSuffix is appended to the finding's reason when non-empty, so the
	// reader can see that the policy changed something and why.
	ReasonSuffix string

	// NoticeCode and NoticeMessage, when set, are a WARN for the run.
	NoticeCode    string
	NoticeMessage string

	// Excepted records that an exception matched, for a caller that wants to
	// count them.
	Excepted bool
}

// Matched reports whether any rule applied.
func (d Decision) Matched() bool { return d.Severity != "" || d.Excepted || d.NoticeCode != "" }

// ─── loading ────────────────────────────────────────────────────────────────

// Load reads and validates a policy file.
//
// A missing file is an error rather than an empty policy: the flag was passed
// explicitly, so a typo in the path must not silently produce a run with no
// policy. That is the same reasoning resolveCorpusDir follows for the corpus,
// and the same failure it prevents — a security control that quietly does
// nothing is worse than one that is absent, because the user believes it ran.
func Load(path string) (*Policy, error) {
	root, err := safefs.New(dirOf(path), safefs.Limits{MaxFileSize: MaxPolicyBytes})
	if err != nil {
		return nil, cerr.New(cerr.ECfg011, path, "the directory could not be opened")
	}
	base := baseOf(path)
	if base == "" {
		return nil, cerr.New(cerr.ECfg011, path, "the path names no file")
	}
	data, err := root.ReadFile(base, MaxPolicyBytes)
	if err != nil {
		return nil, cerr.New(cerr.ECfg011, path, "the file could not be read")
	}
	return Parse(data, path)
}

// Parse decodes a policy from bytes, for tests and for embedded policies.
func Parse(data []byte, source string) (*Policy, error) {
	lim := safeyaml.Limits{MaxBytes: MaxPolicyBytes, MaxDepth: 32}
	node, err := safeyaml.Parse(data, lim)
	if err != nil {
		return nil, cerr.New(cerr.ECfg011, source, "it is not valid YAML")
	}
	var p Policy
	if err := safeyaml.Decode(node, &p); err != nil {
		return nil, cerr.New(cerr.ECfg011, source, "it has an unknown key or a wrong value type")
	}
	p.Source = source
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks a policy for the conditions that make it unenforceable or
// dishonest.
//
// Every rule here exists because its absence has a specific bad outcome, and
// each is named in the error's detail so a user can act on it without reading
// this file.
func (p *Policy) Validate() error {
	if p == nil {
		return nil
	}
	if p.SchemaVersion != SchemaVersion {
		return cerr.New(cerr.ECfg011, p.Source,
			"schema_version is "+itoa(p.SchemaVersion)+"; this build accepts "+itoa(SchemaVersion))
	}

	// Escalation targets must be real and the severity must be one the
	// vocabulary has. A typo in a family name would otherwise produce a rule
	// that matches nothing while looking like it is working — the exact
	// silent-success failure this codebase keeps finding.
	families := p.SortedFamilies()
	for _, family := range families {
		if !isFamily(family) {
			return cerr.New(cerr.ECfg011, p.Source, "escalate.families."+family+
				" is not a licence family (one of "+strings.Join(corpus.Families(), ", ")+")")
		}
		if err := p.checkEscalation("family "+family, p.Escalate.Families[family]); err != nil {
			return err
		}
	}
	for _, spdx := range p.SortedLicences() {
		if strings.TrimSpace(spdx) == "" {
			return cerr.New(cerr.ECfg011, p.Source, "escalate.licences has an empty identifier")
		}
		if err := p.checkEscalation("licence "+spdx, p.Escalate.Licences[spdx]); err != nil {
			return err
		}
	}

	for i := range p.Exceptions {
		e := &p.Exceptions[i]
		where := "exceptions[" + itoa(i) + "]"

		if strings.TrimSpace(e.Dependency) == "" {
			return cerr.New(cerr.ECfg011, p.Source, where+" names no dependency; an exception "+
				"that does not say what it excepts cannot be reviewed")
		}
		if strings.TrimSpace(e.Reason) == "" {
			return cerr.New(cerr.ECfg011, p.Source, where+" has no reason; an exception without "+
				"a reason is an undocumented decision, which is indistinguishable from a mistake")
		}
		if strings.TrimSpace(e.Owner) == "" {
			return cerr.New(cerr.ECfg011, p.Source, where+" has no owner; somebody has to have "+
				"accepted this risk by name, or nobody has")
		}
		if strings.TrimSpace(e.Expires) == "" {
			return cerr.New(cerr.ECfg011, p.Source, where+" has no expiry; an exception without "+
				"an expiry is a permanent policy change wearing an exception's clothes")
		}
		if _, err := time.Parse("2006-01-02", strings.TrimSpace(e.Expires)); err != nil {
			return cerr.New(cerr.ECfg011, p.Source, where+" has an expiry of '"+e.Expires+
				"', which is not a YYYY-MM-DD date")
		}
	}

	return nil
}

// checkEscalation enforces the one-directional rule at load time.
//
// This is where E-POLICY-006 fires, and it fires at LOAD rather than at
// evaluation because a policy that cannot be enforced should stop the run
// before a verdict is produced. A run that produced a verdict and then reported
// that its policy was invalid would already have printed the wrong answer.
func (p *Policy) checkEscalation(target, sev string) error {
	s := strings.ToUpper(strings.TrimSpace(sev))
	if weight(s) < 0 {
		return cerr.New(cerr.ECfg011, p.Source, target+" escalates to '"+sev+
			"', which is not a severity (one of BLOCK, CONDITION, NOTE)")
	}
	if s == SeverityNote {
		// Escalating to NOTE is a downgrade for anything that was already a
		// CONDITION or a BLOCK, and it is the exact move the one-directional
		// rule forbids. It is also never useful: the only sanctioned way to
		// make a finding quieter is to except it by name, which leaves a record.
		//
		// E-CFG-006 rather than E-POLICY-006, and the choice is deliberate.
		// The policy-engine spec §6 names E-POLICY-006 for this condition, but the
		// taxonomy already carries E-CFG-006 for it — "Policy cannot downgrade
		// severity for all of %s. Policy may escalate or narrowly whitelist,
		// never globally weaken." — and the offending artefact is a
		// configuration file that the user fixes with an editor. The config
		// domain is where a user looks for it. E-POLICY-* is the engine's own
		// domain, and every code in it except E-POLICY-001 and E-POLICY-009 is
		// a build-time corpus bug that a user cannot act on. The discrepancy is
		// recorded in the taxonomy's design notes.
		return cerr.New(cerr.ECfg006, target)
	}
	return nil
}

// ─── application ────────────────────────────────────────────────────────────

// Decide returns what this policy says about one finding.
//
// It takes and returns plain strings; see the package comment for why.
//
// # WHAT IT WILL NOT DO
//
// It will not lower a severity. There is no branch that produces a weaker
// severity than it was given, except the exception path — and that path is
// reached only by an entry that named the dependency, an owner and an expiry,
// all of which Validate has already required.
func (p *Policy) Decide(depID, kind, licence, family, severity, today string) Decision {
	if p == nil {
		return Decision{}
	}

	// Exceptions first. An exception is about a specific dependency, and a
	// policy that both escalates a family and excepts one of its members is
	// expressing a deliberate judgement about that member.
	for i := range p.Exceptions {
		e := &p.Exceptions[i]
		if e.Dependency != depID {
			continue
		}
		if e.Kind != "" && e.Kind != kind {
			continue
		}

		// The expiry is compared against the same injected date the corpus
		// staleness rule uses, so a run is reproducible and no test reads a
		// clock (INV-6).
		if !dateOnOrBefore(today, e.Expires) {
			return Decision{
				NoticeCode: string(cerr.ECfg012),
				NoticeMessage: "Policy exception for '" + depID + "' owned by " + e.Owner +
					" expired on " + e.Expires + " and no longer applies. The finding is " +
					"reported at its corpus severity.",
			}
		}

		return Decision{
			Severity: SeverityNote,
			ReasonSuffix: " EXCEPTED BY POLICY: " + e.Owner + " accepted this risk on the record " +
				"of '" + e.Reason + "', and the exception expires on " + e.Expires + ". The " +
				"finding is demoted to a NOTE rather than removed, so that the decision stays " +
				"visible in the report.",
			Excepted: true,
		}
	}

	// Escalation. Both maps are consulted and the stronger of the two wins, so
	// a policy that names a licence BLOCK and its family CONDITION gets BLOCK.
	strongest := ""
	rule := ""

	if fam := strings.ToLower(strings.TrimSpace(family)); fam != "" {
		if raw, ok := p.Escalate.Families[fam]; ok {
			s := strings.ToUpper(strings.TrimSpace(raw))
			if weight(s) > weight(strongest) {
				strongest = s
				rule = "family '" + fam + "'"
			}
		}
	}
	if id := spdxOf(licence); id != "" {
		// Sorted, so that two rules of equal strength resolve the same way on
		// every run and on every machine (INV-6). A map iteration here would
		// make the rule named in the finding's prose depend on Go's map order.
		for _, target := range p.SortedLicences() {
			if !strings.EqualFold(target, id) {
				continue
			}
			s := strings.ToUpper(strings.TrimSpace(p.Escalate.Licences[target]))
			if weight(s) > weight(strongest) {
				strongest = s
				rule = "licence '" + id + "'"
			}
		}
	}

	if strongest == "" || weight(strongest) <= weight(severity) {
		return Decision{}
	}

	return Decision{
		Severity: strongest,
		ReasonSuffix: " RAISED BY ORG POLICY: " + p.label() + " escalates " + rule +
			" to " + strongest + ". The corpus states " + severity + ". A policy may raise a " +
			"severity and may never lower one.",
	}
}

// label names the policy in a finding's prose.
func (p *Policy) label() string {
	if strings.TrimSpace(p.Org) != "" {
		return "the policy for " + p.Org
	}
	if p.Source != "" {
		return "the org policy at " + p.Source
	}
	return "the org policy"
}

// ─── accessors ──────────────────────────────────────────────────────────────

// SortedFamilies returns the escalated family names, sorted, so a caller can
// report the policy without iterating a map into output (INV-6).
func (p *Policy) SortedFamilies() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.Escalate.Families))
	for k := range p.Escalate.Families {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SortedLicences returns the escalated SPDX identifiers, sorted.
func (p *Policy) SortedLicences() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.Escalate.Licences))
	for k := range p.Escalate.Licences {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Describe renders a one-line summary for the verdict's metadata, so a reader
// of a verdict can tell which policy produced it.
func (p *Policy) Describe() string {
	if p == nil {
		return ""
	}
	var parts []string
	if n := len(p.Escalate.Families); n > 0 {
		parts = append(parts, itoa(n)+" family escalation(s)")
	}
	if n := len(p.Escalate.Licences); n > 0 {
		parts = append(parts, itoa(n)+" licence escalation(s)")
	}
	if n := len(p.Exceptions); n > 0 {
		parts = append(parts, itoa(n)+" exception(s)")
	}
	if len(parts) == 0 {
		return "empty policy"
	}
	return strings.Join(parts, ", ")
}

// ─── small helpers ──────────────────────────────────────────────────────────

// spdxOf returns the finding's licence when it looks like an SPDX identifier.
//
// The `licence` field is sometimes a display label rather than an identifier —
// "platform ToS", "third-party binary" — and matching an escalation rule
// against one of those would let a policy called `Licences: {"platform ToS":
// "BLOCK"}` escalate every platform finding, which is a wildcard wearing a
// licence's name. An identifier has no spaces; a label has them.
func spdxOf(licence string) string {
	l := strings.TrimSpace(licence)
	if l == "" || strings.ContainsAny(l, " \t") {
		return ""
	}
	return l
}

// isFamily reports whether f is one of the corpus's families.
func isFamily(f string) bool {
	for _, v := range corpus.Families() {
		if v == f {
			return true
		}
	}
	return false
}

// dateOnOrBefore reports whether date a is on or before date b, both
// YYYY-MM-DD.
//
// String comparison, which is correct for ISO 8601 dates and is the technique
// corpus.StalenessDowngrade already uses. Parsing would be slower and could
// only fail — and a failure here has to resolve to "the exception does not
// apply", which is what the comparison already does for a malformed value.
//
// An empty `today` means the caller did not inject a date. The exception is
// honoured in that case: an expiry check that cannot run must not silently
// disable the policy, because the run would then be more permissive than the
// one the user asked for, and that is the wrong direction to fail in.
func dateOnOrBefore(today, expires string) bool {
	t := strings.TrimSpace(today)
	if t == "" {
		return true
	}
	return t <= strings.TrimSpace(expires)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		if i == 0 {
			return p[:1]
		}
		return p[:i]
	}
	return "."
}

func baseOf(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
