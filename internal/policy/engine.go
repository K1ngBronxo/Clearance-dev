package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/cite"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/corpus"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/obligations"
	"github.com/clearance-dev/clearance/internal/policyfile"
)

// Options are the knobs the interface layer may turn. They are deliberately
// few, and none of them lets a LOW-confidence finding block.
type Options struct {
	// AllowMediumBlockers promotes MEDIUM to blocking for users who want
	// maximum conservatism. There is deliberately no flag that promotes LOW: a
	// LOW confidence is an admission that the tool does not know, and a tool
	// that does not know must not make a decision that costs someone money.
	AllowMediumBlockers bool

	// Today is injected for the ToS staleness rule so that evaluation is
	// deterministic and testable (INV-6).
	Today string

	// OrgPolicy is the organisation's policy file, if one was supplied. Nil
	// means no policy, which is the default and means "the corpus is the only
	// source of judgement".
	//
	// # WHY THIS IS A *policyfile.Policy AND NOT AN INTERFACE
	//
	// An interface here would let a caller substitute any implementation, and
	// the only implementations that make sense are "a policy file" and "none".
	// More importantly, the one-directional rule — a policy may raise a
	// severity and may never lower one — is enforced by policyfile.Validate at
	// load time, and an interface would invite an implementation that skips it.
	// A concrete type whose invariants are checked before it can be constructed
	// is the stronger guarantee.
	//
	// The import is downward: policyfile is L2, this package is L3. policyfile
	// deliberately does not import this package, which is why it speaks in
	// strings; see its package comment.
	OrgPolicy *policyfile.Policy
}

// Evaluation is everything the decision layer produces.
type Evaluation struct {
	Findings     []Finding
	Undetermined []graph.Undetermined

	// Notices carries WARN-class messages from the evaluation itself, plus the
	// corpus's own load-time notices.
	Notices []corpus.Notice

	// Resolved counts how many dependencies had a corpus entry, and
	// Unresolved how many did not. They appear in the verdict summary.
	Resolved   int
	Unresolved int
}

// Evaluate is the whole decision engine: a pure function from a dependency
// graph, a corpus and a declared intent to a set of findings.
//
// It performs no I/O, reads no clock, and iterates no map into a result. Given
// the same three inputs it produces byte-identical findings (INV-6).
func Evaluate(g *graph.Graph, c *corpus.Corpus, in *config.Intent, opts Options) (*Evaluation, error) {
	out := &Evaluation{}

	if g == nil || c == nil || in == nil {
		return out, nil
	}

	// Scanner-level unknowns are carried straight into the verdict.
	//
	// A manifest the scanner could not parse, a path dependency outside the
	// root, a lockfile it refused — these are exactly the "we do not know"
	// cases INV-7 makes first-class. They arrive on the graph, and until this
	// line existed nothing read them: the scanner recorded them faithfully and
	// Evaluate built its own list from scratch, so every scanner-level unknown
	// was silently dropped on the floor.
	//
	// That is the single most dangerous direction for a bug in this product to
	// point. "Could not parse package.json" was becoming "nothing to report",
	// which is a false pass manufactured out of a refusal to guess. The fix is
	// one append, and the guard test is TestScannerUnknownsReachTheVerdict.
	out.Undetermined = append(out.Undetermined, g.Undetermined...)

	// Dependencies are already sorted by the scanner, but sorting here again is
	// cheap and makes this function's determinism independent of its caller.
	deps := append([]graph.Dependency(nil), g.Dependencies...)
	sort.SliceStable(deps, func(i, j int) bool { return deps[i].SortKey() < deps[j].SortKey() })

	// The dependency-scoped slice of the corpus's trap catalogue, gathered once.
	//
	// This is what makes the catalogue live. Until it existed, the only
	// corpus-level traps that could ever produce a finding were the two whose
	// ids crossCheck hardcodes: every other trap in corpus/traps/ was declared,
	// cited, rendered in the corpus browser and never once evaluated, because
	// nothing read its `when`. The corpus's entire documented catalogue of
	// failure modes — the AGPL network service, the BUSL conversion, the SSPL
	// confusion, the LGPL static link — was inert data.
	traps := dependencyScopedTraps(c)

	for _, d := range deps {
		// Kinds whose terms do not come from a licence file are handled by
		// their own layer, and they are skipped here rather than falling
		// through to the resolution branch below.
		//
		// This matters more than it looks. An upstream CLI has no licence to
		// resolve, so before this switch existed every detected `ffmpeg` call
		// would have arrived at the `licence_unresolved` branch and produced an
		// UNDETERMINED record with the message "no licence could be resolved for
		// ffmpeg" — a true sentence about the wrong question, which would have
		// made every project that shells out to anything UNDETERMINED. The
		// platform layer in tos.go asks the right question instead.
		//
		// # WHY ASSET IS NO LONGER IN THE SAME CASE AS UPSTREAM_CLI
		//
		// An asset node has no licence either, so it belongs in this switch —
		// but it is not like an upstream CLI in one respect that decides the
		// whole layer: its terms are a *corpus trap*, decided by its own
		// predicate, and the `continue` that is right for upstream_cli also
		// skipped the trap pass. The brand-asset detector produced a node and
		// nothing ever judged it, so a project that distributed a dependency
		// with a reserved name got no finding, and the trap the corpus ships
		// for exactly that case was inert data. Evaluating the
		// dependency-scoped traps for the kind is what makes it mean something.
		switch d.Kind {
		case graph.KindAsset:
			if err := appendTrapFindings(out, traps, d, &Context{Intent: in, Dep: &d}, opts, c.Citations); err != nil {
				return nil, err
			}
			continue

		case graph.KindUpstreamCLI:
			continue
		}

		ctx := &Context{Intent: in, Dep: &d}

		// A dependency whose licence never resolved cannot be evaluated at all.
		// It is UNDETERMINED with the code that explains why, and it is never
		// rounded to a pass (INV-7).
		if !d.Licence.Resolved || d.Licence.SPDX == "" {
			out.Unresolved++
			out.Undetermined = append(out.Undetermined, graph.Undetermined{
				ID:        d.ID,
				Kind:      d.Kind,
				Reason:    "licence_unresolved",
				Detail:    "no licence could be resolved for " + d.Name + " (raw value: " + rawOrNone(d.Licence.Raw) + ")",
				Evidence:  d.Evidence,
				ErrorCode: string(cerr.EScan011),
			})
			// The trap pass still runs, and here it matters most. "No licence
			// found" is not a gap in the evaluation, it is the fact
			// trap.licence.absent-all-rights-reserved is about — the finding
			// says copyright is granted by default and the honest reading is
			// not "free to use". Skipping this pass for exactly the
			// dependencies it was written for would leave the trap as dead as
			// it was before the pass existed.
			//
			// The verdict does not change: an UNDETERMINED record outranks a
			// condition in the algebra, so the user gets the explanation and
			// still gets "we could not determine this" rather than a pass.
			if err := appendTrapFindings(out, traps, d, ctx, opts, c.Citations); err != nil {
				return nil, err
			}
			continue
		}

		entry, found := c.Resolve(d.Licence.SPDX)
		if !found {
			out.Unresolved++
			out.Undetermined = append(out.Undetermined, graph.Undetermined{
				ID:        d.ID,
				Kind:      d.Kind,
				Reason:    "no_corpus_entry",
				Detail:    "the corpus carries no entry for licence '" + d.Licence.SPDX + "'",
				Evidence:  d.Evidence,
				ErrorCode: string(cerr.EPolicy001),
			})
			out.Notices = append(out.Notices, corpus.Notice{
				Code:    string(cerr.EPolicy001),
				Message: "No corpus entry for licence '" + d.Licence.SPDX + "' (" + d.ID + ").",
			})
			// Same reasoning as above, one case over: the licence is known and
			// the corpus does not describe it, so every field that needs an
			// entry evaluates UNKNOWN. A trap that keys on the identifier alone
			// still applies, and one that keys on the family correctly does not
			// fire.
			if err := appendTrapFindings(out, traps, d, ctx, opts, c.Citations); err != nil {
				return nil, err
			}
			continue
		}
		out.Resolved++

		// Fill the corpus-derived licence facts back onto the dependency, so the
		// cross-dependency checks can compare families without re-resolving.
		d.Licence.Family = entry.Family
		d.Licence.Permissiveness = entry.Permissiveness
		ctx.Entry = entry

		// ── obligations ─────────────────────────────────────────────────────
		for i := range entry.Obligations {
			ob := &entry.Obligations[i]
			res := Eval(ob.When, ctx)
			switch res.Value {
			case TriFalse:
				// The obligation genuinely does not apply. Silence is correct:
				// a finding for every obligation that does not apply would bury
				// the ones that do.
				continue

			case TriTrue:
				f, err := newFinding(d, ob, res, opts, c.Citations)
				if err != nil {
					return nil, err
				}
				out.Findings = append(out.Findings, f)

			case TriUnknown:
				// Cannot determine. The finding is a NOTE at LOW confidence, and
				// the dependency contributes an Undetermined record — so the
				// verdict becomes UNDETERMINED unless a definite blocker
				// outranks it. The tool says "tell me your MAU and I will tell
				// you", which is the honest answer.
				f, err := newUndeterminedFinding(d, ob, res, opts, c.Citations)
				if err != nil {
					return nil, err
				}
				out.Findings = append(out.Findings, f)
				out.Undetermined = append(out.Undetermined, graph.Undetermined{
					ID:        d.ID + "#" + ob.ID,
					Kind:      d.Kind,
					Reason:    "intent_undeclared",
					Detail:    "obligation '" + ob.ID + "' depends on '" + res.UndeclaredField + "', which clearance.config.yml does not declare",
					Evidence:  d.Evidence,
					ErrorCode: string(cerr.EPolicy009),
				})
				out.Notices = append(out.Notices, corpus.Notice{
					Code:    string(cerr.EPolicy009),
					Message: "Cannot determine '" + res.UndeclaredField + "' - declare it in clearance.config.yml for a definitive verdict.",
				})
			}
		}

		// ── traps attached to this entry ────────────────────────────────────
		for i := range entry.Traps {
			tr := &entry.Traps[i]
			res := Eval(tr.When, ctx)
			if res.Value != TriTrue {
				continue
			}
			f, err := newTrapFinding(d, tr, res, opts, c.Citations)
			if err != nil {
				return nil, err
			}
			out.Findings = append(out.Findings, f)
		}

		// ── corpus-level traps evaluated against this dependency ────────────
		//
		// The entry-attached traps above are the same mechanism one layer in: a
		// trap that belongs to one licence lives on that licence's entry, and a
		// trap that belongs to the catalogue lives in corpus/traps/ and is
		// evaluated here, against every dependency.
		//
		// Placed after the obligation loop rather than before it so that the
		// context is complete: `ctx.Entry` is set, which is what makes
		// `dep.licence.family` answerable. Order within the findings is
		// irrelevant — Evaluate sorts at the end — so this is chosen for what
		// the predicate can see, not for what it prints first.
		if err := appendTrapFindings(out, traps, d, ctx, opts, c.Citations); err != nil {
			return nil, err
		}
	}

	// ── cross-dependency checks ─────────────────────────────────────────────
	cross, err := crossCheck(g, c, in, opts)
	if err != nil {
		return nil, err
	}
	out.Findings = append(out.Findings, cross.Findings...)
	out.Undetermined = append(out.Undetermined, cross.Undetermined...)
	out.Notices = append(out.Notices, cross.Notices...)

	// ── platform terms ──────────────────────────────────────────────────────
	//
	// The second differentiator. It runs after the obligation loop because it
	// reads the graph rather than a licence entry, and it contributes findings,
	// notices and — when a platform's clauses are conditional on an undeclared
	// fact — undetermined records of its own.
	platform, err := platformTerms(g, c, in, opts)
	if err != nil {
		return nil, err
	}
	out.Findings = append(out.Findings, platform.Findings...)
	out.Undetermined = append(out.Undetermined, platform.Undetermined...)
	out.Notices = append(out.Notices, platform.Notices...)

	// ── the org policy ──────────────────────────────────────────────────────
	//
	// It runs LAST, after every finding has been constructed, and that position
	// is the point. The policy is the only input that can change a finding's
	// severity without changing the corpus, so it has to see the complete set —
	// an obligation finding, a trap finding, a cross-dependency finding and a
	// platform finding are all equally escalatable, and running the policy in
	// any earlier position would silently exempt whichever layer came after it.
	//
	// It rewrites the DECLARED severity. The confidence gate in EffectiveSeverity
	// runs afterwards, at fold time, so a policy cannot escalate its way past
	// INV-2: a LOW-confidence finding stays a NOTE no matter what the policy
	// says. "I do not know" is not a fact an organisation can override, and a
	// policy that could promote a guess to a block would be the mirror image of
	// the downgrade the one-directional rule forbids.
	if opts.OrgPolicy != nil {
		applyOrgPolicy(out, c, opts)
	}

	// ── stable ordering (INV-6) ─────────────────────────────────────────────
	sort.SliceStable(out.Findings, func(i, j int) bool {
		return out.Findings[i].sortKey() < out.Findings[j].sortKey()
	})
	sort.SliceStable(out.Undetermined, func(i, j int) bool {
		return out.Undetermined[i].SortKey() < out.Undetermined[j].SortKey()
	})
	sort.SliceStable(out.Notices, func(i, j int) bool {
		if out.Notices[i].Code != out.Notices[j].Code {
			return out.Notices[i].Code < out.Notices[j].Code
		}
		return out.Notices[i].Message < out.Notices[j].Message
	})

	return out, nil
}

// dependencyScopedTraps returns the corpus-level traps that are decided by their
// own predicate, in the corpus's stable order.
//
// # WHY GRAPH-SCOPED TRAPS ARE EXCLUDED
//
// Because their `when` is a precondition and not the judgement.
//
// `trap.code-weights-divergence` is satisfied by any non-permissive weights
// dependency, but the finding it exists for is a comparison — this repository's
// code is permissive while its weights are not — and crossCheck is what performs
// that comparison, escalates the severity, and writes the reason line naming
// both licences. Evaluating the precondition here as well would emit a second
// finding for the same defect, at the trap's base severity, with a reason that
// does not mention the code licence it is about. The user would see the
// signature finding twice and the weaker copy would be the one that reads
// like a general observation.
//
// The exclusion is by the declared scope rather than by a list of ids, so a new
// graph-scoped trap cannot be silently double-evaluated, and a trap that is
// wrongly declared graph-scoped is caught by the guard rather than by a reader.
func dependencyScopedTraps(c *corpus.Corpus) []*corpus.Trap {
	all := c.GlobalTraps()
	out := make([]*corpus.Trap, 0, len(all))
	for _, tr := range all {
		if tr.IsGraphScoped() {
			continue
		}
		out = append(out, tr)
	}
	return out
}

// appendTrapFindings evaluates every dependency-scoped corpus trap against one
// dependency and appends the ones that fire.
//
// A trap fires only on a definite TRUE. UNKNOWN is not a near-miss to be
// rounded up: a trap is a claim that a specific failure mode is present, and
// the tool does not make that claim about a project whose facts it could not
// read. The UNDETERMINED records the caller already emitted are where "we could
// not tell" is said.
func appendTrapFindings(out *Evaluation, traps []*corpus.Trap, d graph.Dependency, ctx *Context, opts Options, ix *cite.Index) error {
	for _, tr := range traps {
		res := Eval(tr.When, ctx)
		if res.Value != TriTrue {
			continue
		}
		f, err := newTrapFinding(d, tr, res, opts, ix)
		if err != nil {
			return err
		}
		out.Findings = append(out.Findings, f)
	}
	return nil
}

// applyOrgPolicy rewrites every finding the organisation's policy has something
// to say about.
//
// # WHY IT MUTATES RATHER THAN FILTERS
//
// The obvious design is for the policy to filter findings out — drop the ones
// it excepts, drop the ones below its ceiling. This does not, and the reason is
// that the report is evidence. A finding that vanished because a policy
// permitted it is a finding nobody can audit, and the first question anyone
// asks of a clean verdict is "what did you decide to ignore?".
//
// So an exception demotes to NOTE and appends the owner and the expiry to the
// reason. The verdict gets quieter, which is what the exception was for, and
// the decision stays legible in every output: human, JSON, Markdown, SARIF and
// SBOM.
//
// # WHY IT CANNOT RAISE CONFIDENCE
//
// It changes Severity and Reason and nothing else. There is no path here that
// touches Confidence, which is what keeps INV-2 intact — the gate is applied to
// whatever severity the policy left behind, and a policy cannot buy a block by
// asserting certainty the tool does not have.
func applyOrgPolicy(out *Evaluation, c *corpus.Corpus, opts Options) {
	for i := range out.Findings {
		f := &out.Findings[i]

		// The family is looked up from the corpus rather than carried on the
		// finding. A finding's `Licence` field is a display label as often as
		// it is an SPDX identifier — "platform ToS" is not resolvable — and the
		// lookup failing is the correct outcome for those: a family escalation
		// cannot apply to a finding with no licence family.
		family := ""
		if e, ok := c.Resolve(f.Licence); ok {
			family = e.Family
		}

		d := opts.OrgPolicy.Decide(
			f.DependencyID, f.Kind, f.Licence, family, string(f.Severity), opts.Today)
		if !d.Matched() {
			continue
		}

		if d.Severity != "" {
			f.Severity = Severity(d.Severity)
		}
		if d.ReasonSuffix != "" {
			f.Reason += d.ReasonSuffix
		}
		if d.NoticeCode != "" {
			out.Notices = append(out.Notices, corpus.Notice{
				Code:    d.NoticeCode,
				Message: d.NoticeMessage,
			})
		}
	}
}

// EffectiveSeverity applies the confidence gate (§4 of the verdict algebra).
//
// This is INV-2 in practice, and it is the single most important safety
// property in the product:
//
//	HIGH    may block
//	MEDIUM  becomes a CONDITION, with the ambiguity shown
//	LOW     becomes a NOTE, with the raw clause shown for the human to read
//
// The demotion happens here rather than at fold time so that a demoted blocker
// is still *visible* in the output. A MEDIUM blocker that silently vanished
// from the report would be worse than one that blocked.
func EffectiveSeverity(f Finding, allowMediumBlockers bool) Severity {
	switch f.Confidence {
	case ConfidenceHigh:
		return f.Severity
	case ConfidenceMedium:
		if allowMediumBlockers {
			return f.Severity
		}
		if f.Severity == SeverityBlock {
			return SeverityCondition
		}
		return f.Severity
	default: // LOW, and any unknown value
		switch f.Severity {
		case SeverityBlock, SeverityCondition:
			return SeverityNote
		}
		return f.Severity
	}
}

// newFinding is the ONLY way to construct a Finding.
//
// INV-1 is enforced here by construction rather than by discipline: the
// citation is resolved against the corpus index first, and if it does not
// resolve, the finding is not created and the caller receives E-POLICY-002 — an
// internal error, because an unresolvable citation is a corpus bug that a
// release guard should have caught.
func newFinding(d graph.Dependency, ob *corpus.Obligation, res Result, opts Options, ix *cite.Index) (Finding, error) {
	conf := Confidence(ob.Confidence)
	if !conf.Valid() {
		// Should be impossible: the corpus loader validates every confidence.
		// It is checked anyway because INV-2 is the invariant the product is
		// least able to survive without.
		return Finding{}, cerr.New(cerr.EPolicy007)
	}

	// INV-8 / §3.1: a platform summary older than its staleness window is
	// downgraded one level, because terms change without notice.
	if isStale(ob.Citation.RetrievedAt, opts.Today) {
		conf = downgrade(conf)
	}

	cit, err := resolveCitation(ix, ob.Citation)
	if err != nil {
		return Finding{}, err
	}

	f := Finding{
		ID:           findingID(d.ID, ob.ID),
		DependencyID: d.ID,
		Kind:         ob.ID,
		Severity:     Severity(ob.Severity),
		Confidence:   conf,
		Title:        obligationTitle(ob.Kind),
		Reason:       ob.Message,
		Citation:     cit,
		// Licence is what the finding is ABOUT, and the human renderer prints
		// it in the head line beside the dependency name. This constructor
		// originally omitted it while newTrapFinding set it, so an obligation
		// blocker rendered as `[BLOCK]  firecrawl` with no licence at all —
		// the one fact a reader scans a blocker list for. All three
		// constructors must set it; TestEveryFindingCarriesItsLicence is the
		// guard.
		Licence:   licenceLabel(d),
		Evidence:  d.Evidence,
		Predicate: ob.When,
	}
	if ob.Fix != nil {
		f.Fix = &Fix{
			Action:      ob.Fix.Action,
			Suggestion:  ob.Fix.Suggestion,
			Alternative: ob.Fix.Alternative,
			Confidence:  Confidence(ob.Fix.Confidence),
		}
	}
	return f, nil
}

// obligationTitle is the finding headline for an obligation.
//
// # WHY IT GOES THROUGH THE VOCABULARY RATHER THAN CONCATENATING
//
// Because the string "SOURCE_DISCLOSURE obligation" should have exactly one
// definition, and it should live in the package that owns the list of kinds.
// Before this existed the title was built inline in two constructors, so a
// change to how a kind is spelled in a headline was a two-place edit that
// nothing would catch if only one place was changed.
//
// The fallback is deliberately loud. An unknown kind reaching this function
// means a corpus was loaded without validation — an older binary, or a corpus
// assembled by hand — and printing the raw value as though it were a kind would
// put the exact defect internal/obligations exists to prevent into the report.
// Naming the problem is the honest failure.
func obligationTitle(kind string) string {
	if k, ok := obligations.KindOf(kind); ok {
		return k.Title()
	}
	return "UNKNOWN obligation kind '" + strings.TrimSpace(kind) + "'"
}

// newUndeterminedFinding turns an UNKNOWN predicate into the NOTE the user
// sees: the obligation is shown, with its clause, and the reason it could not
// be decided.
func newUndeterminedFinding(d graph.Dependency, ob *corpus.Obligation, res Result, opts Options, ix *cite.Index) (Finding, error) {
	cit, err := resolveCitation(ix, ob.Citation)
	if err != nil {
		return Finding{}, err
	}
	return Finding{
		ID:                findingID(d.ID, ob.ID),
		DependencyID:      d.ID,
		Kind:              ob.ID,
		Severity:          SeverityNote,
		Confidence:        ConfidenceLow,
		Title:             obligationTitle(ob.Kind) + " (undetermined)",
		Reason:            ob.Message,
		Citation:          cit,
		Licence:           licenceLabel(d),
		Evidence:          d.Evidence,
		Predicate:         ob.When,
		UndeterminedField: res.UndeclaredField,
	}, nil
}

// newTrapFinding turns a fired trap into a finding.
func newTrapFinding(d graph.Dependency, tr *corpus.Trap, res Result, opts Options, ix *cite.Index) (Finding, error) {
	conf := Confidence(tr.Confidence)
	if !conf.Valid() {
		return Finding{}, cerr.New(cerr.EPolicy007)
	}
	if isStale(tr.Citation.RetrievedAt, opts.Today) {
		conf = downgrade(conf)
	}
	cit, err := resolveCitation(ix, tr.Citation)
	if err != nil {
		return Finding{}, err
	}
	f := Finding{
		ID:           findingID(d.ID, tr.ID),
		DependencyID: d.ID,
		Kind:         tr.ID,
		Severity:     Severity(tr.Severity),
		Confidence:   conf,
		Title:        tr.Title,
		Reason:       tr.Summary,
		Citation:     cit,
		Licence:      licenceLabel(d),
		Evidence:     d.Evidence,
		Predicate:    tr.When,
		TrapID:       tr.ID,
	}
	if tr.Fix != nil {
		f.Fix = &Fix{
			Action:      tr.Fix.Action,
			Suggestion:  tr.Fix.Suggestion,
			Alternative: tr.Fix.Alternative,
			Confidence:  Confidence(tr.Fix.Confidence),
		}
	}
	return f, nil
}

// resolveCitation performs the INV-1 gate. It is called by every constructor,
// and it is the only way a Finding acquires a Citation.
//
// # TWO CHECKS, AND THE SECOND ONE IS THE POINT
//
//  1. Structural  — the reference names a URL and a section.
//  2. Resolvable  — the corpus actually carries that clause (cite.Index.Resolve).
//
// The first check alone is not INV-1. INV-1 says a citation must "point at a
// corpus entry, which itself points at a primary source URL and a section" —
// and a reference that is well-formed but unregistered points at nothing. An
// earlier version of this function performed only the structural check and
// documented the gap in a comment, which meant the product's headline invariant
// was enforced by nothing and TestNoUncitedFinding passed for a reason
// unrelated to citations: the guard could not fail, so it certified a
// guarantee it did not check.
//
// The index is now threaded in from Evaluate, which already holds the corpus.
// A miss is E-POLICY-002 — an INTERNAL error, exit 4 — because an unresolvable
// citation is a corpus bug that the release guard should have caught, and the
// user cannot fix it and must not be asked to.
//
// The returned Citation is built from the reference rather than from the
// index's copy. That is deliberate: the index keeps the FIRST registration for
// an ID, and when two entries cite the same clause with different excerpts the
// loader already reports the inconsistency as a Notice. Rendering the entry's
// own excerpt keeps the finding consistent with the entry that produced it,
// while the index still guarantees the clause exists.
func resolveCitation(ix *cite.Index, ref cite.Ref) (cite.Citation, error) {
	if strings.TrimSpace(ref.URL) == "" || strings.TrimSpace(ref.Section) == "" {
		return cite.Citation{}, cerr.New(cerr.EPolicy002, ref.ID())
	}
	if _, err := ix.Resolve(ref); err != nil {
		return cite.Citation{}, err
	}
	return cite.Citation{
		URL:     ref.URL,
		Section: ref.Section,
		Excerpt: ref.Excerpt,
		// ExcerptKind must travel with the excerpt. Dropping it here would
		// re-create the exact defect the field exists to prevent: a
		// paraphrase arriving at a renderer with nothing to distinguish it
		// from a quotation, and being printed in quotation marks.
		ExcerptKind: ref.ExcerptKind,
	}, nil
}

// findingID is a stable identifier for a finding: the dependency and the
// obligation together. It is NOT used for ordering — ordering is by
// (severity, dependency, kind) explicitly — but it is what `clearance explain`
// takes as an argument, so it must be reproducible across runs and machines.
func findingID(depID, kind string) string {
	return "f_" + shortHash(depID+"\x00"+kind)
}

func rawOrNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}

// licenceLabel is what the licence column of a rendered finding shows.
//
// It prefers the resolved SPDX identifier, falls back to the literal string the
// manifest carried, and only then admits that nothing was declared. Showing the
// raw string matters: "see LICENSE" tells a reader where to look, and that is
// more useful than the word "unknown" — which is why the raw value is preserved
// all the way from the parser to here instead of being normalised away.
func licenceLabel(d graph.Dependency) string {
	if s := strings.TrimSpace(d.Licence.SPDX); s != "" {
		return s
	}
	if s := strings.TrimSpace(d.Licence.Raw); s != "" {
		return s
	}
	return "no licence declared"
}

// shortHash is the stable, short identifier used for finding ids. It is a
// SHA-256 prefix, so it is reproducible across runs and machines, and it is
// short enough to paste into a terminal.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// isStale implements the staleness rule of the confidence model (§3.1): a
// source retrieved more than 180 days before Today is downgraded one level,
// because platform terms change without notice and a summary written nine
// months ago may describe terms that no longer exist.
func isStale(retrievedAt, today string) bool {
	if retrievedAt == "" || today == "" {
		return false
	}
	got, err := time.Parse("2006-01-02", retrievedAt)
	if err != nil {
		// An unparseable date cannot be proven fresh, so it is treated as stale.
		// The conservative direction.
		return true
	}
	now, err := time.Parse("2006-01-02", today)
	if err != nil {
		return false
	}
	return now.Sub(got).Hours()/24 > 180
}

// downgrade returns the next weaker confidence. A LOW stays LOW: there is
// nothing below an admission that the tool does not know.
func downgrade(c Confidence) Confidence {
	switch c {
	case ConfidenceHigh:
		return ConfidenceMedium
	case ConfidenceMedium:
		return ConfidenceLow
	}
	return ConfidenceLow
}
