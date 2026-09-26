// The platform-terms layer.
//
// # WHY THIS LAYER IS SEPARATE FROM THE OBLIGATION LOOP
//
// The obligation loop in engine.go answers "what does this dependency's licence
// require?". This layer answers a different question: "what has this project
// agreed to by *invoking* something?". The two share a severity vocabulary, a
// citation gate and a confidence model, and they share nothing else. A licence
// obligation is a predicate over the licence and the declared use; a platform
// clause is a predicate over the use alone, because the act of invoking the
// platform is what inherits the terms.
//
// That is also why an unrecognised platform is a Notice and not a Finding. The
// tool has established a fact — "you call X" — and the corpus has no terms for
// it. A Finding would have to cite a clause, and there is no clause; INV-1
// makes an uncited finding unrepresentable, and inventing a citation here would
// be the exact fabrication the whole product is built to avoid.
//
// PLAN/02-SPECIFICATIONS/06-detection-spec-tos.md is the contract. §5's
// inheritance logic is implemented verbatim, including its default: a clause
// with no `when` predicate applies whenever the platform is invoked.
package policy

import (
	"sort"
	"strconv"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/cite"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/corpus"
	"github.com/clearance-dev/clearance/internal/graph"
)

// platformTerms resolves every detected third-party invocation to a corpus
// platform and evaluates that platform's clauses.
//
// # THE GROUPING, AND WHY IT IS NOT OPTIONAL
//
// One tool reached three ways — a binary name in a script, a host in a fetch,
// an API key in a template — is one platform. Emitting its clauses once per
// signal would produce three identical findings whose only difference is the
// evidence line, which is the noise that trains a reader to skim a verdict.
// So contributions are grouped by platform, the evidence is unioned, and the
// clause list is evaluated once.
func platformTerms(g *graph.Graph, c *corpus.Corpus, in *config.Intent, opts Options) (crossResult, error) {
	var out crossResult
	if g == nil || c == nil || in == nil {
		return out, nil
	}

	type match struct {
		platform *corpus.ToSEntry
		contrib  []graph.Dependency
	}
	byPlatform := map[string]*match{}
	var keys []string

	add := func(p *corpus.ToSEntry, d graph.Dependency) {
		m, ok := byPlatform[p.Platform]
		if !ok {
			m = &match{platform: p}
			byPlatform[p.Platform] = m
			keys = append(keys, p.Platform)
		}
		m.contrib = append(m.contrib, d)
	}

	for _, d := range g.Dependencies {
		switch d.Kind {
		case graph.KindUpstreamCLI:
			signal := d.Metadata["signal"]
			if p, ok := c.PlatformFor(d.Name, signal); ok {
				add(p, d)
				continue
			}
			// The spec's §7 row: "Platform detected, no corpus entry". It is
			// rendered as a Notice rather than the spec's INFO finding, and
			// the reason is INV-1 — see the package comment. The user still
			// learns that the invocation was seen, which is the whole point of
			// the row, and the verdict is untouched because SHIP already means
			// "no *known* obligation contradicts the declared intent".
			out.Notices = append(out.Notices, corpus.Notice{
				Code: string(cerr.ECorpus004),
				Message: "Detected a third-party " + signalNoun(signal) + " '" + d.Name + "' at " +
					firstEvidence(d) + "; the corpus carries no terms for it, so no obligations " +
					"were evaluated for it. Consider contributing an entry.",
			})

		case graph.KindPackage, graph.KindVendored:
			// An SDK is an invocation you can see in the lockfile. Matching the
			// corpus's import aliases against the dependency graph means the
			// platform layer needs no source scan for the most common case of
			// all: "this project calls OpenAI" is visible in pyproject.toml.
			if p, ok := c.PlatformFor(d.Name, "import"); ok {
				add(p, d)
			}
		}
	}

	sort.Strings(keys)

	for _, k := range keys {
		m := byPlatform[k]
		sort.SliceStable(m.contrib, func(i, j int) bool { return m.contrib[i].ID < m.contrib[j].ID })

		// The primary is the first contributor in ID order, so the finding's
		// DependencyID is stable across runs and machines (INV-6). The rest
		// travel in the evidence list.
		primary := m.contrib[0]
		ev := unionEvidence(m.contrib)

		// The staleness downgrade is announced once per entry, not once per
		// clause. An entry with four clauses is one fact — "this summary is
		// old" — and repeating it four times is how a warning list becomes
		// something a reader scrolls past. The per-clause effect is already
		// stated in each finding's reason, because that is where a reader who
		// is looking at one clause will be.
		if _, stale := corpus.StalenessDowngrade(m.platform.LastVerified, m.platform.StalenessDays, opts.Today); stale {
			out.Notices = append(out.Notices, corpus.Notice{
				Code: string(cerr.ECorpus011),
				Message: "Corpus entry '" + m.platform.Platform + "' was last verified on " +
					m.platform.LastVerified + ", which is outside its " +
					strconv.Itoa(m.platform.StalenessDays) + "-day staleness window. " +
					"Its clauses are reported one confidence level lower.",
			})
		}

		for i := range m.platform.RestrictiveClauses {
			cl := &m.platform.RestrictiveClauses[i]

			// §5: a clause with no predicate applies whenever the platform is
			// invoked. UNKNOWN also emits — the tool says "this may apply and I
			// cannot tell" rather than dropping a clause it could not decide,
			// which is the same direction as the licence layer.
			ctx := &Context{Intent: in, Dep: &primary}
			if res := Eval(cl.When, ctx); res.Value == TriFalse {
				continue
			}

			f, err := newPlatformFinding(m.platform, cl, primary, ev, opts, c.Citations)
			if err != nil {
				return out, err
			}
			out.Findings = append(out.Findings, f)
		}
	}

	return out, nil
}

// newPlatformFinding turns a platform clause into a finding.
//
// It is a constructor rather than an inline literal for the same reason the
// other three are: the citation gate and the confidence gate must be
// unavoidable, and a fifth code path that builds a Finding by hand is a fifth
// chance to skip one of them.
func newPlatformFinding(
	e *corpus.ToSEntry,
	cl *corpus.Clause,
	d graph.Dependency,
	ev []graph.Evidence,
	opts Options,
	ix *cite.Index,
) (Finding, error) {
	conf := Confidence(cl.Confidence)
	if !conf.Valid() {
		return Finding{}, cerr.New(cerr.EPolicy007)
	}

	// §4.1: a platform summary older than its staleness window is downgraded one
	// level, because terms change without notice and a summary written nine
	// months ago may describe terms that no longer exist. The downgrade is
	// stated in the finding rather than in a side channel, so a reader who sees
	// a MEDIUM clause can tell whether the corpus downgraded it.
	stale := false
	if _, isStale := corpus.StalenessDowngrade(e.LastVerified, e.StalenessDays, opts.Today); isStale {
		conf = downgrade(conf)
		stale = true
	}

	cit, err := resolveCitation(ix, cl.Citation)
	if err != nil {
		return Finding{}, err
	}

	// §4.2: the tool always distinguishes primary text from a curated summary.
	// A licence finding quotes the licence; a platform finding cannot, because
	// the corpus holds a summary rather than the terms themselves. Saying so in
	// the reason is what keeps the two from looking alike.
	var b strings.Builder
	b.WriteString(strings.TrimSpace(cl.TextSummary))
	b.WriteString(" This is a curated summary of ")
	b.WriteString(e.DisplayName)
	b.WriteString("'s terms, last verified ")
	b.WriteString(e.LastVerified)
	b.WriteString(", not a reading of the primary text. Read the terms yourself before relying on this.")
	if stale {
		b.WriteString(" The summary is older than the ")
		b.WriteString(strconv.Itoa(e.StalenessDays))
		b.WriteString("-day staleness window, so its confidence has been downgraded one level.")
	}

	return Finding{
		ID:           findingID(d.ID, cl.ID),
		DependencyID: d.ID,
		Kind:         cl.ID,
		Severity:     Severity(cl.Severity),
		Confidence:   conf,
		Title:        "platform terms of service",
		Reason:       b.String(),
		Citation:     cit,
		Licence:      platformLabel(e),
		Evidence:     ev,
		Predicate:    cl.When,
	}, nil
}

// platformLabel is what the licence column shows for a platform finding.
//
// The column is the reader's one-glance answer to "what kind of obligation is
// this?", and "platform ToS" answers it in a way that "MIT" cannot: it says the
// source is terms of service rather than a licence file, which is the
// distinction the whole layer exists to draw.
func platformLabel(e *corpus.ToSEntry) string {
	if e != nil && e.Kind == corpus.PlatformBinary {
		return "third-party binary"
	}
	return "platform ToS"
}

// signalNoun renders a signal kind for a sentence.
func signalNoun(signal string) string {
	switch signal {
	case "bin":
		return "program"
	case "runner":
		return "package-runner invocation"
	case "host":
		return "service"
	case "env":
		return "service credential"
	case "image":
		return "container image"
	case "import":
		return "SDK"
	}
	return "dependency"
}

// firstEvidence renders a dependency's first evidence location, for a Notice
// that has to say where something was seen.
func firstEvidence(d graph.Dependency) string {
	if len(d.Evidence) == 0 {
		return "an unknown location"
	}
	ev := d.Evidence[0]
	if ev.LineStart > 0 {
		return ev.Path + ":" + strconv.Itoa(ev.LineStart)
	}
	return ev.Path
}

// unionEvidence merges the evidence of several dependencies, deduplicated by
// location and in a stable order.
func unionEvidence(deps []graph.Dependency) []graph.Evidence {
	var out []graph.Evidence
	seen := map[string]bool{}
	for _, d := range deps {
		for _, ev := range d.Evidence {
			k := ev.Path + "\x00" + strconv.Itoa(ev.LineStart)
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, ev)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].LineStart < out[j].LineStart
	})
	return out
}
