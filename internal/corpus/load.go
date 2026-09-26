package corpus

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/cite"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/obligations"
	"github.com/clearance-dev/clearance/internal/safefs"
	"github.com/clearance-dev/clearance/internal/safeyaml"
)

// LoadOptions controls a load from the YAML source tree.
type LoadOptions struct {
	// Dir is the corpus root (the directory containing licences/, traps/,
	// tos/ and territories/).
	Dir string

	// Previous is the corpus version this one replaces. When supplied, the
	// loader enforces INV-8 in full: a confidence that rose without a
	// correction block fails the load with E-CORPUS-006. Without it, only the
	// structural half of INV-8 can be checked (a correction block must be
	// well-formed), and the loader says so in a Notice rather than pretending.
	Previous *Corpus

	// Today is the date used for the "is last_verified in the future" check and
	// for the ToS staleness downgrade. It is injected rather than read from the
	// clock so that loading is deterministic and testable (INV-6).
	Today string

	Limits safeyaml.Limits
}

// Load reads, validates and indexes a corpus from the YAML source tree.
//
// The order is deliberate: parse every file, validate every entry, then build
// the citation index, then check cross-entry invariants (duplicate SPDX ids,
// confidence rises). A citation index built before validation would let an
// invalid entry's citation resolve, which is how a bad entry becomes a
// confident finding.
func Load(opts LoadOptions) (*Corpus, error) {
	if opts.Dir == "" {
		return nil, cerr.New(cerr.ECorpus001, opts.Dir)
	}
	today := opts.Today
	if today == "" {
		today = time.Now().UTC().Format("2006-01-02")
	}
	lim := opts.Limits
	if lim.MaxBytes == 0 {
		lim = safeyaml.Limits{MaxBytes: 1 << 20, MaxDepth: 32}
	}

	root, err := safefs.New(opts.Dir, safefs.Limits{MaxFileSize: 1 << 20})
	if err != nil {
		return nil, cerr.New(cerr.ECorpus001, opts.Dir)
	}

	c := &Corpus{
		Version:       "0.0.0-unsigned",
		SchemaVersion: SchemaVersion,
		bySPDX:        map[string]*Entry{},
		tos:           map[string]*ToSEntry{},
		territories:   map[string]*TerritoryEntry{},
		Citations:     cite.NewIndex(),
	}

	// ── licences ────────────────────────────────────────────────────────────
	licFiles, _ := listYAML(root, "licences")
	for _, rel := range licFiles {
		data, err := root.ReadFile(rel, int64(lim.MaxBytes))
		if err != nil {
			return nil, err
		}
		node, err := safeyaml.Parse(data, lim)
		if err != nil {
			return nil, wrapEntryError(rel, err)
		}
		var e Entry
		if err := safeyaml.Decode(node, &e); err != nil {
			return nil, wrapEntryError(rel, err)
		}
		e.SourcePath = rel
		if err := validateEntry(&e, today); err != nil {
			return nil, err
		}
		for i := range e.Obligations {
			e.Obligations[i].EntryID = e.ID
		}
		for i := range e.Traps {
			e.Traps[i].EntryID = e.ID
		}

		// Duplicate spdx_id is a build failure, not a last-wins (rule 2).
		key := strings.ToUpper(e.SPDXID)
		if prev, dup := c.bySPDX[key]; dup {
			return nil, cerr.New(cerr.ECorpus005, e.SPDXID+" ("+prev.SourcePath+")")
		}
		c.bySPDX[key] = &e
		c.bySPDX[e.SPDXID] = &e
		c.entries = append(c.entries, &e)

		// Register every citation this entry can produce.
		registerCitation(c, e.Citation, rel)
		for _, ob := range e.Obligations {
			registerCitation(c, ob.Citation, rel)
		}
		for _, t := range e.Traps {
			registerCitation(c, t.Citation, rel)
		}
	}

	// ── global traps ────────────────────────────────────────────────────────
	trapFiles, _ := listYAML(root, "traps")
	for _, rel := range trapFiles {
		data, err := root.ReadFile(rel, int64(lim.MaxBytes))
		if err != nil {
			return nil, err
		}
		node, err := safeyaml.Parse(data, lim)
		if err != nil {
			return nil, wrapEntryError(rel, err)
		}
		// A traps file may hold one trap or a sequence of them.
		if node.Kind == safeyaml.SequenceNode {
			for _, item := range node.List() {
				var t Trap
				if err := safeyaml.Decode(item, &t); err != nil {
					return nil, wrapEntryError(rel, err)
				}
				t.Global = true
				if err := validateTrap(&t, rel); err != nil {
					return nil, err
				}
				c.globalTraps = append(c.globalTraps, &t)
				registerCitation(c, t.Citation, rel)
			}
			continue
		}
		var t Trap
		if err := safeyaml.Decode(node, &t); err != nil {
			return nil, wrapEntryError(rel, err)
		}
		t.Global = true
		if err := validateTrap(&t, rel); err != nil {
			return nil, err
		}
		c.globalTraps = append(c.globalTraps, &t)
		registerCitation(c, t.Citation, rel)
	}
	sort.SliceStable(c.globalTraps, func(i, j int) bool { return c.globalTraps[i].ID < c.globalTraps[j].ID })

	// ── platform terms ──────────────────────────────────────────────────────
	tosFiles, _ := listYAML(root, "tos")
	for _, rel := range tosFiles {
		data, err := root.ReadFile(rel, int64(lim.MaxBytes))
		if err != nil {
			return nil, err
		}
		node, err := safeyaml.Parse(data, lim)
		if err != nil {
			return nil, wrapEntryError(rel, err)
		}
		var t ToSEntry
		if err := safeyaml.Decode(node, &t); err != nil {
			return nil, wrapEntryError(rel, err)
		}
		if err := validateToS(&t, rel, today); err != nil {
			return nil, err
		}
		slug := strings.ToLower(strings.TrimSpace(t.Platform))
		if _, dup := c.tos[slug]; dup {
			return nil, cerr.New(cerr.ECorpus005, t.Platform)
		}
		c.tos[slug] = &t
		for _, cl := range t.RestrictiveClauses {
			registerCitation(c, cl.Citation, rel)
		}
	}

	// ── territories ─────────────────────────────────────────────────────────
	terrFiles, _ := listYAML(root, "territories")
	for _, rel := range terrFiles {
		data, err := root.ReadFile(rel, int64(lim.MaxBytes))
		if err != nil {
			return nil, err
		}
		node, err := safeyaml.Parse(data, lim)
		if err != nil {
			return nil, wrapEntryError(rel, err)
		}
		var t TerritoryEntry
		if err := safeyaml.Decode(node, &t); err != nil {
			return nil, wrapEntryError(rel, err)
		}
		if err := validateTerritory(&t, rel); err != nil {
			return nil, err
		}
		code := strings.ToUpper(strings.TrimSpace(t.Code))
		if _, dup := c.territories[code]; dup {
			return nil, cerr.New(cerr.ECorpus005, t.Code)
		}
		c.territories[code] = &t
		for _, g := range t.Gates {
			registerCitation(c, g.Citation, rel)
		}
	}

	// ── the floor ───────────────────────────────────────────────────────────
	//
	// A directory that produced no content at all is not a corpus, and saying
	// so here is better than returning an empty Corpus that silently resolves
	// nothing — every dependency would become UNDETERMINED and the user would
	// be told their stack is unknown rather than that they pointed the tool at
	// the wrong directory.
	//
	// All four kinds count, and the earlier version of this check counted only
	// two. It read `len(c.entries) == 0 && len(c.globalTraps) == 0`, so a
	// corpus holding only platform terms — or only territories — was rejected
	// as "not found" even though it had loaded perfectly well. That is a real
	// configuration: a corpus fork that ships curated ToS entries on top of the
	// upstream licence set, or a test corpus like fixtures/upstream-stale-tos
	// that exists to exercise one date rule, is a legitimate corpus.
	//
	// The bug was invisible because the shipped corpus has all four kinds, so
	// the two-kind check never returned true on it. It surfaced the first time
	// something tried to load a corpus that was deliberately narrow.
	if len(c.entries) == 0 && len(c.globalTraps) == 0 && len(c.tos) == 0 && len(c.territories) == 0 {
		return nil, cerr.New(cerr.ECorpus001, opts.Dir)
	}

	// ── two platforms claiming one token ────────────────────────────────────
	//
	// PlatformFor resolves a token to the first platform in sorted order, so a
	// token claimed twice resolves silently and arbitrarily. That is worth
	// saying out loud rather than leaving for a maintainer to discover when a
	// finding names the wrong vendor.
	claim := map[string]string{}
	for _, slug := range c.SortedToSPlatforms() {
		t := c.tos[slug]
		if t.Detect == nil {
			continue
		}
		for _, g := range []struct {
			signal string
			tokens []string
		}{
			{"bin", t.Detect.Bins}, {"runner", t.Detect.Runners},
			{"host", t.Detect.Hosts}, {"env", t.Detect.Env},
			{"import", t.Detect.Imports}, {"image", t.Detect.Images},
		} {
			for _, tok := range g.tokens {
				key := g.signal + "\x00" + strings.ToLower(tok)
				if prev, dup := claim[key]; dup && prev != t.Platform {
					c.Notices = append(c.Notices, Notice{
						Code: string(cerr.ECorpus004),
						Message: "Platforms '" + prev + "' and '" + t.Platform + "' both claim the " +
							g.signal + " token '" + tok + "'. The first in sorted order wins.",
					})
					continue
				}
				claim[key] = t.Platform
			}
		}
	}

	// ── INV-8: confidence may not rise without a correction ─────────────────
	if err := checkConfidenceRises(c, opts.Previous); err != nil {
		return nil, err
	}
	if opts.Previous == nil {
		c.Notices = append(c.Notices, Notice{
			Code: string(cerr.ECorpus012),
			Message: "Loaded without a previous corpus version; confidence rises could not be " +
				"compared. Supply the previous version to enforce INV-8 in full.",
		})
	}

	return c, nil
}

// listYAML returns the .yml/.yaml files directly inside a subdirectory, sorted
// bytewise so that load order is deterministic (INV-6).
func listYAML(root *safefs.Root, sub string) ([]string, error) {
	entries, _, err := root.Walk()
	if err != nil {
		return nil, err
	}
	var out []string
	prefix := sub + "/"
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		if !strings.HasPrefix(e.Rel, prefix) {
			continue
		}
		// Only direct children: a nested directory is not a corpus subdir.
		if strings.Contains(strings.TrimPrefix(e.Rel, prefix), "/") {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Rel))
		if ext == ".yml" || ext == ".yaml" {
			out = append(out, e.Rel)
		}
	}
	sort.Strings(out)
	return out, nil
}

// registerCitation adds a citation to the index and reports a conflict as a
// Notice. Two entries citing the same clause with different excerpts is worth
// knowing about but is not fatal: the first registration wins and both entries
// still carry a citation.
func registerCitation(c *Corpus, r cite.Ref, source string) {
	if strings.TrimSpace(r.URL) == "" || strings.TrimSpace(r.Section) == "" {
		return
	}
	if !c.Citations.Add(r) {
		c.Notices = append(c.Notices, Notice{
			Code:    string(cerr.ECorpus004),
			Message: "Two corpus entries cite " + r.ID() + " with different excerpts (see " + source + ").",
		})
	}
}

// ── validation ───────────────────────────────────────────────────────────────

func validateEntry(e *Entry, today string) error {
	if strings.TrimSpace(e.ID) == "" || strings.TrimSpace(e.SPDXID) == "" {
		return cerr.New(cerr.ECorpus004, e.SourcePath)
	}
	if strings.TrimSpace(e.Name) == "" {
		return cerr.New(cerr.ECorpus004, e.ID)
	}
	if !validFamily(e.Family) {
		return cerr.New(cerr.ECorpus004, e.ID)
	}
	if e.Permissiveness < 1 || e.Permissiveness > 5 {
		return cerr.New(cerr.ECorpus004, e.ID)
	}
	if !validConfidence(e.Confidence) {
		return cerr.New(cerr.ECorpus004, e.ID)
	}
	if err := e.Citation.Validate(); err != nil {
		return cerr.New(cerr.ECorpus004, e.ID)
	}
	if err := validateDate(e.LastVerified, e.ID, today); err != nil {
		return err
	}
	if err := validateCorrection(e.Correction, e.ID); err != nil {
		return err
	}

	seen := map[string]bool{}
	for i := range e.Obligations {
		ob := &e.Obligations[i]
		if strings.TrimSpace(ob.ID) == "" {
			return cerr.New(cerr.ECorpus004, e.ID)
		}
		if seen[ob.ID] {
			return cerr.New(cerr.EPolicy008, e.ID)
		}
		seen[ob.ID] = true
		if !validSeverity(ob.Severity) {
			return cerr.New(cerr.ECorpus004, ob.ID)
		}
		if !validConfidence(ob.Confidence) {
			return cerr.New(cerr.ECorpus004, ob.ID)
		}
		// Rule 11: message length 10..600. A one-word message is not an
		// explanation, and a 2,000-word one is not read.
		if n := len(strings.TrimSpace(ob.Message)); n < 10 || n > 600 {
			return cerr.New(cerr.ECorpus004, ob.ID)
		}
		if ob.When == nil {
			return cerr.New(cerr.ECorpus004, ob.ID)
		}
		if err := ob.When.Validate(); err != nil {
			return err
		}
		if err := ob.Citation.Validate(); err != nil {
			return cerr.New(cerr.ECorpus004, ob.ID)
		}
		if ob.Fix != nil && !validConfidence(ob.Fix.Confidence) {
			return cerr.New(cerr.ECorpus004, ob.ID)
		}
	}
	for i := range e.Traps {
		if err := validateTrap(&e.Traps[i], e.ID); err != nil {
			return err
		}
	}

	// ── the two closed vocabularies ─────────────────────────────────────────
	//
	// `kind` and a fix's `action` are the last two corpus fields that were
	// free strings, and they are the two that reach the user as prose: the
	// kind becomes the finding's title and the action becomes the verb of the
	// advice. Everything else on an obligation was already checked above —
	// id, severity, confidence, message length, predicate, citation — so a
	// typo in either of these was the one that survived a green build and
	// appeared in the report. See internal/obligations.
	//
	// It runs after the per-field checks so that a genuinely malformed
	// obligation reports the structural problem first, which is the more
	// useful of the two messages.
	if err := obligations.Validate(e.ID, obligationSources(e)); err != nil {
		return err
	}
	return nil
}

// obligationSources mirrors an entry's obligations into the shape
// internal/obligations validates against.
//
// # WHY A COPY RATHER THAN A SHARED TYPE
//
// Because `obligations` must not import `corpus`: `corpus` imports it to
// validate at load time, and Go forbids the cycle. The mirror is eight field
// assignments and it is the price of having the vocabulary be the lower
// dependency. See the obligations package comment.
func obligationSources(e *Entry) []obligations.Source {
	out := make([]obligations.Source, len(e.Obligations))
	for i := range e.Obligations {
		ob := &e.Obligations[i]
		s := obligations.Source{
			ID:         ob.ID,
			Kind:       ob.Kind,
			Severity:   ob.Severity,
			When:       ob.When,
			Message:    ob.Message,
			Citation:   ob.Citation,
			Confidence: ob.Confidence,
		}
		if ob.Fix != nil {
			s.Fix = &obligations.FixSource{
				Action:      ob.Fix.Action,
				Suggestion:  ob.Fix.Suggestion,
				Alternative: ob.Fix.Alternative,
				Confidence:  ob.Fix.Confidence,
			}
		}
		out[i] = s
	}
	return out
}

func validateTrap(t *Trap, source string) error {
	if strings.TrimSpace(t.ID) == "" {
		return cerr.New(cerr.ECorpus004, source)
	}
	if !validSeverity(t.Severity) {
		return cerr.New(cerr.ECorpus004, t.ID)
	}
	if !validConfidence(t.Confidence) {
		return cerr.New(cerr.ECorpus004, t.ID)
	}
	if strings.TrimSpace(t.Title) == "" {
		return cerr.New(cerr.ECorpus004, t.ID)
	}
	if t.When == nil {
		return cerr.New(cerr.ECorpus004, t.ID)
	}
	if err := t.When.Validate(); err != nil {
		return err
	}
	if err := t.Citation.Validate(); err != nil {
		return cerr.New(cerr.ECorpus004, t.ID)
	}
	// The scope is checked rather than defaulted in silence, because a typo in
	// this field is the difference between a trap that is evaluated and one that
	// is inert. `scope: graph` on a trap the engine has no check for produces no
	// finding and no error — the trap simply never fires — so the load is the
	// last place the mistake can still be caught cheaply. A guard catches the
	// other half (a graph-scoped trap with no engine check).
	//
	// The check is on the RAW value, not on the resolved one. An absent field
	// means the default, and that is the only thing that does: `scope: " "` is a
	// field that is present and wrong, and resolving it first would make it
	// indistinguishable from an omitted one. Silent-defaulting is what this
	// field exists to end, so the validator does not do it either.
	if t.Scope != "" && !ValidTrapScope(t.Scope) {
		return cerr.New(cerr.ECorpus004, t.ID+" (unknown trap scope '"+t.Scope+"', want 'dependency' or 'graph')")
	}
	// A trap attached to a licence entry has exactly one dependency to be
	// evaluated against, so it cannot be graph-scoped. Declaring otherwise is a
	// category error, and accepting it would leave a trap that is looked up by
	// an id no check knows and therefore never evaluated — the same silent
	// inertness, one layer down.
	if t.IsGraphScoped() && !t.Global {
		return cerr.New(cerr.ECorpus004, t.ID+" (scope: graph is only valid for a trap in traps/, not one attached to a licence entry)")
	}
	return nil
}

func validateToS(t *ToSEntry, source, today string) error {
	if strings.TrimSpace(t.Platform) == "" {
		return cerr.New(cerr.ECorpus004, source)
	}
	if strings.TrimSpace(t.DisplayName) == "" {
		// A platform with no display name renders as its slug, which is
		// survivable but is a hole in the finding: "huggingface" in a sentence
		// reads as a typo. The corpus spells it.
		return cerr.New(cerr.ECorpus004, t.Platform)
	}
	switch t.Kind {
	case "", PlatformHostedService, PlatformBinary, PlatformPlatform:
	default:
		return cerr.New(cerr.ECorpus004, t.Platform)
	}
	if strings.TrimSpace(t.Summary) == "" {
		return cerr.New(cerr.ECorpus004, t.Platform)
	}
	if err := validateDate(t.LastVerified, t.Platform, today); err != nil {
		return err
	}
	if t.StalenessDays <= 0 {
		// A staleness window of zero would mean "never stale", which is the
		// opposite of the honest reading: platform terms change without notice,
		// so an entry must state how long its summary is trusted for.
		return cerr.New(cerr.ECorpus004, t.Platform)
	}
	for _, cl := range t.RestrictiveClauses {
		if strings.TrimSpace(cl.ID) == "" || !validSeverity(cl.Severity) || !validConfidence(cl.Confidence) {
			return cerr.New(cerr.ECorpus004, t.Platform)
		}
		if n := len(strings.TrimSpace(cl.TextSummary)); n < 10 || n > 600 {
			return cerr.New(cerr.ECorpus004, cl.ID)
		}
		// The predicate is optional here, unlike on an obligation. When it is
		// present it must validate, because a clause whose predicate does not
		// typecheck would evaluate to UNKNOWN forever and the clause would be
		// silently unreachable.
		if cl.When != nil {
			if err := cl.When.Validate(); err != nil {
				return err
			}
		}
		if err := cl.Citation.Validate(); err != nil {
			return cerr.New(cerr.ECorpus004, t.Platform)
		}
	}
	if t.Detect != nil {
		for _, group := range [][]string{
			t.Detect.Bins, t.Detect.Runners, t.Detect.Hosts,
			t.Detect.Env, t.Detect.Imports, t.Detect.Images,
		} {
			for _, tok := range group {
				if strings.TrimSpace(tok) == "" {
					// An empty token matches nothing but looks like it does, and
					// a Detect list is the kind of thing a maintainer edits by
					// hand at speed.
					return cerr.New(cerr.ECorpus004, t.Platform)
				}
			}
		}
	}
	return nil
}

func validateTerritory(t *TerritoryEntry, source string) error {
	if strings.TrimSpace(t.Code) == "" {
		return cerr.New(cerr.ECorpus004, source)
	}
	for _, g := range t.Gates {
		if strings.TrimSpace(g.ID) == "" || !validSeverity(g.Severity) || !validConfidence(g.Confidence) {
			return cerr.New(cerr.ECorpus004, t.Code)
		}
		if err := g.Citation.Validate(); err != nil {
			return cerr.New(cerr.ECorpus004, t.Code)
		}
	}
	return nil
}

// validateDate enforces rule 7: last_verified must not be in the future. A
// future date is not a warning here — it is a data error, and a corpus that
// claims to have verified something tomorrow is a corpus nobody should trust.
func validateDate(date, id, today string) error {
	d := strings.TrimSpace(date)
	if d == "" {
		return cerr.New(cerr.ECorpus004, id)
	}
	if _, err := time.Parse("2006-01-02", d); err != nil {
		return cerr.New(cerr.ECorpus004, id)
	}
	if today != "" && d > today {
		// ISO dates compare lexicographically, which is why the format is fixed.
		return cerr.New(cerr.ECorpus008, id)
	}
	return nil
}

// validateCorrection enforces the structural half of INV-8: a correction block,
// when present, must be complete and must describe a genuine rise.
func validateCorrection(c *Correction, id string) error {
	if c == nil {
		return nil
	}
	if strings.TrimSpace(c.Reason) == "" || strings.TrimSpace(c.Evidence) == "" ||
		strings.TrimSpace(c.CorrectedAt) == "" || strings.TrimSpace(c.CorrectedBy) == "" {
		return cerr.New(cerr.ECorpus006, id)
	}
	if !validConfidence(c.From) || !validConfidence(c.To) {
		return cerr.New(cerr.ECorpus006, id)
	}
	if ConfidenceWeight(c.To) <= ConfidenceWeight(c.From) {
		// A "correction" that does not raise the confidence is not a correction.
		return cerr.New(cerr.ECorpus006, id)
	}
	return nil
}

// checkConfidenceRises is the full INV-8 check. It compares this corpus against
// the previous version and refuses a rise that has no correction block.
//
// WHY THIS MATTERS SO MUCH: without it, confidence laundering is trivial and
// invisible. A LOW guess becomes MEDIUM in one commit ("I'm fairly sure") and
// HIGH in another ("yes, definitely"), and nobody notices that no new evidence
// ever arrived. The rule makes the laundering path require a written, published
// reason — which is exactly the friction that prevents it.
func checkConfidenceRises(c *Corpus, prev *Corpus) error {
	if prev == nil {
		return nil
	}
	for _, e := range c.entries {
		old, ok := prev.Resolve(e.SPDXID)
		if !ok {
			continue
		}
		rose := ConfidenceWeight(e.Confidence) > ConfidenceWeight(old.Confidence)
		c.ConfidenceRises = append(c.ConfidenceRises, ConfidenceRise{
			EntryID:       e.ID,
			From:          old.Confidence,
			To:            e.Confidence,
			HasCorrection: e.Correction != nil,
		})
		if rose && e.Correction == nil {
			return cerr.New(cerr.ECorpus006, e.ID)
		}
		if rose && e.Correction != nil && e.Correction.From != old.Confidence {
			// The correction must name the level it is rising *from*. A
			// mismatch means the record does not describe this change.
			return cerr.New(cerr.ECorpus006, e.ID)
		}
	}
	sort.SliceStable(c.ConfidenceRises, func(i, j int) bool {
		return c.ConfidenceRises[i].EntryID < c.ConfidenceRises[j].EntryID
	})
	return nil
}

// wrapEntryError maps a parser or decoder failure to the corpus code, keeping
// the underlying message so the maintainer can fix the file.
func wrapEntryError(rel string, err error) error {
	if e, ok := cerr.As(err); ok {
		switch e.Code() {
		case cerr.EParse008, cerr.EParse009, cerr.EParse006, cerr.EParse010, cerr.EParse004:
			return e
		case cerr.EPolicy003, cerr.EPolicy004, cerr.EPolicy005:
			// A predicate bug is a corpus bug. It is reported with the policy
			// code, because that is what the maintainer has to fix.
			return e
		}
	}
	return cerr.New(cerr.ECorpus004, rel+" ("+err.Error()+")")
}

// StalenessDowngrade applies the ToS staleness rule (§3.1 of the confidence
// model): a platform entry whose last_verified is older than its staleness_days
// is downgraded one confidence level, because terms change without notice.
//
// It is a function rather than a load-time mutation so that it is testable
// against an injected date and cannot depend on the clock.
func StalenessDowngrade(lastVerified string, stalenessDays int, today string) (string, bool) {
	if stalenessDays <= 0 || lastVerified == "" || today == "" {
		return "", false
	}
	lv, err := time.Parse("2006-01-02", lastVerified)
	if err != nil {
		return "", false
	}
	t, err := time.Parse("2006-01-02", today)
	if err != nil {
		return "", false
	}
	age := int(t.Sub(lv).Hours() / 24)
	if age <= stalenessDays {
		return "", false
	}
	return "stale", true
}

// SPDXForEntry returns the identifier a lookup would use, for diagnostics.
func SPDXForEntry(e *Entry) string {
	if e == nil {
		return ""
	}
	return config.NormaliseSPDX(e.SPDXID)
}
