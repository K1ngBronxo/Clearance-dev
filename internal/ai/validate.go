package ai

import (
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/safejson"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// Notice is a non-fatal event from the AI layer. It carries a taxonomy code so
// that the user can look it up, exactly like every other message the product
// prints (INV-5).
type Notice struct {
	Code    cerr.Code
	Message string
}

// Usage records what the call cost, in tokens.
//
// There is no prompt column and no response column. Metering records tokens and
// never content, so there is no retained prompt to leak — which is the same
// rule the cloud tier's usage table follows, applied locally.
type Usage struct {
	TokensIn  int
	TokensOut int
}

// Explanation is one finding, explained.
type Explanation struct {
	ID          string `json:"id"`
	Explanation string `json:"explanation"`
}

// Remediation is one action, for one finding.
type Remediation struct {
	FindingID   string `json:"finding_id"`
	Action      string `json:"action"`
	Effort      string `json:"effort"`
	Alternative string `json:"alternative,omitempty"`

	// Verified is set by Attach, never by the model. It is true when the named
	// alternative is a licence identifier the corpus knows, and false when the
	// model named something the corpus cannot confirm. A false here is not a
	// refusal — the suggestion is kept — but it is printed, because a
	// hallucinated package name presented with the same confidence as a real
	// one is exactly the failure this product exists to replace.
	Verified bool `json:"verified"`
}

// Triage is one undetermined entry, and where to start.
type Triage struct {
	ID        string `json:"id"`
	ReadFirst string `json:"read_first"`
	Why       string `json:"why"`
}

// Override is an attempt to change the verdict.
//
// # WHY A TYPE EXISTS FOR SOMETHING THAT IS ALWAYS REFUSED
//
// The obvious design is to have no such field, so that the wire schema simply
// cannot express the attempt. That design is worse, for two reasons.
//
// First, it is a lie about the protocol. A model is a text generator; it can put
// anything in its JSON. If the field is not in the schema the attempt arrives as
// an unknown key, which is silently dropped — and a silent drop is
// indistinguishable from a model that behaved. The operator learns nothing.
//
// Second, the spec's `TestAICannotAlterAVerdict` requires feeding `Attach` a
// suggestion "that tries all three" operations — add, delete and re-severity —
// and asserting the verdict is unchanged *and* that E-AI-006 fired three times.
// That test cannot be written against a schema that cannot express the attempt.
//
// So the field exists, `Attach` refuses every instance of it with E-AI-006, and
// the refusal is counted and reported. The model may ask. The answer is no, and
// the answer is on the record.
type Override struct {
	FindingID  string `json:"finding_id"`
	Op         string `json:"op"` // add | remove | severity | confidence
	Severity   string `json:"severity,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// Suggestion is a validated model response.
//
// It is deliberately not part of the Verdict type and never will be. The spec's
// §6.3 is absolute on this point: `verdict.json` contains no AI output, ever.
// The reason is INV-6 — a verdict must be byte-identical across runs on the same
// inputs, and a model is non-deterministic by nature. Keeping AI output in a
// separate artefact means the AI feature cannot break the determinism invariant
// even if it is buggy: the guarantee is preserved by construction rather than by
// care.
type Suggestion struct {
	SchemaVersion int           `json:"schema_version"`
	Job           Job           `json:"job"`
	Findings      []Explanation `json:"findings,omitempty"`
	Remediation   []Remediation `json:"remediation,omitempty"`
	Triage        []Triage      `json:"triage,omitempty"`

	// Overrides is parsed from the response and emptied by Attach. A non-empty
	// Overrides on a Suggestion that has been through Attach would be a bug.
	Overrides []Override `json:"overrides,omitempty"`

	// Provider and Model are set by the caller from the request, not read from
	// the response: a model's claim about its own identity is not evidence.
	Provider string `json:"provider"`
	Model    string `json:"model"`

	Usage Usage `json:"usage"`
}

// Empty reports whether the suggestion carries nothing usable. A response that
// validated to nothing is not an error — it is an explanation that did not
// arrive, and the verdict is unaffected either way.
func (s Suggestion) Empty() bool {
	return len(s.Findings) == 0 && len(s.Remediation) == 0 && len(s.Triage) == 0
}

// ─── extraction ──────────────────────────────────────────────────────────────

// Extract pulls the assistant's text and the token usage out of the provider's
// response envelope.
//
// Three envelope shapes, one function, because the difference between them is
// three field names and not a different problem. A provider that returned an
// error inside a 200 — which several do — is caught here and reported as
// E-AI-002 with the provider's own message, redacted.
func Extract(p Provider, body []byte, key Secret) (string, Usage, error) {
	var usage Usage

	obj, err := safejson.DecodeObject(body, safejson.DefaultLimits())
	if err != nil {
		return "", usage, cerr.Wrap(cerr.EAi005, err,
			"the response was not valid JSON")
	}

	// A provider that reports its failure in the body rather than the status
	// line. Anthropic and Google both do this, and the shape differs, so the
	// check is "is there an `error` object at the top level" rather than a
	// per-provider branch.
	if e, ok := obj.Get("error"); ok {
		if eo, isObj := e.(safejson.Object); isObj {
			msg := eo.String("message")
			if msg == "" {
				msg = eo.String("status")
			}
			return "", usage, cerr.New(cerr.EAi002, p.ID,
				redactAll(msg, key))
		}
		if s, isStr := e.(string); isStr {
			return "", usage, cerr.New(cerr.EAi002, p.ID, redactAll(s, key))
		}
	}

	switch p.Wire {
	case WireAnthropic:
		usage = Usage{
			TokensIn:  intOf(obj.Object("usage"), "input_tokens"),
			TokensOut: intOf(obj.Object("usage"), "output_tokens"),
		}
		for _, block := range obj.Array("content") {
			bo, ok := block.(safejson.Object)
			if !ok {
				continue
			}
			if bo.String("type") == "text" {
				if t := bo.String("text"); t != "" {
					return t, usage, nil
				}
			}
		}
		return "", usage, cerr.New(cerr.EAi005,
			"the response carried no text block")

	case WireGoogle:
		md := obj.Object("usageMetadata")
		usage = Usage{
			TokensIn:  intOf(md, "promptTokenCount"),
			TokensOut: intOf(md, "candidatesTokenCount"),
		}
		for _, cand := range obj.Array("candidates") {
			co, ok := cand.(safejson.Object)
			if !ok {
				continue
			}
			for _, part := range co.Object("content").Array("parts") {
				po, ok := part.(safejson.Object)
				if !ok {
					continue
				}
				if t := po.String("text"); t != "" {
					return t, usage, nil
				}
			}
		}
		return "", usage, cerr.New(cerr.EAi005,
			"the response carried no text part")

	default: // WireOpenAI
		u := obj.Object("usage")
		usage = Usage{
			TokensIn:  intOf(u, "prompt_tokens"),
			TokensOut: intOf(u, "completion_tokens"),
		}
		for _, choice := range obj.Array("choices") {
			co, ok := choice.(safejson.Object)
			if !ok {
				continue
			}
			// `content` is null on a tool-call or a filtered response; the
			// empty string falls through to the error below rather than
			// returning a blank explanation that looks like a real one.
			if t := co.Object("message").String("content"); t != "" {
				return t, usage, nil
			}
			if fr := co.String("finish_reason"); fr == "content_filter" {
				return "", usage, cerr.New(cerr.EAi005,
					"the provider filtered the response (finish_reason: content_filter)")
			}
		}
		return "", usage, cerr.New(cerr.EAi005,
			"the response carried no message content")
	}
}

// redactAll scrubs the key out of provider-supplied text.
//
// A provider that echoes the key back in an error message is rare and not
// hypothetical, and this is the one place where text Clearance did not write
// reaches a terminal.
func redactAll(text string, keys ...Secret) string {
	return Redact(text, keys...)
}

// ─── parsing ─────────────────────────────────────────────────────────────────

// maxFieldLen bounds any single string the model returns.
//
// A model that answers a question about a clause with a 40 KB essay has not
// answered the question, and the essay would be printed into a terminal. The
// bound is generous — 4 KB is roughly 600 words — so it can only ever truncate
// something that was already unusable.
const maxFieldLen = 4096

// ParseSuggestion turns the assistant's text into a Suggestion.
//
// It is deliberately forgiving about packaging and strict about content. A model
// that wraps its JSON in a ```json fence has still answered the question, and
// discarding that answer would be pedantry; a model that returns a finding id
// that does not exist has not, and `Attach` removes it.
func ParseSuggestion(job Job, text string) (Suggestion, error) {
	raw := stripFence(strings.TrimSpace(text))
	if raw == "" {
		return Suggestion{}, cerr.New(cerr.EAi005, "the response was empty")
	}

	obj, err := safejson.DecodeObject([]byte(raw), safejson.DefaultLimits())
	if err != nil {
		return Suggestion{}, cerr.Wrap(cerr.EAi005, err,
			"the response was not the JSON object it was asked for")
	}

	s := Suggestion{SchemaVersion: 1}

	// The job the response claims must be the job that was requested. A model
	// that answers a different question is not a model whose answer should be
	// partly kept.
	claimed := Job(strings.TrimSpace(obj.String("job")))
	if claimed == "" {
		claimed = job
	}
	if claimed != job {
		return Suggestion{}, cerr.New(cerr.EAi005,
			"the response names job '"+string(claimed)+"' but '"+string(job)+"' was requested")
	}
	s.Job = job

	for _, f := range obj.Array("findings") {
		fo, ok := f.(safejson.Object)
		if !ok {
			continue
		}
		id := strings.TrimSpace(fo.String("id"))
		ex := clip(fo.String("explanation"))
		if id == "" || ex == "" {
			continue
		}
		s.Findings = append(s.Findings, Explanation{ID: id, Explanation: ex})
	}

	for _, r := range obj.Array("remediation") {
		ro, ok := r.(safejson.Object)
		if !ok {
			continue
		}
		fid := strings.TrimSpace(ro.String("finding_id"))
		if fid == "" {
			continue
		}
		effort := strings.ToLower(strings.TrimSpace(ro.String("effort")))
		switch effort {
		case "low", "medium", "high":
		default:
			// An unrecognised effort is dropped rather than guessed at. The
			// field is a hint, and a wrong hint is worse than an absent one.
			effort = ""
		}
		s.Remediation = append(s.Remediation, Remediation{
			FindingID:   fid,
			Action:      clip(ro.String("action")),
			Effort:      effort,
			Alternative: clip(ro.String("alternative")),
		})
	}

	for _, t := range obj.Array("triage") {
		to, ok := t.(safejson.Object)
		if !ok {
			continue
		}
		id := strings.TrimSpace(to.String("id"))
		if id == "" {
			continue
		}
		s.Triage = append(s.Triage, Triage{
			ID:        id,
			ReadFirst: clip(to.String("read_first")),
			Why:       clip(to.String("why")),
		})
	}

	for _, o := range obj.Array("overrides") {
		oo, ok := o.(safejson.Object)
		if !ok {
			continue
		}
		s.Overrides = append(s.Overrides, Override{
			FindingID:  strings.TrimSpace(oo.String("finding_id")),
			Op:         strings.ToLower(strings.TrimSpace(oo.String("op"))),
			Severity:   strings.ToUpper(strings.TrimSpace(oo.String("severity"))),
			Confidence: strings.ToUpper(strings.TrimSpace(oo.String("confidence"))),
		})
	}

	return s, nil
}

// clip bounds a field and strips control characters.
//
// Control characters matter more than length here: a response containing ESC
// sequences would be printed into a terminal, and a model that emitted
// `\x1b[2J` would clear the user's screen in the middle of their verdict. The
// renderer is the last line of defence and does its own escaping; this is the
// first, and both are cheap.
func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r < 0x20, r == 0x7f:
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > maxFieldLen {
		s = strings.ToValidUTF8(s[:maxFieldLen], "") + "…"
	}
	return s
}

// stripFence removes a Markdown code fence around a JSON document.
//
// The prompt asks for JSON and most providers honour it, but a local runtime
// with a small model often wraps the answer in a fence because that is what its
// training data looks like. Refusing the answer would be a pedantic failure with
// a real cost, so the fence is removed and the content is judged on its merits.
func stripFence(s string) string {
	if !strings.HasPrefix(s, "```") {
		return s
	}
	// Drop the opening fence and its optional language tag.
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	} else {
		return ""
	}
	if i := strings.LastIndex(s, "```"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// ─── the guard ───────────────────────────────────────────────────────────────

// LicenceOracle reports whether a licence identifier is one the corpus knows.
//
// It is an interface rather than a corpus import because the AI layer must be
// testable without a corpus, and because the *only* thing it needs from the
// corpus is this one yes/no question.
type LicenceOracle interface {
	KnowsLicence(spdxID string) bool
}

// Attach is the only function that accepts a Suggestion, and it is the whole of
// the enforcement for the spec's §1 governing rule.
//
// It returns the suggestion with every unacceptable element removed, plus a
// notice for each removal. The verdict is not passed by pointer and is not
// returned: this function cannot change a verdict, because it has no way to
// express the change.
//
// # THE THREE REFUSALS
//
//  1. An Override — any attempt to add, remove or re-severity a finding —
//     is refused with E-AI-006 and counted. This is the INV-1 guard: a model
//     that can remove a blocker is a model that can turn DO NOT SHIP into SHIP,
//     and the product's entire value is that it cannot.
//
//  2. An explanation whose id is not in the verdict is dropped with E-AI-005.
//     A model that explains a finding that does not exist has invented it, and
//     an invented finding presented to a user is the worst output this feature
//     could produce.
//
//  3. A job that was not requested. The caller checks this before the request;
//     Attach checks it again on the way back, because the response is the
//     untrusted half.
//
// # WHY IT TAKES THE VERDICT RATHER THAN AN ID SET
//
// Because the ids have to come from the same object the user will read. A caller
// that built the id set itself could pass a set that disagrees with the verdict
// — through a stale variable, or a filter applied to one and not the other — and
// the result would be a suggestion that validates against a verdict the user
// never sees.
func Attach(v verdict.Verdict, s Suggestion, opts Options, oracle LicenceOracle) (Suggestion, []Notice) {
	var notices []Notice

	// (3) The job must have been requested.
	if !s.Job.Valid() {
		return Suggestion{}, []Notice{{
			Code:    cerr.EAi005,
			Message: "the response named no valid job and was discarded",
		}}
	}
	if !opts.JobEnabled(s.Job) {
		return Suggestion{}, []Notice{{
			Code: cerr.EAi005,
			Message: "the response named job '" + string(s.Job) +
				"', which was not requested, and was discarded",
		}}
	}

	// (1) The overrides. Every one is refused, and every refusal is reported.
	// A silent refusal would be indistinguishable from compliance.
	if n := len(s.Overrides); n > 0 {
		for _, o := range s.Overrides {
			id := o.FindingID
			if id == "" {
				id = "(no id given)"
			}
			notices = append(notices, Notice{
				Code: cerr.EAi006,
				Message: "the model attempted to " + overrideVerb(o.Op) +
					" finding '" + id + "'; the attempt was refused and the verdict is unchanged",
			})
		}
		s.Overrides = nil
	}

	// (2) Ids that are not in the verdict.
	known := findingIDs(v)
	knownUndet := undeterminedIDs(v)

	kept := s.Findings[:0]
	for _, f := range s.Findings {
		if !known[f.ID] {
			notices = append(notices, Notice{
				Code: cerr.EAi005,
				Message: "discarded an explanation for '" + f.ID +
					"', which is not a finding in this verdict",
			})
			continue
		}
		kept = append(kept, f)
	}
	s.Findings = kept

	keptRem := s.Remediation[:0]
	for _, r := range s.Remediation {
		if !known[r.FindingID] {
			notices = append(notices, Notice{
				Code: cerr.EAi005,
				Message: "discarded a remediation for '" + r.FindingID +
					"', which is not a finding in this verdict",
			})
			continue
		}
		r.Verified = alternativeVerified(r.Alternative, oracle)
		keptRem = append(keptRem, r)
	}
	s.Remediation = keptRem

	keptTri := s.Triage[:0]
	for _, t := range s.Triage {
		if !knownUndet[t.ID] {
			notices = append(notices, Notice{
				Code: cerr.EAi005,
				Message: "discarded a triage entry for '" + t.ID +
					"', which is not an undetermined record in this verdict",
			})
			continue
		}
		keptTri = append(keptTri, t)
	}
	s.Triage = keptTri

	return s, notices
}

// intOf reads an integer field, treating an absent or non-numeric value as 0.
//
// Token counts are metering, not judgement: a provider that omits them, or
// returns them as a string, must not fail a call that otherwise succeeded. Zero
// is the honest answer to "how many tokens did you use?" when the provider did
// not say.
func intOf(o safejson.Object, key string) int {
	if n, ok := o.Int(key); ok {
		return int(n)
	}
	return 0
}

// overrideVerb names the operation for the message.
func overrideVerb(op string) string {
	switch op {
	case "add", "create":
		return "add a finding"
	case "remove", "delete", "suppress":
		return "remove a finding"
	case "severity":
		return "change the severity of"
	case "confidence":
		return "change the confidence of"
	}
	return "alter"
}

// alternativeVerified reports whether a named alternative is confirmable.
//
// An empty alternative is not "unverified" — there is nothing to verify, and
// marking it would put a warning next to a blank field. A non-empty alternative
// is verified only when the oracle recognises it, and an oracle that cannot
// answer (nil) yields false, because "we could not check" must never render as
// "we checked and it is fine".
func alternativeVerified(alt string, oracle LicenceOracle) bool {
	if strings.TrimSpace(alt) == "" {
		return true
	}
	if oracle == nil {
		return false
	}
	return oracle.KnowsLicence(alternativeSPDX(alt))
}

// alternativeSPDX pulls the licence identifier out of an alternative string.
//
// Models write alternatives in the shape the product's own corpus does —
// "crawl4ai (Apache-2.0)" — so the identifier is the last parenthesised run, and
// the whole string is the fallback when there is no parenthesis. Both are
// guesses, which is why the answer only ever marks a suggestion `verified` and
// never suppresses one.
func alternativeSPDX(alt string) string {
	alt = strings.TrimSpace(alt)
	if i := strings.LastIndex(alt, "("); i >= 0 {
		if j := strings.LastIndex(alt, ")"); j > i {
			if inner := strings.TrimSpace(alt[i+1 : j]); inner != "" {
				return inner
			}
		}
	}
	return alt
}

// findingIDs is the set of every finding id in the verdict, across all three
// severity groups. A finding in Notes is as real as one in Blockers, and a
// suggestion about a demoted LOW finding must be accepted — otherwise the AI
// layer would silently refuse to explain exactly the findings a user is most
// confused by.
func findingIDs(v verdict.Verdict) map[string]bool {
	out := make(map[string]bool, len(v.Blockers)+len(v.Conditions)+len(v.Notes))
	for _, group := range [][]policy.Finding{
		v.Blockers, v.Conditions, v.Notes,
	} {
		for _, f := range group {
			out[f.ID] = true
		}
	}
	return out
}

// undeterminedIDs is the set of undetermined ids.
func undeterminedIDs(v verdict.Verdict) map[string]bool {
	out := make(map[string]bool, len(v.Undetermined))
	for _, u := range v.Undetermined {
		out[u.ID] = true
	}
	return out
}
