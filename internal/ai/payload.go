package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// Job is one of the three permitted uses of a model.
//
// # THE ENGINE DECIDES. THE MODEL EXPLAINS.
//
// These three are the complete list, and the list is the design. None of them
// can create, remove or alter a finding; all three run *after* the verdict
// exists and read only what the engine already produced.
//
//	explain   restates a finding in plain language for someone who is not a lawyer
//	remediate drafts a remediation plan — ordering, effort, alternatives
//	triage    says which document a human should open first, for an UNDETERMINED entry
type Job string

const (
	JobExplain   Job = "explain"
	JobRemediate Job = "remediate"
	JobTriage    Job = "triage"
)

// AllJobs is the complete set, in canonical order.
func AllJobs() []Job { return []Job{JobExplain, JobRemediate, JobTriage} }

// Valid reports whether j is one of the three.
func (j Job) Valid() bool {
	switch j {
	case JobExplain, JobRemediate, JobTriage:
		return true
	}
	return false
}

// Needs reports which part of the verdict a job reads. It is what lets the
// payload builder omit the parts a job does not need — a `triage` request
// carries no findings, so a model asked to triage cannot be handed a blocker
// and asked to comment on it.
func (j Job) Needs() (findings, undetermined bool) {
	switch j {
	case JobExplain, JobRemediate:
		return true, false
	case JobTriage:
		return false, true
	}
	return false, false
}

// Options is the `ai:` block of the config, resolved and validated.
type Options struct {
	Enabled           bool
	Provider          string
	Model             string
	Jobs              []Job
	BaseURL           string
	MaxTokens         int
	Timeout           time.Duration
	RedactProjectName bool

	// MaxResponseBytes caps the response body the transport will read. It is
	// not a config field: it is a safety bound, and a user who raised it would
	// be raising the ceiling on how much memory a hostile endpoint can make
	// the tool allocate.
	MaxResponseBytes int64
}

// DefaultOptions is the built-in default: Tier 0, the offline product.
//
// `Enabled: false` is the default and must remain so. The offline product is
// the product; every AI feature is additive and degrades to silence with a
// warning when it is absent.
func DefaultOptions() Options {
	return Options{
		Enabled:           false,
		Provider:          "openai",
		Jobs:              []Job{JobExplain},
		MaxTokens:         1024,
		Timeout:           30 * time.Second,
		RedactProjectName: true,
		MaxResponseBytes:  MaxResponseBytes,
	}
}

// MaxResponseBytes is the hard ceiling on a response body. 256 KiB is roughly
// two hundred times the largest legitimate response (a long remediation plan for
// a very large verdict), so it cannot refuse real work, and it bounds what a
// hostile or broken endpoint can make the tool hold in memory.
const MaxResponseBytes = 256 << 10

// JobEnabled reports whether j was requested. A job that was not requested may
// not run, and a response naming a job that was not requested is discarded
// whole (E-AI-005) rather than partially honoured — a model that volunteers an
// unrequested job is a model doing something other than what it was asked.
func (o Options) JobEnabled(j Job) bool {
	for _, want := range o.Jobs {
		if want == j {
			return true
		}
	}
	return false
}

// HTTPRequest is one outbound request, in the terms the AI layer needs and
// nothing more.
//
// # WHY THE TRANSPORT IS AN INTERFACE AND NOT net/http
//
// INV-3 as scoped by ADR-021 permits exactly one file in this repository to
// import net/http, and internal/arch_test.go enforces the count. The AI layer
// is L4 and pure, so it cannot be that file — and it should not want to be.
//
// Defining the transport as an interface has three consequences, all of them
// good:
//
//  1. The whole AI layer is testable with a stub and no socket. The spec's
//     `TestVerdictUnaffectedByAI` requires running the determinism test "with a
//     stub provider", which is only expressible if the transport is an
//     interface.
//  2. Every outbound request passes one host allowlist in one place, because
//     there is exactly one implementation.
//  3. The purity check in arch_test.go covers this package, so a future edit
//     cannot quietly give the decision path a socket.
type HTTPRequest struct {
	Method  string
	URL     string
	Headers [][2]string
	Body    []byte
}

// HTTPResponse is the reply, already size-bounded by the transport.
type HTTPResponse struct {
	Status int
	Body   []byte
}

// Transport performs one request. The only implementation is in internal/cli,
// which is the layer permitted to do I/O.
type Transport interface {
	Do(ctx context.Context, req HTTPRequest) (HTTPResponse, error)
}

// ─── the payload ─────────────────────────────────────────────────────────────

// payloadFinding is one finding, as the model sees it.
//
// # WHAT IS HERE, AND WHAT IS NOT
//
// The model receives text the engine already produced. It never receives a file
// from the project. There is no field for file contents and there will not be
// one: a payload builder that read a file would be a payload builder that could
// upload a repository, and the spec's AI-8 control asserts the builder's inputs
// are exactly the verdict and the intent.
//
// The citation is carried in full — URL and section — because a finding's whole
// value is that it quotes a clause. An explanation of a finding whose clause is
// withheld is an explanation of a label.
type payloadFinding struct {
	ID              string   `json:"id"`
	Dependency      string   `json:"dependency"`
	Kind            string   `json:"kind"`
	Severity        string   `json:"severity"`
	Confidence      string   `json:"confidence"`
	Licence         string   `json:"licence"`
	Title           string   `json:"title"`
	Reason          string   `json:"reason"`
	CitationURL     string   `json:"citation_url"`
	CitationSection string   `json:"citation_section"`
	EvidencePaths   []string `json:"evidence_paths,omitempty"`
}

// payloadUndetermined is one gap, as the model sees it.
type payloadUndetermined struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Reason    string   `json:"reason"`
	Detail    string   `json:"detail"`
	ErrorCode string   `json:"error_code"`
	Paths     []string `json:"paths,omitempty"`
}

// payloadIntent is the declared intent, as the model sees it.
//
// It is the *declaration*, not the project. "commercial: true, saas: false" is
// a fact the user wrote in a config file; it is not a fact about their code.
type payloadIntent struct {
	Commercial     bool     `json:"commercial"`
	LicenceModel   string   `json:"licence_model"`
	Modified       bool     `json:"modified"`
	NetworkExposed bool     `json:"network_exposed"`
	Distributed    bool     `json:"distributed"`
	SaaS           bool     `json:"saas"`
	Territories    []string `json:"territories"`
}

// Payload is exactly what leaves the machine.
type Payload struct {
	SchemaVersion int                   `json:"schema_version"`
	Job           Job                   `json:"job"`
	Verdict       string                `json:"verdict"`
	Project       string                `json:"project"`
	Intent        payloadIntent         `json:"intent"`
	Findings      []payloadFinding      `json:"findings,omitempty"`
	Undetermined  []payloadUndetermined `json:"undetermined,omitempty"`
}

// BuildPayload assembles the payload for one job.
//
// It is a pure function of (job, verdict, intent, options). It reads no file,
// opens no socket, and consults no clock. That is what makes AI-8 — "the
// payload contains no file contents" — checkable by inspection of a signature
// rather than by auditing every call site.
func BuildPayload(job Job, v verdict.Verdict, in *config.Intent, opts Options) (Payload, error) {
	if !job.Valid() {
		return Payload{}, cerr.New(cerr.EAi005, "unknown job "+string(job))
	}

	p := Payload{
		SchemaVersion: 1,
		Job:           job,
		Verdict:       string(v.Verdict),
		Project:       projectLabel(v.Project, opts),
		Intent:        intentView(in),
	}

	wantFindings, wantUndetermined := job.Needs()

	if wantFindings {
		// The order is the verdict's order — blockers, then conditions, then
		// notes — because that is the order of importance, and a model reading
		// a list reads the top of it most carefully.
		for _, group := range [][]findingView{
			findingViews(v.Blockers), findingViews(v.Conditions), findingViews(v.Notes),
		} {
			for _, f := range group {
				p.Findings = append(p.Findings, payloadFinding{
					ID:              f.ID,
					Dependency:      f.DependencyID,
					Kind:            f.Kind,
					Severity:        f.Severity,
					Confidence:      f.Confidence,
					Licence:         f.Licence,
					Title:           f.Title,
					Reason:          f.Reason,
					CitationURL:     f.CitationURL,
					CitationSection: f.CitationSection,
					EvidencePaths:   safePaths(f.Paths),
				})
			}
		}
	}

	if wantUndetermined {
		for _, u := range v.Undetermined {
			var paths []string
			for _, e := range u.Evidence {
				paths = append(paths, e.Path)
			}
			p.Undetermined = append(p.Undetermined, payloadUndetermined{
				ID:        u.ID,
				Kind:      string(u.Kind),
				Reason:    u.Reason,
				Detail:    u.Detail,
				ErrorCode: u.ErrorCode,
				Paths:     safePaths(paths),
			})
		}
	}

	return p, nil
}

// findingView is the subset of a finding the payload builder reads, flattened
// out of policy.Finding so that the builder does not depend on the policy
// package's shape. It also makes the "no file contents" property visible: there
// is no field here that could carry one.
type findingView struct {
	ID, DependencyID, Kind, Severity, Confidence, Licence, Title, Reason string
	CitationURL, CitationSection                                         string
	Paths                                                                []string
}

func findingViews(fs []policy.Finding) []findingView {
	out := make([]findingView, 0, len(fs))
	for _, f := range fs {
		paths := make([]string, 0, len(f.Evidence))
		for _, e := range f.Evidence {
			paths = append(paths, e.Path)
		}
		out = append(out, findingView{
			ID:              f.ID,
			DependencyID:    f.DependencyID,
			Kind:            f.Kind,
			Severity:        string(f.Severity),
			Confidence:      string(f.Confidence),
			Licence:         f.Licence,
			Title:           f.Title,
			Reason:          f.Reason,
			CitationURL:     f.Citation.URL,
			CitationSection: f.Citation.Section,
			Paths:           paths,
		})
	}
	return out
}

// safePaths keeps only paths that are safe to send: relative, with no traversal
// and no absolute prefix.
//
// An evidence path is produced by the scanner and is already project-relative
// (graph.Evidence documents "project-relative, always"), so this should be a
// no-op on every real input. It is here anyway because the cost of being wrong
// is a user's home directory and username leaving their machine, and the cost of
// the check is a string comparison. A defence that only matters when another
// component is wrong is still worth having when it is this cheap.
func safePaths(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "..") {
			continue
		}
		if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") {
			continue
		}
		// A Windows drive letter, e.g. C:\Users\…
		if len(p) >= 2 && p[1] == ':' {
			continue
		}
		out = append(out, p)
	}
	return out
}

// projectLabel is the project's name, or a pronoun when the user asked for
// redaction.
//
// The default is `true`. A project name is often a company name, a product name
// or a codename, and it is the one field in the payload that is not already
// public — every other field is either a licence identifier or a clause citation
// that anyone could look up.
func projectLabel(name string, opts Options) string {
	if opts.RedactProjectName {
		return "the project"
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "the project"
	}
	return name
}

// intentView copies the declared intent into the payload.
//
// A nil intent is not an error: a verdict can exist without one in a test, and
// the model is told the truth ("everything is false") rather than being told a
// lie about a declaration nobody made. `Declared` is deliberately not consulted
// — the model is explaining a verdict the engine already reached under this
// intent, so what it needs is the values the engine used, not which of them were
// written down.
func intentView(in *config.Intent) payloadIntent {
	if in == nil {
		return payloadIntent{}
	}
	terr := make([]string, 0, len(in.Territories))
	for _, t := range in.Territories {
		if s := strings.TrimSpace(t); s != "" {
			terr = append(terr, s)
		}
	}
	sort.Strings(terr)
	return payloadIntent{
		Commercial:     in.Use.Commercial,
		LicenceModel:   string(in.Use.LicenceModel),
		Modified:       in.Use.Modified,
		NetworkExposed: in.Use.NetworkExposed,
		Distributed:    in.Use.Distributed,
		SaaS:           in.Use.SaaS,
		Territories:    terr,
	}
}

// ─── the request ─────────────────────────────────────────────────────────────

// BuildRequest renders a payload into the provider's wire shape.
//
// It is the only place the key is used, and the only place the provider's
// quirks live: Anthropic's `x-api-key` plus version header, Google's
// `x-goog-api-key` and `models/{model}:generateContent` path, Azure's
// deployment path and `api-key` header. Adding a provider is a row in the table
// and a case here, never a new client.
func BuildRequest(p Provider, model string, key Secret, opts Options, pl Payload) (HTTPRequest, error) {
	base := p.Base(opts.BaseURL)
	if base == "" {
		// Only reachable for a provider whose endpoint is user-specific and
		// whose base_url was not supplied. E-AI-009 covers the opposite
		// mistake; this is the missing half, reported with the same code
		// because the fix is the same field.
		return HTTPRequest{}, cerr.New(cerr.EAi009, p.ID)
	}
	if model == "" {
		model = p.DefaultModel
	}
	if model == "" {
		return HTTPRequest{}, cerr.New(cerr.EAi009, p.ID)
	}

	// The payload is embedded as a *string* of JSON inside the message rather
	// than as structured content, so that the model sees the exact bytes the
	// user could inspect with `--ai-dump`. A payload smuggled through the
	// provider's own JSON would be a payload nobody can audit.
	body, err := json.Marshal(pl)
	if err != nil {
		// A marshal failure over a struct of strings and bools is a bug, not a
		// condition, but it still has to be typed (INV-5).
		return HTTPRequest{}, cerr.Wrap(cerr.EAi005, err, "the payload could not be serialised")
	}

	req := HTTPRequest{Method: "POST"}
	var envelope any

	switch p.Wire {
	case WireAnthropic:
		req.URL = base + "/messages"
		envelope = map[string]any{
			"model":       model,
			"max_tokens":  opts.MaxTokens,
			"temperature": 0,
			"system":      systemPrompt(pl.Job),
			"messages": []any{
				map[string]any{"role": "user", "content": userPrompt(pl.Job, string(body))},
			},
		}
	case WireGoogle:
		req.URL = base + "/models/" + model + ":generateContent"
		envelope = map[string]any{
			"systemInstruction": map[string]any{
				"parts": []any{map[string]any{"text": systemPrompt(pl.Job)}},
			},
			"contents": []any{
				map[string]any{
					"role":  "user",
					"parts": []any{map[string]any{"text": userPrompt(pl.Job, string(body))}},
				},
			},
			"generationConfig": map[string]any{
				"temperature":      0,
				"maxOutputTokens":  opts.MaxTokens,
				"responseMimeType": "application/json",
			},
		}
	case WireOpenAI:
		switch {
		case p.ID == "azure-openai":
			req.URL = base + "/openai/deployments/" + model +
				"/chat/completions?api-version=" + p.APIVersion
		default:
			req.URL = base + "/chat/completions"
		}
		envelope = map[string]any{
			"model":       model,
			"max_tokens":  opts.MaxTokens,
			"temperature": 0,
			// The response is asked for as JSON so that validation is a parse
			// rather than a hunt for a fenced code block. A provider that does
			// not support the field ignores it, and the validator copes with a
			// fenced block anyway.
			"response_format": map[string]any{"type": "json_object"},
			"messages": []any{
				map[string]any{"role": "system", "content": systemPrompt(pl.Job)},
				map[string]any{"role": "user", "content": userPrompt(pl.Job, string(body))},
			},
		}
	default:
		return HTTPRequest{}, cerr.New(cerr.EAi007, p.ID)
	}

	enc, err := json.Marshal(envelope)
	if err != nil {
		return HTTPRequest{}, cerr.Wrap(cerr.EAi005, err, "the request could not be serialised")
	}
	req.Body = enc

	req.Headers = append(req.Headers, [2]string{"content-type", "application/json"})
	req.Headers = append(req.Headers, [2]string{"accept", "application/json"})

	switch p.Auth {
	case AuthBearer:
		if key.Set() {
			var hdr [2]string
			if err := key.Use(func(raw string) error {
				hdr = [2]string{"authorization", "Bearer " + raw}
				return nil
			}); err != nil {
				return HTTPRequest{}, cerr.Wrap(cerr.EAi001, err, p.ID)
			}
			req.Headers = append(req.Headers, hdr)
		}
	case AuthXAPIKey:
		if err := key.Use(func(raw string) error {
			req.Headers = append(req.Headers, [2]string{"x-api-key", raw})
			return nil
		}); err != nil {
			return HTTPRequest{}, cerr.Wrap(cerr.EAi001, err, p.ID)
		}
		if p.VersionHeader != "" {
			req.Headers = append(req.Headers, [2]string{"anthropic-version", p.VersionHeader})
		}
	case AuthGoogle:
		if err := key.Use(func(raw string) error {
			req.Headers = append(req.Headers, [2]string{"x-goog-api-key", raw})
			return nil
		}); err != nil {
			return HTTPRequest{}, cerr.Wrap(cerr.EAi001, err, p.ID)
		}
	case AuthAzureKey:
		if err := key.Use(func(raw string) error {
			req.Headers = append(req.Headers, [2]string{"api-key", raw})
			return nil
		}); err != nil {
			return HTTPRequest{}, cerr.Wrap(cerr.EAi001, err, p.ID)
		}
	case AuthNone:
		// The local runtimes take no credential. Nothing to add, and nothing
		// to complain about — a keyless tier that demanded a key would not be
		// keyless.
	}

	// A key that was required and is absent is E-AI-001, and it is FATAL: the
	// user asked for AI explicitly, and silently proceeding without one would
	// produce a run that looks like it worked.
	if !p.Keyless && p.Auth != AuthNone && !key.Set() {
		return HTTPRequest{}, cerr.New(cerr.EAi001, p.ID, keyEnvName(p))
	}

	return req, nil
}

// keyEnvName is the variable to tell the user to set.
func keyEnvName(p Provider) string {
	if p.KeyEnv != "" {
		return p.KeyEnv
	}
	return "CLEARANCE_AI_API_KEY"
}

// systemPrompt is the instruction. It is short on purpose.
//
// # WHY THIS PROMPT IS SO BORING
//
// The model has exactly one job here, and the job does not need a persona. What
// the prompt must do is state the boundary in terms the model cannot
// misunderstand: it explains, it does not decide. Everything else — tone,
// length, structure — is left to the model, because a prompt that over-specifies
// produces an answer that reads like a template, and a template is what the user
// already had.
//
// The last line is the load-bearing one. It is not a security control (the
// control is `Attach`, which refuses any attempt structurally); it is a
// courtesy, so that a model which *would* have tried to re-decide instead
// answers the question it was asked.
func systemPrompt(j Job) string {
	base := "You are helping a developer understand a software licence verdict that has already been decided " +
		"by a deterministic offline engine. You are not the decision-maker. " +
		"You must not invent facts, licences, clauses or URLs; if something is not in the data you were given, " +
		"say that it is not available. Be concise and concrete. Write for a developer who is not a lawyer."

	switch j {
	case JobExplain:
		return base + " Explain each finding in plain language: what the obligation is, " +
			"what it requires of this project given the declared intent, and what the practical consequence is. " +
			"Do not repeat the citation text verbatim; explain it. " +
			"Respond with JSON only, matching the schema you are given."
	case JobRemediate:
		return base + " For the findings you were given, produce a remediation plan: what to do, " +
			"in what order, at what rough effort, and — where a permissively-licensed alternative to the " +
			"offending dependency is widely known — name it. Only name an alternative you are confident exists. " +
			"Respond with JSON only, matching the schema you are given."
	case JobTriage:
		return base + " You are given the entries the engine could not resolve. For each, say which single " +
			"document or file a human should open first to resolve it, and why. " +
			"Respond with JSON only, matching the schema you are given."
	}
	return base + " Respond with JSON only."
}

// userPrompt wraps the payload in the response schema the job expects.
//
// The schema is repeated in the prompt rather than being described in prose
// because a model given a literal example of the shape it must return is far
// more likely to return it, and every response that has to be discarded for
// being the wrong shape is an explanation the user paid for and did not get.
func userPrompt(j Job, payloadJSON string) string {
	var shape string
	switch j {
	case JobExplain:
		shape = `{"schema_version":1,"job":"explain","findings":[{"id":"<the finding id, exactly as given>","explanation":"<plain-language explanation>"}]}`
	case JobRemediate:
		shape = `{"schema_version":1,"job":"remediate","remediation":[{"finding_id":"<the finding id, exactly as given>","action":"<what to do>","effort":"low|medium|high","alternative":"<a permissively-licensed alternative, or omit>"}]}`
	case JobTriage:
		shape = `{"schema_version":1,"job":"triage","triage":[{"id":"<the undetermined id, exactly as given>","read_first":"<the one document to open first>","why":"<why that document>"}]}`
	default:
		shape = `{"schema_version":1}`
	}

	return fmt.Sprintf(
		"Here is the verdict data as JSON:\n\n%s\n\n"+
			"Return a single JSON object with exactly this shape:\n\n%s\n\n"+
			"Use the ids exactly as they appear above. Do not add findings, remove findings, "+
			"or change any severity or confidence — the verdict is final and your output is an explanation of it.",
		payloadJSON, shape)
}
