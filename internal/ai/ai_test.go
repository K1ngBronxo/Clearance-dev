package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/cite"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// ─── fixtures ────────────────────────────────────────────────────────────────

// canary is a key-shaped string that must never appear in any output. It is not
// a real key and cannot be mistaken for one: the prefix makes it greppable, and
// the test that uses it greps every rendering the package can produce.
const canary = "sk-CANARY-0000000000000000000000000000"

func testVerdict() verdict.Verdict {
	return verdict.Fold(verdict.Input{
		Findings: []policy.Finding{
			{
				ID:           "npm:firecrawl@1.2.3#agpl-network-use",
				DependencyID: "npm:firecrawl@1.2.3",
				Kind:         "licence.network-copyleft",
				Severity:     policy.SeverityBlock,
				Confidence:   policy.ConfidenceHigh,
				Title:        "AGPL-3.0 in a network-exposed service",
				Reason:       "The AGPL requires source disclosure to network users.",
				Licence:      "AGPL-3.0-only",
				Citation: cite.Citation{
					URL:         "https://www.gnu.org/licenses/agpl-3.0.txt",
					Section:     "Section 13",
					Excerpt:     "you must offer all users interacting with it over a network the opportunity to receive the Corresponding Source",
					ExcerptKind: cite.ExcerptVerbatim,
				},
				Evidence: []graph.Evidence{
					{Path: "package-lock.json", LineStart: 12, LineEnd: 14},
				},
			},
			{
				ID:           "npm:leftpad@1.0.0#attribution",
				DependencyID: "npm:leftpad@1.0.0",
				Kind:         "licence.attribution",
				Severity:     policy.SeverityCondition,
				Confidence:   policy.ConfidenceMedium,
				Title:        "Attribution required",
				Reason:       "The MIT licence requires the copyright notice be retained.",
				Licence:      "MIT",
				Citation: cite.Citation{
					URL:         "https://opensource.org/license/mit",
					Section:     "Permission notice",
					ExcerptKind: cite.ExcerptParaphrase,
				},
			},
		},
		Undetermined: []graph.Undetermined{
			{
				ID:        "weights:models/model.safetensors",
				Kind:      "weight",
				Reason:    "licence_unresolved",
				Detail:    "The weight file's licence could not be resolved.",
				ErrorCode: string(cerr.EScan010),
			},
		},
	})
}

func testIntent() *config.Intent {
	var in config.Intent
	in.SchemaVersion = 1
	in.Project.Name = "Acme Search"
	in.Use.Commercial = true
	in.Use.LicenceModel = "closed-source"
	in.Use.NetworkExposed = true
	in.Territories = []string{"EU", "US"}
	return &in
}

// stubTransport is the whole point of the Transport interface: a complete AI
// run with no socket, no key store and no clock.
type stubTransport struct {
	resp HTTPResponse
	err  error

	// responder, when set, answers the request it was given. It exists so that
	// a multi-job test can return a job-appropriate body, which is the only way
	// to tell "both jobs ran" from "one job ran twice".
	responder func(HTTPRequest) HTTPResponse

	got   []HTTPRequest
	calls int
}

func (s *stubTransport) Do(_ context.Context, req HTTPRequest) (HTTPResponse, error) {
	s.calls++
	s.got = append(s.got, req)
	if s.err != nil {
		return HTTPResponse{}, s.err
	}
	if s.responder != nil {
		return s.responder(req), nil
	}
	return s.resp, nil
}

// explainOrRemediate builds a minimal valid answer for a job.
func explainOrRemediate(j Job) string {
	switch j {
	case JobRemediate:
		return `{"schema_version":1,"job":"remediate","remediation":[` +
			`{"finding_id":"npm:leftpad@1.0.0#attribution","action":"keep the notice","effort":"low"}]}`
	case JobTriage:
		return `{"schema_version":1,"job":"triage","triage":[` +
			`{"id":"weights:models/model.safetensors","read_first":"MODEL_CARD.md","why":"it names the licence"}]}`
	}
	return `{"schema_version":1,"job":"explain","findings":[` +
		`{"id":"npm:leftpad@1.0.0#attribution","explanation":"Keep the notice."}]}`
}

// openAIBody wraps a model's JSON answer in an OpenAI-shaped envelope, with the
// usage numbers the caller wants to assert against.
func openAIBody(inner string) []byte { return openAIBodyTokens(inner, 120, 64) }

func openAIBodyTokens(inner string, in, out int) []byte {
	return []byte(`{"choices":[{"message":{"role":"assistant","content":` +
		jsonString(inner) + `},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":` + itoa(in) + `,"completion_tokens":` + itoa(out) + `}}`)
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// ─── the Secret type ─────────────────────────────────────────────────────────

// TestSecretRendering is AI-2: a Secret has no rendering that returns the raw
// value, for any verb.
//
// # EVERY VERB, NOT JUST %s
//
// %v and %s are the ones a developer writes on purpose. %q, %x and %#v are the
// ones that appear by accident — inside a struct printed during debugging, or in
// a formatted error that quotes an argument. A type that redacted only the first
// two would be safe against the mistake someone thought of and unsafe against
// the one they did not.
func TestSecretRendering(t *testing.T) {
	s := NewSecret(canary)
	if !s.Set() {
		t.Fatal("a Secret built from a non-empty string reports Set() == false")
	}

	verbs := []string{"%v", "%s", "%q", "%x", "%X", "%d", "%#v", "%+v", "%p", "%T"}
	for _, verb := range verbs {
		got := fmt.Sprintf(verb, s)
		if strings.Contains(got, canary) {
			t.Errorf("Sprintf(%q, secret) leaked the key: %s", verb, got)
		}
	}

	// The pointer, because that is what a struct field usually is.
	got := fmt.Sprintf("%v", &s)
	if strings.Contains(got, canary) {
		t.Errorf("Sprintf(\"%%v\", &secret) leaked the key: %s", got)
	}

	// JSON, because `--format json` and `--ai-output` both marshal structs.
	jb, err := json.Marshal(struct {
		Key Secret `json:"key"`
	}{s})
	if err != nil {
		t.Fatalf("marshalling a struct holding a Secret: %v", err)
	}
	if strings.Contains(string(jb), canary) {
		t.Errorf("json.Marshal leaked the key: %s", jb)
	}
	if !strings.Contains(string(jb), redacted) {
		t.Errorf("json.Marshal did not render the Secret as %s: %s", redacted, jb)
	}

	// Text, because YAML and every other text marshaller goes through it.
	tb, err := s.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if strings.Contains(string(tb), canary) {
		t.Errorf("MarshalText leaked the key: %s", tb)
	}
}

// TestSecretUseGivesTheRawValue is the control for the test above.
//
// Without it, a Secret whose Use never passed anything through would pass every
// assertion in TestSecretRendering while making the feature impossible. The
// type must be unusable for logging and fully usable for its one job.
func TestSecretUseGivesTheRawValue(t *testing.T) {
	s := NewSecret(" " + canary + "\n")
	var got string
	if err := s.Use(func(raw string) error { got = raw; return nil }); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if got != canary {
		t.Errorf("Use passed %q, want the trimmed key", got)
	}
	if s.Len() != len(canary) {
		t.Errorf("Len() = %d, want %d", s.Len(), len(canary))
	}
}

// TestEmptySecretIsAbsent asserts that "no key" and "an empty key" are the same
// state. A user who exports CLEARANCE_OPENAI_API_KEY="" has not supplied a key.
func TestEmptySecretIsAbsent(t *testing.T) {
	for _, raw := range []string{"", " ", "\t", "\n"} {
		if NewSecret(raw).Set() {
			t.Errorf("NewSecret(%q).Set() is true; whitespace is not a key", raw)
		}
	}
}

// TestRedactRemovesTheKey covers the one case the type cannot reach: a provider
// that echoes the key back inside an error message.
func TestRedactRemovesTheKey(t *testing.T) {
	s := NewSecret(canary)
	in := "upstream said: invalid api key " + canary + " (401)"
	out := Redact(in, s)
	if strings.Contains(out, canary) {
		t.Errorf("Redact left the key in place: %s", out)
	}
	if !strings.Contains(out, redacted) {
		t.Errorf("Redact did not mark the removal: %s", out)
	}
	// A missing key must not blank the message.
	if got := Redact("nothing to hide", NewSecret("")); got != "nothing to hide" {
		t.Errorf("Redact with an empty needle changed the text: %q", got)
	}
}

// ─── the provider table ──────────────────────────────────────────────────────

// TestProviderTableIsCoherent walks every row and asserts the invariants the
// rest of the package assumes.
//
// # WHY A TABLE NEEDS A TEST
//
// The table is data, and data is where a typo is invisible. A row with a
// BaseURL of "api.openai.com" (no scheme) would produce a request URL that
// http.Client rejects with a message about an unsupported protocol; a row with
// NeedsBaseURL and no guard would produce a request to the empty host. Neither
// is caught by the compiler, and both are caught here.
func TestProviderTableIsCoherent(t *testing.T) {
	if len(Providers()) < 20 {
		t.Errorf("the table holds %d providers; the spec names 20", len(Providers()))
	}

	seen := map[string]bool{}
	for _, p := range Providers() {
		if p.ID == "" {
			t.Error("a provider row has no id")
			continue
		}
		if seen[p.ID] {
			t.Errorf("provider id %q appears twice", p.ID)
		}
		seen[p.ID] = true

		switch p.Kind {
		case KindFirstParty, KindAggregator, KindCloudHosted, KindLocal, KindEscapeHatch:
		default:
			t.Errorf("%s has unknown kind %q", p.ID, p.Kind)
		}
		switch p.Wire {
		case WireOpenAI, WireAnthropic, WireGoogle:
		default:
			t.Errorf("%s has unknown wire shape %q", p.ID, p.Wire)
		}
		switch p.Auth {
		case AuthBearer, AuthXAPIKey, AuthGoogle, AuthAzureKey, AuthNone:
		default:
			t.Errorf("%s has unknown auth style %q", p.ID, p.Auth)
		}

		// A fixed endpoint must be a URL with a scheme, or the request URL is
		// malformed in a way that surfaces as a confusing transport error.
		if p.BaseURL != "" && !strings.Contains(p.BaseURL, "://") {
			t.Errorf("%s has BaseURL %q with no scheme", p.ID, p.BaseURL)
		}
		if p.BaseURL == "" && !p.NeedsBaseURL {
			t.Errorf("%s has no BaseURL and is not marked NeedsBaseURL, so "+
				"requests would go to the empty host", p.ID)
		}

		// Keyless and KeyEnv must agree. A keyless row that names an env var
		// would ask a user for a key they do not need; a non-keyless row with
		// no env var leaves them no way to supply one.
		if p.Keyless && p.KeyEnv != "" {
			t.Errorf("%s is keyless but names KeyEnv %q", p.ID, p.KeyEnv)
		}
		if !p.Keyless && p.Auth != AuthNone && p.KeyEnv == "" {
			t.Errorf("%s needs a key but names no KeyEnv, so the user cannot "+
				"be told which variable to set", p.ID)
		}

		// Every non-keyless provider must be resolvable to a host, because the
		// host is the egress allowlist. A provider whose host is empty would
		// allow a redirect to anywhere.
		if p.BaseURL != "" && p.Host("") == "" {
			t.Errorf("%s yields an empty host from %q", p.ID, p.BaseURL)
		}

		// A local runtime is loopback. This is the guarantee the tier exists to
		// make, and it is asserted rather than assumed.
		if p.Kind == KindLocal {
			host := p.Host("")
			if !strings.HasPrefix(host, "127.0.0.1:") && host != "localhost" {
				t.Errorf("%s is KindLocal but its host is %q; a local runtime "+
					"must be loopback, or the keyless tier is an egress", p.ID, host)
			}
		}
	}

	for _, want := range []string{
		"openai", "anthropic", "google", "mistral", "cohere", "deepseek", "xai",
		"perplexity", "groq", "together", "fireworks", "openrouter",
		"azure-openai", "aws-bedrock", "google-vertex",
		"ollama", "lmstudio", "llamacpp", "vllm", "openai-compatible",
	} {
		if !seen[want] {
			t.Errorf("the spec names provider %q and the table does not carry it", want)
		}
	}
}

// TestProviderHostAllowlistIsDerivedFromTheRow asserts the allowlist comes from
// the table and nowhere else, and that a trailing slash cannot smuggle in a
// different host.
func TestProviderHostAllowlistIsDerivedFromTheRow(t *testing.T) {
	p, ok := Lookup("openai")
	if !ok {
		t.Fatal("openai is not in the table")
	}
	if got := p.Host(""); got != "api.openai.com" {
		t.Errorf("Host() = %q, want api.openai.com", got)
	}
	// A path is not part of the host.
	p.BaseURL = "https://api.example.com/v1/extra"
	if got := p.Host(""); got != "api.example.com" {
		t.Errorf("Host() with a deep path = %q, want api.example.com", got)
	}
	// A port survives, because the local runtimes need it.
	p.BaseURL = "http://127.0.0.1:11434/v1"
	if got := p.Host(""); got != "127.0.0.1:11434" {
		t.Errorf("Host() with a port = %q, want 127.0.0.1:11434", got)
	}
	// A trailing slash on an override does not double up.
	esc, _ := Lookup("openai-compatible")
	if got := esc.Base("https://my.gateway.internal/v1/"); got != "https://my.gateway.internal/v1" {
		t.Errorf("Base() with a trailing slash = %q", got)
	}
}

// ─── resolution ──────────────────────────────────────────────────────────────

func TestResolveRejectsAnUnknownProvider(t *testing.T) {
	o := DefaultOptions()
	o.Provider = "openaii" // the typo the spec names
	_, _, err := Resolve(o)
	if err == nil {
		t.Fatal("Resolve accepted a provider id that is not in the table; " +
			"silently falling back to a default would send a key to a vendor " +
			"the user did not choose")
	}
	if got := cerr.CodeOf(err); got != cerr.EAi007 {
		t.Errorf("code = %s, want %s", got, cerr.EAi007)
	}
}

func TestResolveRefusesBaseURLForANamedProvider(t *testing.T) {
	o := DefaultOptions()
	o.Provider = "openai"
	o.BaseURL = "https://evil.example.com/v1"
	_, _, err := Resolve(o)
	if err == nil {
		t.Fatal("Resolve accepted a base_url for a named provider; that is a " +
			"redirect of a provider's traffic, which is what the host allowlist " +
			"exists to prevent")
	}
	if got := cerr.CodeOf(err); got != cerr.EAi009 {
		t.Errorf("code = %s, want %s", got, cerr.EAi009)
	}
}

func TestResolveRequiresBaseURLWhereTheEndpointIsUsersOwn(t *testing.T) {
	for _, id := range []string{"azure-openai", "openai-compatible", "google-vertex"} {
		o := DefaultOptions()
		o.Provider = id
		if _, _, err := Resolve(o); err == nil {
			t.Errorf("%s resolved with no base_url, so requests would go to the "+
				"empty host", id)
		}
	}
}

func TestResolveAppliesTheDefaultModel(t *testing.T) {
	o := DefaultOptions()
	o.Provider = "anthropic"
	p, model, err := Resolve(o)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if model != p.DefaultModel {
		t.Errorf("model = %q, want the row's default %q", model, p.DefaultModel)
	}
	o.Model = "claude-3-opus-latest"
	if _, model, _ := Resolve(o); model != "claude-3-opus-latest" {
		t.Errorf("an explicit model was overridden by the default: %q", model)
	}
}

func TestResolveRefusesAnUnknownJob(t *testing.T) {
	o := DefaultOptions()
	o.Jobs = []Job{"summarise"}
	if _, _, err := Resolve(o); err == nil {
		t.Fatal("Resolve accepted a job that is not one of the three permitted ones")
	}
	o.Jobs = nil
	if _, _, err := Resolve(o); err == nil {
		t.Fatal("Resolve accepted an empty job list; a run that asks for nothing " +
			"would spend a network call and return nothing")
	}
}

// ─── the request ─────────────────────────────────────────────────────────────

// TestBuildRequestPerWire asserts each wire shape's URL, path and auth header.
//
// # THE THREE MISTAKES THIS CATCHES
//
//  1. Sending a bearer token to Anthropic, which wants x-api-key and rejects a
//     bearer with a 401 that reads like a bad key.
//  2. Forgetting anthropic-version, which produces a 400 that reads like a bad
//     model name.
//  3. Putting Google's key in a query string, where it lands in every access log
//     between here and Mountain View.
func TestBuildRequestPerWire(t *testing.T) {
	pl := Payload{SchemaVersion: 1, Job: JobExplain, Verdict: "DO_NOT_SHIP"}
	key := NewSecret(canary)

	cases := []struct {
		provider   string
		baseURL    string
		model      string
		wantURL    string
		wantHeader string
		wantValue  string
	}{
		{provider: "openai", wantURL: "https://api.openai.com/v1/chat/completions", wantHeader: "authorization", wantValue: "Bearer " + canary},
		{provider: "anthropic", wantURL: "https://api.anthropic.com/v1/messages", wantHeader: "x-api-key", wantValue: canary},
		{provider: "google", wantURL: "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent", wantHeader: "x-goog-api-key", wantValue: canary},
		{provider: "groq", wantURL: "https://api.groq.com/openai/v1/chat/completions", wantHeader: "authorization", wantValue: "Bearer " + canary},
		// Azure's model is the deployment name and the escape hatch's is whatever
		// the vendor calls it; neither can be defaulted, so the test supplies one
		// exactly as a user would.
		{
			provider: "azure-openai", baseURL: "https://acme.openai.azure.com", model: "acme-gpt",
			wantURL:    "https://acme.openai.azure.com/openai/deployments/acme-gpt/chat/completions?api-version=2024-10-21",
			wantHeader: "api-key", wantValue: canary,
		},
		{
			provider: "openai-compatible", baseURL: "https://gateway.internal/v1", model: "acme-model",
			wantURL:    "https://gateway.internal/v1/chat/completions",
			wantHeader: "authorization", wantValue: "Bearer " + canary,
		},
	}

	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			o := DefaultOptions()
			o.Provider = tc.provider
			o.BaseURL = tc.baseURL
			o.Model = tc.model
			p, model, err := Resolve(o)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			req, err := BuildRequest(p, model, key, o, pl)
			if err != nil {
				t.Fatalf("BuildRequest: %v", err)
			}
			if req.URL != tc.wantURL {
				t.Errorf("URL = %q\nwant    %q", req.URL, tc.wantURL)
			}
			if !hasHeader(req, tc.wantHeader, tc.wantValue) {
				t.Errorf("missing header %s: %s\nheaders: %v",
					tc.wantHeader, tc.wantValue, req.Headers)
			}
			if req.Method != "POST" {
				t.Errorf("method = %q, want POST", req.Method)
			}
			if len(req.Body) == 0 {
				t.Error("the request body is empty")
			}
			// The key must never be in the URL. A key in a query string lands
			// in every proxy log on the path.
			if strings.Contains(req.URL, canary) {
				t.Errorf("the URL carries the key: %s", req.URL)
			}
			// Anthropic needs its version header, and its absence is a 400 that
			// reads like a bad model name.
			if tc.provider == "anthropic" && !hasHeader(req, "anthropic-version", "2023-06-01") {
				t.Error("the Anthropic request has no anthropic-version header")
			}
		})
	}
}

func hasHeader(req HTTPRequest, name, value string) bool {
	for _, h := range req.Headers {
		if strings.EqualFold(h[0], name) && h[1] == value {
			return true
		}
	}
	return false
}

func TestBuildRequestRefusesAMissingKey(t *testing.T) {
	o := DefaultOptions()
	o.Provider = "openai"
	p, model, _ := Resolve(o)
	_, err := BuildRequest(p, model, NewSecret(""), o, Payload{Job: JobExplain})
	if err == nil {
		t.Fatal("BuildRequest built a request with no key; the provider would " +
			"return a 401 and the user would be told their key was wrong when " +
			"they never supplied one")
	}
	if got := cerr.CodeOf(err); got != cerr.EAi001 {
		t.Errorf("code = %s, want %s", got, cerr.EAi001)
	}
}

func TestBuildRequestNeedsNoKeyForALocalRuntime(t *testing.T) {
	o := DefaultOptions()
	o.Provider = "ollama"
	p, model, err := Resolve(o)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	req, err := BuildRequest(p, model, NewSecret(""), o, Payload{Job: JobExplain})
	if err != nil {
		t.Fatalf("a keyless local runtime refused a request with no key: %v", err)
	}
	for _, h := range req.Headers {
		if strings.EqualFold(h[0], "authorization") {
			t.Error("a keyless provider sent an authorization header")
		}
	}
}

// ─── extraction ──────────────────────────────────────────────────────────────

func TestExtractHandlesAllThreeEnvelopes(t *testing.T) {
	inner := `{"schema_version":1,"job":"explain","findings":[{"id":"a","explanation":"b"}]}`

	cases := []struct {
		name     string
		provider string
		body     string
		want     string
	}{
		{
			name:     "openai",
			provider: "openai",
			body:     string(openAIBodyTokens(inner, 10, 5)),
			want:     inner,
		},
		{
			name:     "anthropic",
			provider: "anthropic",
			body: `{"content":[{"type":"text","text":` + jsonString(inner) + `}],` +
				`"usage":{"input_tokens":10,"output_tokens":5}}`,
			want: inner,
		},
		{
			name:     "google",
			provider: "google",
			body: `{"candidates":[{"content":{"parts":[{"text":` + jsonString(inner) +
				`}]}}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5}}`,
			want: inner,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := Lookup(tc.provider)
			got, usage, err := Extract(p, []byte(tc.body), NewSecret(canary))
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if got != tc.want {
				t.Errorf("text = %q\nwant     %q", got, tc.want)
			}
			if usage.TokensIn != 10 || usage.TokensOut != 5 {
				t.Errorf("usage = %+v, want 10 in / 5 out", usage)
			}
		})
	}
}

// TestExtractFindsAnErrorInsideA200 is the case that bites in production: a
// provider that returns HTTP 200 with an error object.
func TestExtractFindsAnErrorInsideA200(t *testing.T) {
	p, _ := Lookup("anthropic")
	body := `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key ` + canary + `"}}`
	_, _, err := Extract(p, []byte(body), NewSecret(canary))
	if err == nil {
		t.Fatal("a 200 carrying an error object was treated as a success")
	}
	// The provider's own words are surfaced, because they are the diagnosis.
	if !strings.Contains(err.Error(), "invalid x-api-key") {
		t.Errorf("the provider's message was not surfaced: %v", err)
	}
	// And the key inside them is scrubbed. Both halves matter: a message with
	// no detail is useless, and a message with the key in it is a leak.
	if strings.Contains(err.Error(), canary) {
		t.Errorf("Extract leaked the key in an error: %v", err)
	}
}

func TestExtractRefusesANonJSONBody(t *testing.T) {
	p, _ := Lookup("openai")
	if _, _, err := Extract(p, []byte("<html>502 Bad Gateway</html>"), NewSecret(canary)); err == nil {
		t.Fatal("an HTML error page parsed as a model response")
	}
}

// ─── parsing ─────────────────────────────────────────────────────────────────

func TestParseSuggestionStripsAFence(t *testing.T) {
	fenced := "```json\n{\"schema_version\":1,\"job\":\"explain\",\"findings\":[{\"id\":\"a\",\"explanation\":\"b\"}]}\n```"
	s, err := ParseSuggestion(JobExplain, fenced)
	if err != nil {
		t.Fatalf("a fenced response was refused: %v", err)
	}
	if len(s.Findings) != 1 || s.Findings[0].ID != "a" {
		t.Errorf("findings = %+v, want one entry with id \"a\"", s.Findings)
	}
}

func TestParseSuggestionRefusesTheWrongJob(t *testing.T) {
	// A response that answers a different question than the one asked.
	body := `{"schema_version":1,"job":"remediate","remediation":[{"finding_id":"a","action":"b"}]}`
	if _, err := ParseSuggestion(JobExplain, body); err == nil {
		t.Fatal("a response naming job 'remediate' was accepted for a request " +
			"that asked for 'explain'")
	}
}

func TestParseSuggestionDropsEmptyEntries(t *testing.T) {
	body := `{"schema_version":1,"job":"explain","findings":[
		{"id":"","explanation":"no id"},
		{"id":"a","explanation":""},
		{"id":"b","explanation":"a real explanation"}
	]}`
	s, err := ParseSuggestion(JobExplain, body)
	if err != nil {
		t.Fatalf("ParseSuggestion: %v", err)
	}
	if len(s.Findings) != 1 || s.Findings[0].ID != "b" {
		t.Errorf("findings = %+v, want only the one with both an id and a body", s.Findings)
	}
}

func TestParseSuggestionStripsControlCharacters(t *testing.T) {
	// An ANSI erase-screen sequence. A model that emitted one would clear the
	// user's terminal in the middle of their verdict.
	body := `{"schema_version":1,"job":"explain","findings":[{"id":"a","explanation":"safe\u001b[2Jtext"}]}`
	s, err := ParseSuggestion(JobExplain, body)
	if err != nil {
		t.Fatalf("ParseSuggestion: %v", err)
	}
	if len(s.Findings) != 1 {
		t.Fatalf("findings = %+v", s.Findings)
	}
	if strings.ContainsRune(s.Findings[0].Explanation, 0x1b) {
		t.Errorf("an escape character survived parsing: %q", s.Findings[0].Explanation)
	}
}

func TestParseSuggestionBoundsLongFields(t *testing.T) {
	long := strings.Repeat("x", maxFieldLen*2)
	body := `{"schema_version":1,"job":"explain","findings":[{"id":"a","explanation":` +
		jsonString(long) + `}]}`
	s, err := ParseSuggestion(JobExplain, body)
	if err != nil {
		t.Fatalf("ParseSuggestion: %v", err)
	}
	if len(s.Findings) != 1 {
		t.Fatalf("findings = %+v", s.Findings)
	}
	if n := len(s.Findings[0].Explanation); n > maxFieldLen+8 {
		t.Errorf("a %d-character field was not bounded (limit %d)", n, maxFieldLen)
	}
}

// ─── Attach, the guard ───────────────────────────────────────────────────────

// TestAttachRefusesEveryOverride is the package-level half of
// TestAICannotAlterAVerdict. It feeds Attach one override of each kind and
// asserts every one is refused with E-AI-006 and counted.
func TestAttachRefusesEveryOverride(t *testing.T) {
	v := testVerdict()
	o := DefaultOptions()
	o.Jobs = []Job{JobExplain, JobRemediate, JobTriage}

	s := Suggestion{
		SchemaVersion: 1,
		Job:           JobExplain,
		Findings: []Explanation{
			{ID: "npm:leftpad@1.0.0#attribution", Explanation: "fine"},
		},
		Overrides: []Override{
			{FindingID: "npm:leftpad@1.0.0#attribution", Op: "remove"},
			{FindingID: "npm:invented@9.9.9#x", Op: "add"},
			{FindingID: "npm:leftpad@1.0.0#attribution", Op: "severity", Severity: "NOTE"},
			{FindingID: "npm:leftpad@1.0.0#attribution", Op: "confidence", Confidence: "LOW"},
		},
	}

	got, notices := Attach(v, s, o, nil)

	if len(got.Overrides) != 0 {
		t.Errorf("Attach left %d override(s) in place; every one must be refused",
			len(got.Overrides))
	}
	var refusals int
	for _, n := range notices {
		if n.Code == cerr.EAi006 {
			refusals++
		}
	}
	if refusals != 4 {
		t.Errorf("E-AI-006 fired %d times, want 4 (one per override).\n"+
			"notices: %+v", refusals, notices)
	}
	// The legitimate explanation survives. A guard that dropped everything
	// would pass the assertion above and break the feature.
	if len(got.Findings) != 1 {
		t.Errorf("the legitimate explanation was dropped: %+v", got.Findings)
	}
}

func TestAttachDropsIdsThatAreNotInTheVerdict(t *testing.T) {
	v := testVerdict()
	o := DefaultOptions()
	o.Jobs = []Job{JobExplain, JobRemediate, JobTriage}

	s := Suggestion{
		SchemaVersion: 1,
		Job:           JobExplain,
		Findings: []Explanation{
			{ID: "npm:leftpad@1.0.0#attribution", Explanation: "real"},
			{ID: "npm:invented@9.9.9#hallucinated", Explanation: "invented"},
		},
		Remediation: []Remediation{
			{FindingID: "npm:leftpad@1.0.0#attribution", Action: "real"},
			{FindingID: "npm:also-invented@1.0.0", Action: "invented"},
		},
		Triage: []Triage{
			{ID: "weights:models/model.safetensors", ReadFirst: "MODEL_CARD.md"},
			{ID: "weights:nowhere", ReadFirst: "nothing"},
		},
	}

	got, notices := Attach(v, s, o, nil)

	if len(got.Findings) != 1 || got.Findings[0].ID != "npm:leftpad@1.0.0#attribution" {
		t.Errorf("findings = %+v, want only the real one", got.Findings)
	}
	if len(got.Remediation) != 1 {
		t.Errorf("remediation = %+v, want only the real one", got.Remediation)
	}
	if len(got.Triage) != 1 || got.Triage[0].ID != "weights:models/model.safetensors" {
		t.Errorf("triage = %+v, want only the real one", got.Triage)
	}

	var dropped int
	for _, n := range notices {
		if n.Code == cerr.EAi005 {
			dropped++
		}
	}
	if dropped != 3 {
		t.Errorf("E-AI-005 fired %d times, want 3 (one per invented id)", dropped)
	}
}

func TestAttachRefusesAJobThatWasNotRequested(t *testing.T) {
	v := testVerdict()
	o := DefaultOptions()
	o.Jobs = []Job{JobExplain}

	s := Suggestion{
		SchemaVersion: 1,
		Job:           JobRemediate,
		Remediation:   []Remediation{{FindingID: "npm:leftpad@1.0.0#attribution", Action: "x"}},
	}
	got, notices := Attach(v, s, o, nil)
	if !got.Empty() {
		t.Errorf("a response for an unrequested job was partly kept: %+v", got)
	}
	if len(notices) != 1 || notices[0].Code != cerr.EAi005 {
		t.Errorf("notices = %+v, want one E-AI-005", notices)
	}
}

// TestAttachMarksUnverifiedAlternatives asserts the corpus oracle is consulted
// and that a nil oracle is "unverified", never "verified".
//
// The direction matters: an oracle that cannot answer must not render as a pass,
// because "we could not check" and "we checked and it is fine" are different
// statements and only one of them is true.
func TestAttachMarksUnverifiedAlternatives(t *testing.T) {
	v := testVerdict()
	o := DefaultOptions()
	o.Jobs = []Job{JobRemediate}

	oracle := fakeOracle{"Apache-2.0": true}

	s := Suggestion{
		SchemaVersion: 1,
		Job:           JobRemediate,
		Remediation: []Remediation{
			{FindingID: "npm:leftpad@1.0.0#attribution", Action: "swap", Alternative: "crawl4ai (Apache-2.0)"},
			{FindingID: "npm:leftpad@1.0.0#attribution", Action: "swap", Alternative: "mystery-lib (Made-Up-9.9)"},
			{FindingID: "npm:leftpad@1.0.0#attribution", Action: "remove the dependency"},
		},
	}

	got, _ := Attach(v, s, o, oracle)
	if len(got.Remediation) != 3 {
		t.Fatalf("remediation = %+v, want all three kept", got.Remediation)
	}
	if !got.Remediation[0].Verified {
		t.Error("a corpus-known alternative was marked unverified")
	}
	if got.Remediation[1].Verified {
		t.Error("an unknown alternative was marked verified")
	}
	if !got.Remediation[2].Verified {
		t.Error("an empty alternative was marked unverified; there is nothing " +
			"to verify, and marking it puts a warning next to a blank field")
	}

	// With no oracle, nothing can be confirmed.
	got, _ = Attach(v, s, o, nil)
	if got.Remediation[0].Verified {
		t.Error("with no oracle, an alternative was reported as verified")
	}
}

type fakeOracle map[string]bool

func (f fakeOracle) KnowsLicence(id string) bool { return f[id] }

func TestAlternativeSPDX(t *testing.T) {
	cases := map[string]string{
		"crawl4ai (Apache-2.0)": "Apache-2.0",
		"crawl4ai":              "crawl4ai",
		"x (MIT) (Apache-2.0)":  "Apache-2.0",
		"  (ISC)  ":             "ISC",
		"no parens at all":      "no parens at all",
		"unclosed (Apache-2.0":  "unclosed (Apache-2.0",
	}
	for in, want := range cases {
		if got := alternativeSPDX(in); got != want {
			t.Errorf("alternativeSPDX(%q) = %q, want %q", in, got, want)
		}
	}
}

// ─── the payload ─────────────────────────────────────────────────────────────

// TestPayloadCarriesNoFileContents is AI-8 at the package level.
//
// The assertion is made against the *serialised* payload rather than against the
// struct, because the struct is not what leaves the machine. A field added to
// payloadFinding in future would be caught here even if nobody thought to add it
// to this test's expectations.
func TestPayloadCarriesNoFileContents(t *testing.T) {
	v := testVerdict()
	o := DefaultOptions()

	pl, err := BuildPayload(JobExplain, v, testIntent(), o)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	raw, err := json.Marshal(pl)
	if err != nil {
		t.Fatalf("marshalling the payload: %v", err)
	}

	// The excerpt is the quoted clause and it is deliberately NOT in the
	// payload: the URL and the section identify the clause, and the clause text
	// is a document Clearance is not licensed to redistribute.
	if strings.Contains(string(raw), "Corresponding Source") {
		t.Error("the payload carries a clause excerpt; the citation's URL and " +
			"section identify the clause, and the text itself is not ours to send")
	}
	// The evidence path is sent, project-relative — but never an absolute one.
	if strings.Contains(string(raw), "C:\\") || strings.Contains(string(raw), "/home/") {
		t.Errorf("the payload carries an absolute path: %s", raw)
	}
	// The intent is the declaration, not the project.
	if !strings.Contains(string(raw), `"licence_model":"closed-source"`) {
		t.Errorf("the payload is missing the declared intent: %s", raw)
	}
}

func TestPayloadRedactsTheProjectName(t *testing.T) {
	v := testVerdict()
	v.Project = "Acme Secret Codename"

	o := DefaultOptions()
	o.RedactProjectName = true
	pl, _ := BuildPayload(JobExplain, v, testIntent(), o)
	if pl.Project != "the project" {
		t.Errorf("with redaction on, the project name is %q", pl.Project)
	}
	raw, _ := json.Marshal(pl)
	if strings.Contains(string(raw), "Codename") {
		t.Errorf("the project name leaked despite redaction: %s", raw)
	}

	o.RedactProjectName = false
	pl, _ = BuildPayload(JobExplain, v, testIntent(), o)
	if pl.Project != "Acme Secret Codename" {
		t.Errorf("with redaction off, the project name is %q", pl.Project)
	}
}

// TestPayloadOmitsWhatTheJobDoesNotNeed asserts a triage request carries no
// findings.
//
// It is a privacy property as much as a design one: a model asked to triage a
// gap has no business being handed a blocker, and the cheapest way to guarantee
// that is for the blocker never to be in the request.
func TestPayloadOmitsWhatTheJobDoesNotNeed(t *testing.T) {
	v := testVerdict()
	o := DefaultOptions()

	pl, _ := BuildPayload(JobTriage, v, testIntent(), o)
	if len(pl.Findings) != 0 {
		t.Errorf("a triage payload carried %d finding(s)", len(pl.Findings))
	}
	if len(pl.Undetermined) != 1 {
		t.Errorf("a triage payload carried %d undetermined record(s), want 1",
			len(pl.Undetermined))
	}

	pl, _ = BuildPayload(JobExplain, v, testIntent(), o)
	if len(pl.Undetermined) != 0 {
		t.Errorf("an explain payload carried %d undetermined record(s)",
			len(pl.Undetermined))
	}
	if len(pl.Findings) != 2 {
		t.Errorf("an explain payload carried %d finding(s), want 2", len(pl.Findings))
	}
	// Blocker first: the order of importance is the order a model reads in.
	if pl.Findings[0].Severity != string(policy.SeverityBlock) {
		t.Errorf("the first finding has severity %q, want BLOCK first",
			pl.Findings[0].Severity)
	}
}

func TestSafePathsDropsAnythingNotRelative(t *testing.T) {
	in := []string{
		"package-lock.json",
		"models/config.json",
		"../secrets.env",
		"/etc/passwd",
		`C:\Users\kate\.ssh\id_rsa`,
		"",
		"  ",
	}
	got := safePaths(in)
	for _, p := range got {
		if strings.Contains(p, "..") || strings.HasPrefix(p, "/") ||
			strings.HasPrefix(p, "\\") || strings.Contains(p, ":") {
			t.Errorf("safePaths kept %q", p)
		}
	}
	if len(got) != 2 {
		t.Errorf("safePaths kept %d path(s) (%v), want the 2 relative ones", len(got), got)
	}
}

// ─── the status mapping ──────────────────────────────────────────────────────

func TestStatusErrorMapping(t *testing.T) {
	p, _ := Lookup("openai")
	cases := []struct {
		status int
		want   cerr.Code
		fatal  bool
	}{
		{200, "", false},
		{401, cerr.EAi002, true},
		{403, cerr.EAi002, true},
		{400, cerr.EAi002, true},
		{404, cerr.EAi002, true},
		{422, cerr.EAi002, true},
		{429, cerr.EAi003, false},
		{500, cerr.EAi004, false},
		{503, cerr.EAi004, false},
		{418, cerr.EAi005, false},
	}
	for _, tc := range cases {
		err := statusError(p, tc.status, NewSecret(canary))
		if tc.want == "" {
			if err != nil {
				t.Errorf("HTTP %d produced %v, want no error", tc.status, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("HTTP %d produced no error, want %s", tc.status, tc.want)
			continue
		}
		if got := cerr.CodeOf(err); got != tc.want {
			t.Errorf("HTTP %d → %s, want %s", tc.status, got, tc.want)
		}
		if cerr.IsFatal(err) != tc.fatal {
			t.Errorf("HTTP %d fatal = %v, want %v (%s is %s)",
				tc.status, cerr.IsFatal(err), tc.fatal, tc.want, cerr.ClassOf(err))
		}
	}
}

// ─── Run, end to end with a stub ─────────────────────────────────────────────

func TestRunProducesASuggestionWithAStubTransport(t *testing.T) {
	inner := `{"schema_version":1,"job":"explain","findings":[` +
		`{"id":"npm:leftpad@1.0.0#attribution","explanation":"Keep the notice."}]}`
	st := &stubTransport{resp: HTTPResponse{Status: 200, Body: openAIBody(inner)}}

	o := DefaultOptions()
	o.Enabled = true
	o.Provider = "openai"

	res, err := Run(context.Background(), st, o, testVerdict(), testIntent(),
		NewSecret(canary), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if st.calls != 1 {
		t.Errorf("the transport was called %d times, want 1", st.calls)
	}
	if len(res.Suggestion.Findings) != 1 {
		t.Fatalf("suggestion = %+v, want one explanation", res.Suggestion)
	}
	if res.Suggestion.Provider != "openai" {
		t.Errorf("provider = %q", res.Suggestion.Provider)
	}
	if res.Usage.TokensIn != 120 || res.Usage.TokensOut != 64 {
		t.Errorf("usage = %+v, want 120/64 from the envelope", res.Usage)
	}
	// The key must be in the request header and nowhere in the request URL.
	if !hasHeader(st.got[0], "authorization", "Bearer "+canary) {
		t.Error("the request carried no authorization header")
	}
	if strings.Contains(st.got[0].URL, canary) {
		t.Error("the key is in the request URL")
	}
}

// TestRunDegradesRatherThanFails is the property that makes the whole feature
// safe to enable: a network failure costs an explanation and nothing else.
func TestRunDegradesRatherThanFails(t *testing.T) {
	st := &stubTransport{err: fmt.Errorf("dial tcp: connection refused")}

	o := DefaultOptions()
	o.Enabled = true
	o.Provider = "groq"

	res, err := Run(context.Background(), st, o, testVerdict(), testIntent(),
		NewSecret(canary), nil)
	if err == nil {
		t.Fatal("a network failure produced no error at all")
	}
	if !Degraded(err) {
		t.Errorf("a network failure was classified %s, want a degrade class",
			cerr.ClassOf(err))
	}
	if cerr.IsFatal(err) {
		t.Error("a network failure is FATAL; a user whose Wi-Fi dropped would " +
			"lose their verdict, and the exit code would depend on a third " +
			"party's availability (ADR-008)")
	}
	// The result is still usable: the caller has a provider, a model and an
	// empty suggestion, which is exactly the shape the renderer expects.
	if res.Provider != "groq" {
		t.Errorf("provider = %q, want groq", res.Provider)
	}
	if !res.Suggestion.Empty() {
		t.Errorf("a failed run produced a non-empty suggestion: %+v", res.Suggestion)
	}
	// The key must not appear in the error text.
	if strings.Contains(err.Error(), canary) {
		t.Errorf("the error leaked the key: %v", err)
	}
}

func TestRunKeepsAFatalProviderErrorFatal(t *testing.T) {
	st := &stubTransport{resp: HTTPResponse{Status: 401, Body: []byte(`{}`)}}
	o := DefaultOptions()
	o.Enabled = true
	o.Provider = "openai"

	_, err := Run(context.Background(), st, o, testVerdict(), testIntent(),
		NewSecret("wrong-key-000000000000"), nil)
	if err == nil {
		t.Fatal("a 401 produced no error")
	}
	if !cerr.IsFatal(err) {
		t.Errorf("a 401 was classified %s; a bad key is a configuration error, "+
			"not a degraded run", cerr.ClassOf(err))
	}
	if got := cerr.CodeOf(err); got != cerr.EAi002 {
		t.Errorf("code = %s, want %s", got, cerr.EAi002)
	}
}

// TestRunRunsEveryRequestedJob asserts the multi-job path, because a `for` loop
// that ran only its first iteration would pass every single-job test above.
func TestRunRunsEveryRequestedJob(t *testing.T) {
	// The responder answers whichever job was asked for, so a run that fired
	// the same request twice would produce a validation failure and be caught.
	st := &stubTransport{responder: func(req HTTPRequest) HTTPResponse {
		job := JobExplain
		// The payload is embedded as an escaped JSON string inside the envelope,
		// so the quotes arrive as \" and the search is for the bare word.
		if strings.Contains(string(req.Body), "remediate") {
			job = JobRemediate
		}
		return HTTPResponse{Status: 200, Body: openAIBody(explainOrRemediate(job))}
	}}

	o := DefaultOptions()
	o.Enabled = true
	o.Jobs = []Job{JobExplain, JobRemediate}

	res, err := Run(context.Background(), st, o, testVerdict(), testIntent(),
		NewSecret(canary), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if st.calls != 2 {
		t.Errorf("the transport was called %d times for 2 jobs, want 2", st.calls)
	}
	// Two calls means two usage records.
	if res.Usage.TokensIn != 240 {
		t.Errorf("usage = %+v, want the two calls summed (240 in)", res.Usage)
	}
}

// TestMergeDeduplicatesById keeps a two-job run from explaining one finding
// twice.
func TestMergeDeduplicatesById(t *testing.T) {
	var dst Suggestion
	merge(&dst, Suggestion{Findings: []Explanation{{ID: "a", Explanation: "first"}}})
	merge(&dst, Suggestion{Findings: []Explanation{
		{ID: "a", Explanation: "second"},
		{ID: "b", Explanation: "third"},
	}})
	if len(dst.Findings) != 2 {
		t.Fatalf("findings = %+v, want 2", dst.Findings)
	}
	if dst.Findings[0].Explanation != "first" {
		t.Errorf("the first explanation was overwritten: %+v", dst.Findings[0])
	}
}
