package ai

import (
	"sort"
	"strings"
)

// Kind classifies how a provider is reached. It exists because the four kinds
// have genuinely different trust postures, and a user deciding whether to
// enable AI needs to see which one they have selected.
type Kind string

const (
	// KindFirstParty is a vendor's own API. The endpoint is fixed, the auth is
	// a key, and the key is the vendor's.
	KindFirstParty Kind = "first-party"

	// KindAggregator fronts many models behind one OpenAI-shaped API. Useful
	// because one key reaches many models; notable because the prompt reaches
	// a third party that is not the model's author.
	KindAggregator Kind = "aggregator"

	// KindCloudHosted is a model served by a cloud, where the endpoint and the
	// credential both come from the user's cloud account.
	KindCloudHosted Kind = "cloud-hosted"

	// KindLocal is a runtime on the user's own machine. Keyless, and the only
	// tier that gives an air-gapped user AI help with no vendor in the loop.
	KindLocal Kind = "local"

	// KindEscapeHatch is `openai-compatible`: any endpoint that speaks the
	// OpenAI chat-completions shape, which is now the de-facto wire standard.
	KindEscapeHatch Kind = "escape-hatch"
)

// AuthStyle is how a key is presented. It is the difference between providers
// that a naive implementation gets wrong: Anthropic uses `x-api-key` and a
// version header rather than a bearer token, Google uses `x-goog-api-key`, and
// Azure uses `api-key`.
type AuthStyle string

const (
	AuthBearer   AuthStyle = "bearer"    // Authorization: Bearer <key>
	AuthXAPIKey  AuthStyle = "x-api-key" // Anthropic
	AuthGoogle   AuthStyle = "x-goog-api-key"
	AuthAzureKey AuthStyle = "api-key"
	AuthNone     AuthStyle = "none" // the keyless local runtimes
)

// Wire is the request/response shape a provider speaks. Three shapes cover all
// twenty rows: the OpenAI chat-completions shape (which every aggregator and
// every local runtime also speaks), Anthropic's Messages API, and Google's
// generateContent.
type Wire string

const (
	WireOpenAI    Wire = "openai"    // POST {base}/chat/completions
	WireAnthropic Wire = "anthropic" // POST {base}/messages
	WireGoogle    Wire = "google"    // POST {base}/models/{model}:generateContent
)

// Provider is one row of the table.
//
// # A PROVIDER IS DATA, NOT CODE
//
// This is ADR-003's principle — all judgement lives in data — applied to
// transport. Adding a provider is a table edit and a test case, never a new
// code path, because a new code path is a new place for the host allowlist, the
// redaction or the key resolution to be forgotten.
type Provider struct {
	// ID is the value of `ai.provider`.
	ID string

	Kind Kind

	// BaseURL is the fixed endpoint prefix. Empty means the user must supply
	// one (see NeedsBaseURL).
	BaseURL string

	// NeedsBaseURL marks a provider whose endpoint is user-specific: Azure
	// per-deployment, and the escape hatch per-vendor.
	NeedsBaseURL bool

	Wire Wire
	Auth AuthStyle

	// KeyEnv is the environment variable consulted for the key. Empty means
	// keyless (the local runtimes), which is a first-class state and not an
	// error.
	KeyEnv string

	// Keyless is true for the local runtimes. It is separate from KeyEnv == ""
	// so that a future provider with a key read from somewhere unusual cannot
	// accidentally be treated as needing none.
	Keyless bool

	// DefaultModel is used when `ai.model` is empty.
	DefaultModel string

	// VersionHeader is sent with AuthXAPIKey. Anthropic rejects a request
	// without it, and the failure is a 400 that reads like a bad model name.
	VersionHeader string

	// APIVersion is appended as a query parameter (Azure).
	APIVersion string

	// Docs is the page a user should read to obtain a key. It is printed by
	// `clearance doctor`, because "set CLEARANCE_OPENAI_API_KEY" is not
	// actionable to someone who does not yet have a key.
	Docs string
}

// Base returns the endpoint prefix, preferring the user's override where the
// provider permits one.
func (p Provider) Base(override string) string {
	if p.NeedsBaseURL && strings.TrimSpace(override) != "" {
		return strings.TrimRight(strings.TrimSpace(override), "/")
	}
	return p.BaseURL
}

// Host returns the hostname requests will be sent to, or "" when it cannot be
// known without the user's override (in which case the override's host is the
// allowlist).
//
// It is the single source of the egress allowlist: the redirect policy in the
// CLI is derived from this, so a provider row that gained a second host would
// gain it here and nowhere else.
func (p Provider) Host(override string) string {
	base := p.Base(override)
	if base == "" {
		return ""
	}
	// The host is everything between the scheme and the first path separator.
	s := base
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// Strip a port, because http.Client matches on Host (which includes the
	// port) but a redirect is compared on hostname in practice. Keeping the
	// host without the port would break the local runtimes, so the port is
	// preserved — see hostsMatch in the CLI.
	return s
}

// providers is the table. Its order is canonical: it is the order
// `clearance doctor` prints and the order a documentation test walks, so it is
// grouped by kind rather than alphabetised — a user scanning it is looking for
// "which of these do I already have?".
//
// # THE TWENTY ROWS, AND WHY EACH IS HERE
//
// The four local runtimes matter more than they look. They are the only tier
// that gives an air-gapped or security-conscious user AI help with no key, no
// vendor and no egress, which is exactly the user most likely to be auditing a
// licence in the first place. They are keyless, and they are loopback-only.
//
// `openai-compatible` is the honest answer to "support all AI providers". A
// table cannot enumerate every vendor, and a new one ships every month. This row
// accepts any endpoint speaking the OpenAI shape, so a provider that did not
// exist when this binary was compiled works on day one, with no release. The
// other nineteen rows exist because they have a *different wire shape*
// (Anthropic, Google) or a *different discovery story* (the local runtimes).
//
// # WHAT IS DELIBERATELY ABSENT
//
// A plugin system for providers. ADR-006 forbids plugins, and the reason
// applies twice over here: a tool that audits third-party code must not load
// third-party code to do it. A data table plus one generic adapter is the whole
// feature.
var providers = []Provider{
	// ── first-party ─────────────────────────────────────────────────────────
	{
		ID: "openai", Kind: KindFirstParty,
		BaseURL: "https://api.openai.com/v1", Wire: WireOpenAI, Auth: AuthBearer,
		KeyEnv: "CLEARANCE_OPENAI_API_KEY", DefaultModel: "gpt-4o-mini",
		Docs: "https://platform.openai.com/api-keys",
	},
	{
		ID: "anthropic", Kind: KindFirstParty,
		BaseURL: "https://api.anthropic.com/v1", Wire: WireAnthropic, Auth: AuthXAPIKey,
		KeyEnv: "CLEARANCE_ANTHROPIC_API_KEY", DefaultModel: "claude-3-5-haiku-latest",
		VersionHeader: "2023-06-01",
		Docs:          "https://console.anthropic.com/settings/keys",
	},
	{
		ID: "google", Kind: KindFirstParty,
		BaseURL: "https://generativelanguage.googleapis.com/v1beta", Wire: WireGoogle, Auth: AuthGoogle,
		KeyEnv: "CLEARANCE_GOOGLE_API_KEY", DefaultModel: "gemini-2.0-flash",
		Docs: "https://aistudio.google.com/apikey",
	},
	{
		ID: "mistral", Kind: KindFirstParty,
		BaseURL: "https://api.mistral.ai/v1", Wire: WireOpenAI, Auth: AuthBearer,
		KeyEnv: "CLEARANCE_MISTRAL_API_KEY", DefaultModel: "mistral-small-latest",
		Docs: "https://console.mistral.ai/api-keys",
	},
	{
		ID: "cohere", Kind: KindFirstParty,
		BaseURL: "https://api.cohere.com/v1", Wire: WireOpenAI, Auth: AuthBearer,
		KeyEnv: "CLEARANCE_COHERE_API_KEY", DefaultModel: "command-r7b-12-2024",
		Docs: "https://dashboard.cohere.com/api-keys",
	},
	{
		ID: "deepseek", Kind: KindFirstParty,
		BaseURL: "https://api.deepseek.com/v1", Wire: WireOpenAI, Auth: AuthBearer,
		KeyEnv: "CLEARANCE_DEEPSEEK_API_KEY", DefaultModel: "deepseek-chat",
		Docs: "https://platform.deepseek.com/api_keys",
	},
	{
		ID: "xai", Kind: KindFirstParty,
		BaseURL: "https://api.x.ai/v1", Wire: WireOpenAI, Auth: AuthBearer,
		KeyEnv: "CLEARANCE_XAI_API_KEY", DefaultModel: "grok-2-latest",
		Docs: "https://console.x.ai",
	},
	{
		ID: "perplexity", Kind: KindFirstParty,
		BaseURL: "https://api.perplexity.ai", Wire: WireOpenAI, Auth: AuthBearer,
		KeyEnv: "CLEARANCE_PERPLEXITY_API_KEY", DefaultModel: "sonar",
		Docs: "https://www.perplexity.ai/settings/api",
	},

	// ── aggregators ─────────────────────────────────────────────────────────
	{
		ID: "groq", Kind: KindAggregator,
		BaseURL: "https://api.groq.com/openai/v1", Wire: WireOpenAI, Auth: AuthBearer,
		KeyEnv: "CLEARANCE_GROQ_API_KEY", DefaultModel: "llama-3.3-70b-versatile",
		Docs: "https://console.groq.com/keys",
	},
	{
		ID: "together", Kind: KindAggregator,
		BaseURL: "https://api.together.xyz/v1", Wire: WireOpenAI, Auth: AuthBearer,
		KeyEnv: "CLEARANCE_TOGETHER_API_KEY", DefaultModel: "meta-llama/Llama-3.3-70B-Instruct-Turbo",
		Docs: "https://api.together.ai/settings/api-keys",
	},
	{
		ID: "fireworks", Kind: KindAggregator,
		BaseURL: "https://api.fireworks.ai/inference/v1", Wire: WireOpenAI, Auth: AuthBearer,
		KeyEnv: "CLEARANCE_FIREWORKS_API_KEY", DefaultModel: "accounts/fireworks/models/llama-v3p3-70b-instruct",
		Docs: "https://fireworks.ai/account/api-keys",
	},
	{
		ID: "openrouter", Kind: KindAggregator,
		BaseURL: "https://openrouter.ai/api/v1", Wire: WireOpenAI, Auth: AuthBearer,
		KeyEnv: "CLEARANCE_OPENROUTER_API_KEY", DefaultModel: "openai/gpt-4o-mini",
		Docs: "https://openrouter.ai/settings/keys",
	},

	// ── cloud-hosted ────────────────────────────────────────────────────────
	{
		// Azure serves the OpenAI shape, but the endpoint names the user's
		// resource and the model is the deployment name, so neither can be
		// defaulted. The key comes from Azure, not OpenAI.
		ID: "azure-openai", Kind: KindCloudHosted,
		NeedsBaseURL: true, Wire: WireOpenAI, Auth: AuthAzureKey,
		KeyEnv: "CLEARANCE_AZURE_OPENAI_API_KEY", DefaultModel: "",
		APIVersion: "2024-10-21",
		Docs:       "https://learn.microsoft.com/azure/ai-services/openai/",
	},
	{
		// Bedrock is reached through its OpenAI-compatible endpoint with a
		// bearer token. The SigV4 signing path is deliberately not implemented:
		// see the note on CredentialFromEnv in the CLI. A user who needs SigV4
		// sets AWS_BEARER_TOKEN_BEDROCK, which is AWS's own supported
		// alternative, and gets a working call rather than a half-implemented
		// signer that is wrong in a way nobody can debug.
		ID: "aws-bedrock", Kind: KindCloudHosted,
		BaseURL: "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1",
		Wire:    WireOpenAI, Auth: AuthBearer,
		KeyEnv: "AWS_BEARER_TOKEN_BEDROCK", DefaultModel: "us.amazon.nova-lite-v1:0",
		Docs: "https://docs.aws.amazon.com/bedrock/latest/userguide/",
	},
	{
		// Vertex, likewise, through its OpenAI-compatible endpoint. The OAuth2
		// token is obtained out of band — `gcloud auth print-access-token` — and
		// supplied as the key, because reimplementing Google's token exchange
		// is a larger surface than the whole AI feature.
		ID: "google-vertex", Kind: KindCloudHosted,
		NeedsBaseURL: true, Wire: WireOpenAI, Auth: AuthBearer,
		KeyEnv: "CLEARANCE_VERTEX_ACCESS_TOKEN", DefaultModel: "gemini-2.0-flash",
		Docs: "https://cloud.google.com/vertex-ai/docs",
	},

	// ── local, keyless ──────────────────────────────────────────────────────
	//
	// Loopback only, by construction: the host allowlist is derived from these
	// URLs, so a local provider cannot be pointed at a remote host by a config
	// file. That is the guarantee the tier exists to make.
	{
		ID: "ollama", Kind: KindLocal,
		BaseURL: "http://127.0.0.1:11434/v1", Wire: WireOpenAI, Auth: AuthNone,
		Keyless: true, DefaultModel: "llama3.2",
		Docs: "https://ollama.com/download",
	},
	{
		ID: "lmstudio", Kind: KindLocal,
		BaseURL: "http://127.0.0.1:1234/v1", Wire: WireOpenAI, Auth: AuthNone,
		Keyless: true, DefaultModel: "local-model",
		Docs: "https://lmstudio.ai",
	},
	{
		ID: "llamacpp", Kind: KindLocal,
		BaseURL: "http://127.0.0.1:8080/v1", Wire: WireOpenAI, Auth: AuthNone,
		Keyless: true, DefaultModel: "local-model",
		Docs: "https://github.com/ggml-org/llama.cpp",
	},
	{
		ID: "vllm", Kind: KindLocal,
		BaseURL: "http://127.0.0.1:8000/v1", Wire: WireOpenAI, Auth: AuthNone,
		Keyless: true, DefaultModel: "local-model",
		Docs: "https://docs.vllm.ai",
	},

	// ── escape hatch ────────────────────────────────────────────────────────
	{
		ID: "openai-compatible", Kind: KindEscapeHatch,
		NeedsBaseURL: true, Wire: WireOpenAI, Auth: AuthBearer,
		KeyEnv: "CLEARANCE_AI_API_KEY", DefaultModel: "",
		Docs: "https://platform.openai.com/docs/api-reference/chat",
	},
}

// providersByID is the lookup index, built once. A duplicate id panics at
// start-up rather than resolving to whichever row was defined last, because a
// silently shadowed provider is a provider whose allowlist is not the one in
// force.
var providersByID = func() map[string]Provider {
	m := make(map[string]Provider, len(providers))
	for _, p := range providers {
		if _, dup := m[p.ID]; dup {
			panic("ai: duplicate provider id in the table: " + p.ID)
		}
		m[p.ID] = p
	}
	return m
}()

// Lookup returns the provider row for id. The second result is false for an
// unknown id, which the caller reports as E-AI-007 — a typo in a provider name
// is worth failing on, because the alternative is silently using the default
// and sending a key to a vendor the user did not choose.
func Lookup(id string) (Provider, bool) {
	p, ok := providersByID[strings.TrimSpace(strings.ToLower(id))]
	return p, ok
}

// Providers returns every row in canonical order. The slice is a copy: callers
// may not mutate the table.
func Providers() []Provider {
	out := make([]Provider, len(providers))
	copy(out, providers)
	return out
}

// ProviderIDs returns the ids in canonical order, for an error message that
// lists the valid choices.
func ProviderIDs() []string {
	out := make([]string, 0, len(providers))
	for _, p := range providers {
		out = append(out, p.ID)
	}
	return out
}

// SortedProviderIDs returns the ids alphabetically, for a message where the
// user is scanning rather than browsing by kind.
func SortedProviderIDs() []string {
	out := ProviderIDs()
	sort.Strings(out)
	return out
}
