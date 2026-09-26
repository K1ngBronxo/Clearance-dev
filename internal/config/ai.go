package config

import "github.com/clearance-dev/clearance/internal/cerr"

// AIOptions is the `ai:` block of clearance.config.yml.
//
// See PLAN/02-SPECIFICATIONS/10-ai-provider-spec.md §5.
//
// # WHY THIS BLOCK IS NOT PART OF THE INTENT HASH
//
// Intent.Hash() is the identity of a verdict: two runs with the same hash must
// produce the same output byte for byte (INV-6). Turning AI on must not change
// that hash, because turning AI on does not change the verdict — it adds an
// explanation beside it. If the hash covered this block, enabling AI would
// invalidate every stored verdict hash, and a diff between two runs would show
// a change in the decision when only the commentary had changed.
//
// The rule is enforced by omission: Hash() lists the fields it covers, and this
// block is not among them. `TestAIConfigIsNotPartOfTheIntentHash` pins it.
type AIOptions struct {
	// Enabled is the master switch. The default is false and must remain so:
	// the offline product is the product.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Provider is an id from the provider table. Empty means "openai", which is
	// the least surprising default for a user who enabled AI and named nothing.
	Provider string `yaml:"provider" json:"provider"`

	// Model overrides the provider row's default. Empty means the row's default.
	Model string `yaml:"model" json:"model"`

	// Jobs is the subset of {explain, remediate, triage} to run. Empty means
	// {explain}, the cheapest and the one that needs the least of the verdict.
	Jobs []string `yaml:"jobs" json:"jobs"`

	// BaseURL is the endpoint for a provider whose endpoint is the user's own:
	// azure-openai, google-vertex and openai-compatible. Setting it for a named
	// provider is refused with E-AI-009, because that is a redirect of a
	// provider's traffic.
	BaseURL string `yaml:"base_url" json:"base_url"`

	// MaxTokens caps the response, so a runaway reply cannot blow a budget.
	MaxTokens int `yaml:"max_tokens" json:"max_tokens"`

	// TimeoutS is the whole call, not the connect.
	TimeoutS int `yaml:"timeout_s" json:"timeout_s"`

	// RedactProjectName sends "the project" instead of the project's name.
	//
	// It is a pointer because the default is true and a plain bool cannot tell
	// "not written" from "written as false". Getting that wrong in the unsafe
	// direction is exactly the failure this field exists to prevent, so the
	// absence of the field must be distinguishable from a deliberate `false`.
	RedactProjectName *bool `yaml:"redact_project_name" json:"redact_project_name,omitempty"`
}

// DefaultAIMaxTokens and DefaultAITimeoutS are the documented defaults, mirrored
// from ai.DefaultOptions. They are repeated here rather than imported because
// internal/config is L0 and internal/ai is L4 — a lower layer may not import a
// higher one, and a config default is not worth breaking the layering for.
const (
	DefaultAIMaxTokens = 1024
	DefaultAITimeoutS  = 30
)

// EffectiveRedactProjectName applies the default: absent means true.
//
// The default is redaction because the cost of being wrong in that direction is
// one pronoun, and the cost of being wrong in the other is a user's codename for
// an unannounced product arriving at a third party.
func (a AIOptions) EffectiveRedactProjectName() bool {
	if a.RedactProjectName == nil {
		return true
	}
	return *a.RedactProjectName
}

// EffectiveMaxTokens applies the default and the sanity bound.
func (a AIOptions) EffectiveMaxTokens() int {
	if a.MaxTokens <= 0 {
		return DefaultAIMaxTokens
	}
	return a.MaxTokens
}

// EffectiveTimeoutS applies the default and the sanity bound.
func (a AIOptions) EffectiveTimeoutS() int {
	if a.TimeoutS <= 0 {
		return DefaultAITimeoutS
	}
	return a.TimeoutS
}

// EffectiveProvider applies the default.
func (a AIOptions) EffectiveProvider() string {
	if a.Provider == "" {
		return "openai"
	}
	return a.Provider
}

// EffectiveJobs applies the default: explain only.
func (a AIOptions) EffectiveJobs() []string {
	if len(a.Jobs) == 0 {
		return []string{"explain"}
	}
	return a.Jobs
}

// validateAI checks the block's own coherence.
//
// It deliberately does NOT check whether the provider id exists: that is the
// provider table's business, and the table lives in internal/ai, which is above
// this layer. The check happens in the CLI, which can see both, and the code is
// the same E-AI-007 the user would get either way.
func validateAI(a AIOptions) error {
	for _, j := range a.Jobs {
		switch j {
		case "explain", "remediate", "triage":
		default:
			return cerr.New(cerr.EAi005, "unknown job '"+j+"'")
		}
	}
	// A negative bound is a typo, and a typo that silently became the default
	// would hide a user's intent to lower the cap.
	if a.MaxTokens < 0 {
		return cerr.New(cerr.EAi011, a.Provider, "ai.max_tokens")
	}
	if a.TimeoutS < 0 {
		return cerr.New(cerr.EAi011, a.Provider, "ai.timeout_s")
	}
	return nil
}
