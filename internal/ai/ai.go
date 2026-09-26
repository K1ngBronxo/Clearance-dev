// Package ai is the bring-your-own-key provider layer.
//
// # THE GOVERNING RULE
//
//	The engine decides. The model explains.
//
// A verdict is computed by internal/policy and internal/verdict: deterministic,
// offline, from a signed corpus, reproducible byte for byte. This package may
// not influence that. It runs strictly *after* a verdict exists, it reads only
// what the engine already produced, and it can produce exactly one kind of
// output: a suggestion, which the caller writes to its own file.
//
// # WHY THIS PACKAGE IS PURE
//
// It is L4, and internal/arch_test.go's purity check covers it. It imports no
// os, no net, no net/http and reads no clock. Everything impure — resolving a
// key from the environment, reading keys.yml, opening a socket — lives in
// internal/cli, which is the layer the plan confines I/O to.
//
// That is not tidiness. It is what makes the spec's two load-bearing tests
// expressible: `TestAICannotAlterAVerdict` needs to hand Attach a hostile
// suggestion with no socket in the way, and `TestVerdictUnaffectedByAI` needs to
// run the determinism test "with a stub provider". A package that opened its own
// sockets could not be tested that way, and the guarantee would rest on care
// instead of on structure.
//
// # THE FOUR TIERS
//
//	T0  the CLI, unmodified        no network, no key, no AI      ← the default
//	T1  clearance check . --ai     direct to the provider, user's key
//	T2  the hosted product         server-side, keys in Supabase Vault
//	T3  --provider ollama          loopback only, keyless
//
// T0 is the product and must remain the default. Every AI feature is additive
// and degrades to silence with a WARN.
package ai

import (
	"context"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// Result is everything one AI run produced.
type Result struct {
	Provider   string
	Model      string
	Suggestion Suggestion
	Notices    []Notice
	Usage      Usage

	// Attempts counts how many times a model tried to change the verdict. It is
	// surfaced because a non-zero value is interesting: a well-behaved model
	// never produces one, and a model that reliably does is one a user may want
	// to stop paying for.
	Attempts int
}

// Resolve turns an Options into the provider row and the model name it will
// use, applying the provider's default model and validating the two mistakes a
// config can make.
//
// It is exported because the CLI needs the same resolution for `doctor`, and
// because a test that asserts the provider table is coherent should not have to
// go through a network call to do it.
func Resolve(opts Options) (Provider, string, error) {
	id := strings.TrimSpace(opts.Provider)
	if id == "" {
		id = "openai"
	}
	p, ok := Lookup(id)
	if !ok {
		return Provider{}, "", cerr.New(cerr.EAi007, id)
	}

	// base_url is the escape hatch's field. Setting it for a named provider is
	// always a mistake, and always one of two: the user meant
	// `openai-compatible`, or they are trying to redirect a provider's traffic
	// — which is the one thing the host allowlist exists to prevent. Both are
	// refused with the same code, because both are fixed by the same edit.
	if strings.TrimSpace(opts.BaseURL) != "" && !p.NeedsBaseURL {
		return Provider{}, "", cerr.New(cerr.EAi009, p.ID)
	}
	if p.NeedsBaseURL && strings.TrimSpace(opts.BaseURL) == "" {
		return Provider{}, "", cerr.New(cerr.EAi011, p.ID, "ai.base_url")
	}

	model := strings.TrimSpace(opts.Model)
	if model == "" {
		model = p.DefaultModel
	}
	if model == "" {
		// Azure's model is the deployment name and the escape hatch's is
		// whatever the vendor calls it. Neither can be defaulted, and a
		// request to a named deployment that does not exist is a 404 that
		// reads like a bad model — so the tool asks instead of guessing.
		return Provider{}, "", cerr.New(cerr.EAi011, p.ID, "ai.model")
	}

	for _, j := range opts.Jobs {
		if !j.Valid() {
			return Provider{}, "", cerr.New(cerr.EAi005, "unknown job '"+string(j)+"'")
		}
	}
	if len(opts.Jobs) == 0 {
		return Provider{}, "", cerr.New(cerr.EAi005, "no job was requested")
	}

	return p, model, nil
}

// Run performs the requested jobs and returns everything they produced.
//
// # THE ERROR CONTRACT
//
// A FATAL error from this function means the run cannot start — an unknown
// provider, a missing key, an unreachable base_url. A DEGRADE error means the
// call was attempted and failed in a way that costs an explanation, never a
// decision, and it is returned alongside whatever succeeded: the caller prints
// it as a notice and carries on with the verdict it already has.
//
// Run therefore returns a Result *and* an error on the degrade paths, and the
// caller must not treat a non-nil error as "there is no result". The helper
// `Degraded(err)` exists so that distinction is one call rather than a class
// switch at every call site.
func Run(
	ctx context.Context,
	t Transport,
	opts Options,
	v verdict.Verdict,
	in *config.Intent,
	key Secret,
	oracle LicenceOracle,
) (Result, error) {
	p, model, err := Resolve(opts)
	if err != nil {
		return Result{}, err
	}

	res := Result{Provider: p.ID, Model: model, Suggestion: Suggestion{
		SchemaVersion: 1,
		Provider:      p.ID,
		Model:         model,
	}}

	if t == nil {
		return res, cerr.New(cerr.EAi004, p.Host(opts.BaseURL), "no transport is configured")
	}

	var degraded error

	for _, job := range opts.Jobs {
		if !job.Valid() {
			continue
		}

		pl, err := BuildPayload(job, v, in, opts)
		if err != nil {
			return res, err
		}
		req, err := BuildRequest(p, model, key, opts, pl)
		if err != nil {
			return res, err
		}

		resp, err := t.Do(ctx, req)
		if err != nil {
			// The transport could not complete the request. If it already
			// classified the failure — the egress tripwire, a redirect off the
			// allowlist, an oversized body — that classification is kept rather
			// than re-wrapped, because wrapping a typed error in another of the
			// same code produces a message that names its own code twice and
			// reads like a bug in the tool.
			if _, ok := cerr.As(err); ok {
				degraded = firstDegrade(degraded, err)
			} else {
				degraded = firstDegrade(degraded, cerr.Wrap(cerr.EAi004,
					err, p.Host(opts.BaseURL), redactAll(err.Error(), key)))
			}
			continue
		}

		if sErr := statusError(p, resp.Status, key); sErr != nil {
			if cerr.IsFatal(sErr) {
				return res, sErr
			}
			degraded = firstDegrade(degraded, sErr)
			continue
		}

		text, usage, err := Extract(p, resp.Body, key)
		if err != nil {
			if cerr.IsFatal(err) {
				return res, err
			}
			degraded = firstDegrade(degraded, err)
			continue
		}
		res.Usage.TokensIn += usage.TokensIn
		res.Usage.TokensOut += usage.TokensOut

		sug, err := ParseSuggestion(job, text)
		if err != nil {
			degraded = firstDegrade(degraded, err)
			continue
		}
		sug.Provider = p.ID
		sug.Model = model
		sug.Usage = usage

		attached, notices := Attach(v, sug, opts, oracle)
		res.Notices = append(res.Notices, notices...)
		for _, n := range notices {
			if n.Code == cerr.EAi006 {
				res.Attempts++
			}
		}

		// Merged rather than replaced: a run with two jobs asked for two
		// answers, and returning the second would silently discard the first.
		merge(&res.Suggestion, attached)
	}

	res.Suggestion.Provider = p.ID
	res.Suggestion.Model = model
	res.Suggestion.Usage = res.Usage

	return res, degraded
}

// Degraded reports whether err is a non-fatal failure from this package.
//
// It exists so that a caller does not have to know that E-AI-003, 004, 005, 006
// and 010 are the degrade codes. The class is the contract (INV-5); the codes
// are detail.
func Degraded(err error) bool {
	if err == nil {
		return false
	}
	c := cerr.ClassOf(err)
	return c == cerr.ClassDegrade || c == cerr.ClassWarn
}

// firstDegrade keeps the first degrade error and discards the rest.
//
// A run with three jobs against an unreachable host produces three identical
// network errors. Printing three copies of the same sentence trains a user to
// stop reading the notices, which is how a real notice gets missed. The first is
// kept because it is the one with the original cause attached.
func firstDegrade(existing, next error) error {
	if existing != nil {
		return existing
	}
	return next
}

// statusError maps an HTTP status onto the taxonomy.
//
// # THE MAPPING IS THE POLICY
//
// 401 and 403 are FATAL because a bad key is a configuration error: the user
// asked for AI, the key is wrong, and continuing silently would produce a run
// that looks like it worked. 429 is DEGRADE because being rate-limited is
// somebody else's temporary condition, and a user whose CI went red because a
// vendor was busy would be right to be angry.
//
// 400, 404 and 422 are FATAL for the same reason 401 is: in practice they mean
// the model name does not exist, and a model name that does not exist is a
// config typo. A 5xx is DEGRADE — the provider is having a bad day, which is not
// the user's problem to fix.
func statusError(p Provider, status int, key Secret) error {
	if status >= 200 && status < 300 {
		return nil
	}
	switch {
	case status == 401 || status == 403:
		return cerr.New(cerr.EAi002, p.ID, itoa(status))
	case status == 429:
		return cerr.New(cerr.EAi003, p.ID)
	case status == 400 || status == 404 || status == 422:
		// Reported through E-AI-002 as well: both are "the provider refused the
		// request and the reason is in your config". The message names the
		// status, so the two are still distinguishable.
		return cerr.New(cerr.EAi002, p.ID, itoa(status))
	case status >= 500:
		return cerr.New(cerr.EAi004, p.Host(""), "the provider returned HTTP "+itoa(status))
	default:
		return cerr.New(cerr.EAi005, "the provider returned HTTP "+itoa(status))
	}
}

// itoa renders a small non-negative int without importing strconv, which is
// otherwise unused in this package.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
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

// merge folds a second suggestion into the first.
//
// Concatenation, not replacement, and with duplicates removed by id so that two
// jobs both explaining the same finding (which `explain,remediate` can produce)
// yields one explanation rather than two.
func merge(dst *Suggestion, src Suggestion) {
	seen := make(map[string]bool, len(dst.Findings))
	for _, f := range dst.Findings {
		seen[f.ID] = true
	}
	for _, f := range src.Findings {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		dst.Findings = append(dst.Findings, f)
	}

	seenR := make(map[string]bool, len(dst.Remediation))
	for _, r := range dst.Remediation {
		seenR[r.FindingID] = true
	}
	for _, r := range src.Remediation {
		if seenR[r.FindingID] {
			continue
		}
		seenR[r.FindingID] = true
		dst.Remediation = append(dst.Remediation, r)
	}

	seenT := make(map[string]bool, len(dst.Triage))
	for _, t := range dst.Triage {
		seenT[t.ID] = true
	}
	for _, t := range src.Triage {
		if seenT[t.ID] {
			continue
		}
		seenT[t.ID] = true
		dst.Triage = append(dst.Triage, t)
	}
}
