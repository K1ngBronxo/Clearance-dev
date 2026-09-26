package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/clearance-dev/clearance/internal/ai"
	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/corpus"
	"github.com/clearance-dev/clearance/internal/report"
	"github.com/clearance-dev/clearance/internal/safefs"
	"github.com/clearance-dev/clearance/internal/safeyaml"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// maxKeyFileBytes bounds keys.yml. It is one constant rather than two because it
// is used twice: once as the read cap and once as the parser's limit. A file too
// big to parse should not be read into memory first, and a file that has been
// read should not then be refused by a parser with a different idea of "too
// big".
const maxKeyFileBytes = 64 << 10

// ─────────────────────────────────────────────────────────────────────────────
// The AI step.
//
// It runs strictly after the verdict has been rendered, and it cannot change the
// verdict: internal/ai has no way to express the change, and the verdict is
// passed by value.
//
// Everything impure about the feature lives here, in L5, where the plan confines
// I/O: reading a key from the environment or a file, arming egress, opening a
// socket through the one transport, and writing the suggestion artefact.
// ─────────────────────────────────────────────────────────────────────────────

// resolveAIKey finds the key, in the documented order.
//
//  1. --api-key-stdin      (CI; never an argv, so never in ps or shell history)
//  2. $CLEARANCE_<PROVIDER>_API_KEY
//  3. the OS keychain      (see the note below — not implemented in this build)
//  4. ~/.config/clearance/keys.yml   (mode 0600)
//
// # WHY --api-key <value> DOES NOT EXIST
//
// A key on a command line is a key in the process table and in the shell
// history. `--api-key-stdin` is the CI path and it is the only flag that carries
// key material, which is why TestNoAIKeyFlag asserts that a value-taking flag
// does not exist.
//
// # THE KEYCHAIN, HONESTLY
//
// Step 3 is not implemented. Reading the Windows Credential Manager, the macOS
// Keychain or libsecret requires either cgo or a subprocess, and this binary is
// CGO_ENABLED=0 with no process execution anywhere in it (INV-3). Rather than
// half-implement one platform or quietly renumber the list, the step is absent
// and this comment says so — and `clearance doctor` prints the same sentence, so
// a user is never left wondering why their keychain entry is ignored.
func resolveAIKey(p ai.Provider, fromStdin bool, stdin io.Reader) (ai.Secret, error) {
	// 1. stdin.
	if fromStdin {
		raw, err := io.ReadAll(io.LimitReader(stdin, 8<<10))
		if err != nil {
			return ai.Secret{}, cerr.Wrap(cerr.EAi001, err, p.ID, keyEnvNameFor(p))
		}
		s := ai.NewSecret(string(raw))
		if !s.Set() {
			return ai.Secret{}, cerr.New(cerr.EAi001, p.ID, keyEnvNameFor(p))
		}
		return s, nil
	}

	// 2. the environment.
	if p.KeyEnv != "" {
		if s := ai.NewSecret(os.Getenv(p.KeyEnv)); s.Set() {
			return s, nil
		}
	}

	// 3. the OS keychain — not implemented; see the note above.

	// 4. the key file.
	if path := aiKeysPath(); path != "" {
		if s, err := readAIKeysFile(path, p.ID); err != nil {
			return ai.Secret{}, err
		} else if s.Set() {
			return s, nil
		}
	}

	if p.Keyless {
		// A keyless provider has no key to find and that is not a failure.
		return ai.Secret{}, nil
	}
	return ai.Secret{}, cerr.New(cerr.EAi001, p.ID, keyEnvNameFor(p))
}

// keyEnvNameFor is the variable to name in the error.
func keyEnvNameFor(p ai.Provider) string {
	if p.KeyEnv != "" {
		return p.KeyEnv
	}
	return "CLEARANCE_AI_API_KEY"
}

// aiKeysPath is the key file's location, or "" when there is no home directory
// to put it in.
func aiKeysPath() string {
	if cfg, err := os.UserConfigDir(); err == nil && cfg != "" {
		return filepath.Join(cfg, "clearance", "keys.yml")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".config", "clearance", "keys.yml")
	}
	return ""
}

// readAIKeysFile reads one key out of keys.yml.
//
// The file is a flat map of provider id to key. It is parsed with safeyaml, the
// documented YAML subset, so a tag, an anchor or an alias in this file is
// refused rather than executed — which matters more here than anywhere else in
// the program, because this is the one file a user is told to put a credential
// in.
func readAIKeysFile(path, providerID string) (ai.Secret, error) {
	// The read goes through safefs rather than os.ReadFile, because INV-4 is
	// kept checkable by a grep: "os.ReadFile outside internal/safefs" is the
	// rule, and a second exception in this package would make the grep a list of
	// exceptions instead of a rule. safefs.ReadAbsFile exists for exactly this
	// read — see its comment — and applies the size cap below before reading
	// rather than after.
	data, exists, err := safefs.ReadAbsFile(path, "keys.yml", maxKeyFileBytes)
	if err != nil {
		return ai.Secret{}, cerr.Wrap(cerr.EAi001, err, providerID, keyEnvNameFor(mustProvider(providerID)))
	}
	// Absent is not an error: it is one of four places a key might be, and the
	// other three are checked around this call.
	if !exists {
		return ai.Secret{}, nil
	}

	if permErr := checkKeyFilePermissions(path, fileModeOf(path)); permErr != nil {
		return ai.Secret{}, permErr
	}

	node, err := safeyaml.Parse(data, safeyaml.Limits{MaxBytes: maxKeyFileBytes, MaxDepth: 8})
	if err != nil {
		return ai.Secret{}, cerr.Wrap(cerr.EAi001, err, providerID, "the key file is not valid YAML")
	}

	keys := map[string]string{}
	if err := safeyaml.Decode(node, &keys); err != nil {
		return ai.Secret{}, cerr.Wrap(cerr.EAi001, err, providerID,
			"the key file must be a flat map of provider id to key")
	}

	// A `default` entry is honoured last, so a user with one key for a gateway
	// does not have to repeat it under every provider id.
	if raw, ok := keys[providerID]; ok {
		return ai.NewSecret(raw), nil
	}
	if raw, ok := keys["default"]; ok {
		return ai.NewSecret(raw), nil
	}
	return ai.Secret{}, nil
}

// mustProvider is Lookup without the error, for a message that only needs the
// env-var name. An unknown id cannot reach here: Resolve has already refused it.
func mustProvider(id string) ai.Provider {
	p, _ := ai.Lookup(id)
	return p
}

// fileModeOf returns a file's mode. It exists so that the permission check is a
// pure function of a mode, which is what makes it testable on every platform
// including the one where POSIX bits are a fiction.
//
// It used to take the file's bytes as a first argument, which it never read —
// the stat was always the source. That parameter was removed rather than left
// alone, because a signature that suggests a mode can be derived from content is
// a signature the next reader will trust.
func fileModeOf(path string) os.FileMode {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Mode()
}

// permissionsTooOpen is the whole permission policy, extracted so that it is a
// pure function and can be asserted on Windows, where a real 0600 file cannot be
// created.
//
// The rule is: any group or other bit at all is a refusal. Not "readable by
// others" — any bit. A key file that others may execute is a key file with a
// careless chmod behind it, and the message that follows is the same either way.
func permissionsTooOpen(mode os.FileMode) bool {
	return mode.Perm()&0o077 != 0
}

// checkKeyFilePermissions refuses a key file the rest of the machine can read.
//
// # WINDOWS IS A DOCUMENTED EXCEPTION, NOT AN OVERSIGHT
//
// Go's os.FileMode on Windows is synthesised from the read-only attribute: a
// writable file reports 0666 whatever its ACL says. Running the POSIX check there
// would refuse every key file on the platform the product owner uses, and
// weakening the check to pass would make it meaningless everywhere. So the check
// is skipped on Windows and the reason is stated, in the code and in
// `clearance doctor`.
//
// The protection is not absent on Windows — a file under %AppData% is protected
// by the profile's ACL — it is simply not a property this program can verify
// without syscall, which INV-3 forbids it from importing.
func checkKeyFilePermissions(path string, mode os.FileMode) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if mode == 0 {
		return nil // the file vanished between read and stat; not our problem here
	}
	if permissionsTooOpen(mode) {
		return cerr.New(cerr.EAi008, path, fmt.Sprintf("%04o", mode.Perm()))
	}
	return nil
}

// ─── the step ────────────────────────────────────────────────────────────────

// runAIStep runs the requested AI jobs and renders the result.
//
// It returns an exit code and a bool: the code is non-zero only for a FATAL
// failure, and the bool says whether the caller should return immediately. Every
// degrade path prints a notice and leaves the exit code untouched, because the
// exit code is a CI contract (ADR-008) and it must not depend on a third party's
// availability.
func runAIStep(
	f checkFlags,
	cfg *config.Loaded,
	v verdict.Verdict,
	c *corpus.Corpus,
	stdout, stderr io.Writer,
) (int, bool) {
	opts, err := aiOptionsFrom(f, cfg)
	if err != nil {
		// A config mistake is FATAL, and it is the user's to fix.
		return fail(stderr, err), true
	}
	if !opts.Enabled {
		return cerr.ExitOK, false
	}

	// --ai --offline is refused, never silently ignored. A user who passed
	// --offline is a user who needs the guarantee.
	//
	// # WHY THIS IS NOT E-NET-004
	//
	// E-NET-004 is the code named for this case, and this build deliberately
	// departs from it. E-NET-004 is documented
	// as DEGRADE with exit 0 and the message "Network call blocked (--offline).
	// Expected; no action" — which is exactly right for the corpus updater,
	// where the fallback is the local corpus and the run is still complete. Here
	// the user has asked for two things that cannot both be true, and a run that
	// exits 0 has *silently ignored* one of them, which is the one outcome that
	// rule forbids. The honest classification is a configuration error, so it is
	// E-AI-012 and exit 2, and the departure is recorded rather than silent.
	if f.offline {
		return fail(stderr, cerr.New(cerr.EAi012)), true
	}

	p, model, err := ai.Resolve(opts)
	if err != nil {
		return fail(stderr, err), true
	}

	key, err := resolveAIKey(p, f.apiKeyStdin, f.stdin)
	if err != nil {
		return fail(stderr, err), true
	}
	if !p.Keyless && !key.Set() {
		return fail(stderr, cerr.New(cerr.EAi001, p.ID, keyEnvNameFor(p))), true
	}

	// --verbose states what is about to leave the machine. It is the answer to
	// "which vendor, which model, and is my project name in the prompt?", and it
	// is printed before the call rather than after, so that a user who is
	// surprised by the destination can stop it.
	if f.verbose && !f.quiet {
		dest := p.Host(opts.BaseURL)
		if dest == "" {
			dest = "(no host)"
		}
		noticeText(stderr, "ai", fmt.Sprintf(
			"sending to %s as %s (model %s); project name is %s",
			dest, p.ID, model, redactionState(opts)))
	}

	// The note about the keychain and about Windows permissions. Printed once,
	// to stderr, so that a user who wonders why their keychain entry is ignored
	// gets the answer without reading the source.
	if !f.quiet {
		if runtime.GOOS == "windows" {
			noticeText(stderr, "note", "OS keychain lookup and key-file permission checks are not available on Windows; a key comes from --api-key-stdin, the environment, or keys.yml.")
		}
	}

	// Egress is armed here and nowhere else, after every refusal above.
	EnableAI()
	tr, err := newAITransport(p.Host(opts.BaseURL), f.offline, opts.Timeout)
	if err != nil {
		return fail(stderr, err), true
	}

	ctx := context.Background()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	res, runErr := ai.Run(ctx, tr, opts, v, cfg.Intent, key, corpusOracle{c})

	// Every notice from Attach — a refused override, a dropped invented id — is
	// printed. A silent refusal is indistinguishable from compliance, and the
	// whole point of E-AI-006 is that the attempt is on the record.
	for _, n := range res.Notices {
		if f.quiet {
			break
		}
		noticeText(stderr, string(n.Code), n.Message)
	}
	if res.Attempts > 0 {
		noticeText(stderr, string(cerr.EAi006), fmt.Sprintf(
			"the model attempted to alter the verdict %d time(s). The verdict is unchanged.",
			res.Attempts))
	}

	if runErr != nil {
		if cerr.IsFatal(runErr) {
			return fail(stderr, runErr), true
		}
		// A degrade. The verdict has already been printed; the explanation did
		// not arrive. The exit code is untouched.
		//
		// The message is printed without its code prefix because noticeText
		// supplies the code: rendering err.Error() here would name the code
		// twice on one line.
		if !f.quiet {
			if e, ok := cerr.As(runErr); ok {
				noticeText(stderr, string(e.Code()), e.Message())
			} else {
				noticeText(stderr, string(cerr.CodeOf(runErr)), runErr.Error())
			}
		}
	}

	// The artefact. It is written even when the suggestion is empty, because a
	// caller in CI that asked for a file and got none cannot tell "nothing to
	// say" from "the write failed".
	if f.aiOutput != "" {
		if code := writeSuggestions(f.aiOutput, res); code != cerr.ExitOK {
			return code, true
		}
	}

	// The human block, on stderr, under a heading that states its authority.
	// Never on stdout: `clearance check . > verdict.txt` must produce a file
	// that is still exactly the verdict.
	if !f.quiet && !res.Suggestion.Empty() {
		if err := report.WriteAnnotation(stderr, aiAnnotation(res), report.Options{
			Color: !f.noColor && colorEnabled(stderr),
		}); err != nil {
			return fail(stderr, cerr.Wrap(cerr.ERender001, err, "stderr")), true
		}
	}

	return cerr.ExitOK, false
}

// aiOptionsFrom merges the config block, the CLI flags and the defaults.
//
// Precedence: CLI flag > project config > user config > built-in default. The
// merge of project over user already happened in config.Load, so this function
// only has to apply the flags on top.
func aiOptionsFrom(f checkFlags, cfg *config.Loaded) (ai.Options, error) {
	o := ai.DefaultOptions()

	if cfg != nil && cfg.Intent != nil {
		a := cfg.Intent.AI
		o.Enabled = a.Enabled
		o.Provider = a.EffectiveProvider()
		o.Model = a.Model
		o.BaseURL = a.BaseURL
		o.MaxTokens = a.EffectiveMaxTokens()
		o.Timeout = time.Duration(a.EffectiveTimeoutS()) * time.Second
		o.RedactProjectName = a.EffectiveRedactProjectName()

		jobs := make([]ai.Job, 0, len(a.EffectiveJobs()))
		for _, j := range a.EffectiveJobs() {
			jobs = append(jobs, ai.Job(j))
		}
		o.Jobs = jobs
	}

	// The flags. --ai turns it on; --no-ai turns it off and always wins.
	if f.ai {
		o.Enabled = true
	}
	if f.noAI {
		o.Enabled = false
	}
	if f.aiProvider != "" {
		o.Provider = f.aiProvider
	}
	if f.aiModel != "" {
		o.Model = f.aiModel
	}
	if len(f.aiJobs) > 0 {
		jobs := make([]ai.Job, 0, len(f.aiJobs))
		for _, j := range f.aiJobs {
			jobs = append(jobs, ai.Job(j))
		}
		o.Jobs = jobs
	}

	return o, nil
}

// redactionState renders the project-name setting for the verbose line.
func redactionState(o ai.Options) string {
	if o.RedactProjectName {
		return "redacted"
	}
	return "sent as declared"
}

// corpusOracle answers "is this licence one the corpus knows?".
//
// It is the AI layer's only window onto the corpus, and it is a yes/no question.
// A model that names an alternative the corpus recognises gets a `verified`
// mark; one that names something else is kept and marked unverified. Neither
// outcome changes a finding.
type corpusOracle struct{ c *corpus.Corpus }

func (o corpusOracle) KnowsLicence(id string) bool {
	if o.c == nil || strings.TrimSpace(id) == "" {
		return false
	}
	_, ok := o.c.Resolve(id)
	return ok
}

// writeSuggestions writes the ai-suggestions.json artefact.
//
// # IT IS A SEPARATE FILE, AND THAT IS THE WHOLE DESIGN
//
// INV-6 requires that two runs on identical (project, intent, corpus) produce
// byte-identical verdict.json. A model is non-deterministic by nature. Keeping
// AI output in its own artefact means the AI feature cannot break the
// determinism guarantee even if it is buggy — the guarantee is preserved by
// construction rather than by care.
func writeSuggestions(path string, res ai.Result) int {
	// The file is written with the same discipline as the verdict: O_WRONLY, no
	// read-back, and a close that is checked, because a truncated JSON file that
	// parses is a file that reads as a clean result.
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fail(os.Stderr, cerr.Wrap(cerr.ERender001, err, path))
	}
	enc := json.NewEncoder(fh)
	enc.SetIndent("", "  ")
	// SetEscapeHTML(false) so that a citation URL containing & is written as it
	// is rather than as \u0026. The verdict's own renderer makes the same choice.
	enc.SetEscapeHTML(false)

	doc := struct {
		SchemaVersion int           `json:"schema_version"`
		Provider      string        `json:"provider"`
		Model         string        `json:"model"`
		Usage         ai.Usage      `json:"usage"`
		Suggestion    ai.Suggestion `json:"suggestion"`
	}{
		SchemaVersion: 1,
		Provider:      res.Provider,
		Model:         res.Model,
		Usage:         res.Usage,
		Suggestion:    res.Suggestion,
	}
	if err := enc.Encode(doc); err != nil {
		_ = fh.Close()
		return fail(os.Stderr, cerr.Wrap(cerr.ERender002, err))
	}
	if err := fh.Close(); err != nil {
		return fail(os.Stderr, cerr.Wrap(cerr.ERender001, err, path))
	}
	return cerr.ExitOK
}

// aiAnnotation turns a suggestion into the renderer's neutral Annotation.
//
// The conversion lives here rather than in internal/report because the renderer
// must not know what an ai.Suggestion is. It receives a heading and some lines
// and cannot tell whether they came from a model, which is exactly the property
// that keeps AI output out of the canonical artefact.
func aiAnnotation(res ai.Result) report.Annotation {
	a := report.Annotation{Heading: report.AnnotationAIHeading}

	for _, f := range res.Suggestion.Findings {
		a.Lines = append(a.Lines, wrapHeading(f.ID), f.Explanation, "")
	}
	for _, r := range res.Suggestion.Remediation {
		line := r.FindingID
		if r.Effort != "" {
			line += "  [" + r.Effort + " effort]"
		}
		a.Lines = append(a.Lines, wrapHeading(line), r.Action)
		if r.Alternative != "" {
			mark := "unverified"
			if r.Verified {
				mark = "verified against the corpus"
			}
			a.Lines = append(a.Lines, "  alternative: "+r.Alternative+" ("+mark+")")
		}
		a.Lines = append(a.Lines, "")
	}
	for _, t := range res.Suggestion.Triage {
		a.Lines = append(a.Lines, wrapHeading(t.ID), "  read first: "+t.ReadFirst)
		if t.Why != "" {
			a.Lines = append(a.Lines, "  "+t.Why)
		}
		a.Lines = append(a.Lines, "")
	}

	a.Lines = append(a.Lines,
		fmt.Sprintf("Provider: %s · model: %s · tokens: %d in / %d out",
			res.Provider, res.Model, res.Usage.TokensIn, res.Usage.TokensOut),
		"Generated by a language model. It is not part of the verdict and carries no",
		"citation. The verdict above is the authoritative output.",
	)
	return a
}

// wrapHeading returns an id as a heading line, wrapped so that a long id does
// not push the annotation off the right edge of a terminal.
func wrapHeading(id string) string {
	if len(id) <= 72 {
		return id
	}
	return id[:72] + "…"
}
