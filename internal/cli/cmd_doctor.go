package cli

import (
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/clearance-dev/clearance/internal/ai"
	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/corpus"
)

// ─────────────────────────────────────────────────────────────────────────────
// clearance doctor — the support surface.
//
// A user who cannot get a verdict has one question: which of the five things
// this program needs is missing? doctor answers it by naming each one and its
// state, in the order the pipeline uses them, so that the first line that says
// something is wrong is the thing to fix.
//
// It never prints a key. It prints whether a key *resolves*, which is the
// question a user has, and the length, which is the question a user has when
// they suspect a truncated paste.
// ─────────────────────────────────────────────────────────────────────────────

func runDoctor(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("clearance doctor")
	jsonOut := fs.Bool("json", false, "")
	showKeys := fs.Bool("keys", false, "")
	if code, ok := parseFlags(fs, args, stdout, stderr, doctorUsage); !ok {
		return code
	}

	fmt.Fprintln(stdout, "clearance doctor")
	fmt.Fprintf(stdout, "  %s\n\n", VersionLine())

	// ── the binary ─────────────────────────────────────────────────────────
	fmt.Fprintln(stdout, "binary")
	fmt.Fprintf(stdout, "  version:   %s\n", Version)
	fmt.Fprintf(stdout, "  commit:    %s\n", orNone(Commit))
	fmt.Fprintf(stdout, "  provenance: %s\n", orNone(Provenance))
	fmt.Fprintf(stdout, "  go:        %s\n", goVersion())
	fmt.Fprintf(stdout, "  platform:  %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(stdout, "  network:   %s\n", networkState())
	fmt.Fprintf(stdout, "  ai egress: %s\n", aiEgressState())

	// ── the corpus ─────────────────────────────────────────────────────────
	fmt.Fprintln(stdout, "\ncorpus")
	dir, tried := resolveCorpusDir("")
	if dir == "" {
		fmt.Fprintf(stdout, "  state:     MISSING\n")
		for _, t := range tried {
			fmt.Fprintf(stdout, "  tried:     %s\n", t)
		}
		fmt.Fprintf(stdout, "  %s\n", cerr.New(cerr.ECorpus001, strings.Join(tried, "; ")).Error())
	} else {
		// LoadInstalled, not Load: a release installs a compiled signed bundle
		// and no YAML, so Load would report UNLOADABLE for a corpus that is
		// present, valid and signed. `doctor` exists to explain a broken
		// install, and it must not invent one.
		c, err := corpus.LoadInstalled(corpus.LoadOptions{Dir: dir, Today: ""})
		if err != nil {
			fmt.Fprintf(stdout, "  state:     UNLOADABLE\n")
			fmt.Fprintf(stdout, "  path:      %s\n", dir)
			fmt.Fprintf(stdout, "  %s\n", errorLine(err))
		} else {
			s := c.Stats()
			fmt.Fprintf(stdout, "  state:     OK\n")
			fmt.Fprintf(stdout, "  path:      %s\n", dir)
			fmt.Fprintf(stdout, "  version:   %s\n", c.Version)
			fmt.Fprintf(stdout, "  schema:    %d\n", c.SchemaVersion)
			fmt.Fprintf(stdout, "  signed:    %s\n", yesNo(c.Signed))
			fmt.Fprintf(stdout, "  contents:  %d licences, %d obligations, %d traps, %d ToS, %d territories\n",
				s.Licences, s.Obligations, s.Traps, s.ToS, s.Territories)
			for _, n := range c.Notices {
				fmt.Fprintf(stdout, "  notice:    %s %s\n", n.Code, n.Message)
			}
		}
	}

	// ── the config ─────────────────────────────────────────────────────────
	fmt.Fprintln(stdout, "\nconfig")
	loaded, err := config.Load(config.Options{WorkDir: "."})
	if err != nil {
		fmt.Fprintf(stdout, "  state:     MISSING or INVALID\n")
		fmt.Fprintf(stdout, "  %s\n", errorLine(err))
		fmt.Fprintf(stdout, "  fix:       create clearance.config.yml in the project root\n")
	} else {
		fmt.Fprintf(stdout, "  state:     OK\n")
		fmt.Fprintf(stdout, "  sources:   %s\n", strings.Join(loaded.Sources, ", "))
		fmt.Fprintf(stdout, "  project:   %s\n", loaded.Intent.Project.Name)
		fmt.Fprintf(stdout, "  intent:    %s\n", loaded.Intent.Hash())
		a := loaded.Intent.AI
		fmt.Fprintf(stdout, "  ai:        %s\n", enabledState(a.Enabled))
		if a.Enabled {
			fmt.Fprintf(stdout, "  ai provider: %s\n", a.EffectiveProvider())
			fmt.Fprintf(stdout, "  ai jobs:   %s\n", strings.Join(a.EffectiveJobs(), ", "))
		}
		for _, n := range loaded.Notices {
			fmt.Fprintf(stdout, "  notice:    %s %s\n", n.Code, n.Message)
		}
	}

	// ── the AI providers ───────────────────────────────────────────────────
	//
	// The list is printed whether or not AI is enabled, because the question
	// "which providers can I use?" is asked before the decision to enable one.
	fmt.Fprintln(stdout, "\nproviders")
	fmt.Fprintf(stdout, "  %-20s %-14s %-12s %s\n", "ID", "KIND", "KEY", "DEFAULT MODEL")
	for _, p := range ai.Providers() {
		key := "keyless"
		if !p.Keyless {
			if resolveKeyQuietly(p) {
				key = "set"
			} else {
				key = "absent"
			}
		}
		fmt.Fprintf(stdout, "  %-20s %-14s %-12s %s\n", p.ID, p.Kind, key, orNone(p.DefaultModel))
	}
	if !*showKeys {
		fmt.Fprintf(stdout, "\n  (no key material is printed, by design. `doctor` reports only whether a key resolves.)\n")
	}
	fmt.Fprintf(stdout, "  keychain lookup is not implemented in this build; see PLAN/02-SPECIFICATIONS/10-ai-provider-spec.md §4.\n")

	if *jsonOut {
		// A machine-readable form, so that a support script does not have to
		// scrape the table. It is deliberately the same facts, not a richer set:
		// two renderings of one truth, never two truths.
		return writeDoctorJSON(stdout, stderr, dir, loaded, err)
	}
	return cerr.ExitOK
}

// resolveKeyQuietly reports whether a key resolves for a provider, without
// producing an error and without printing anything.
func resolveKeyQuietly(p ai.Provider) bool {
	if p.Keyless {
		return true
	}
	s, err := resolveAIKey(p, false, nil)
	return err == nil && s.Set()
}

// enabledState renders a bool as a word a reader does not have to interpret.
func enabledState(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled (the default)"
}

// aiEgressState states plainly whether this process can send anything to a model
// vendor. It is printed by both `version` and `doctor` because it is the fact a
// privacy-conscious user is looking for.
func aiEgressState() string {
	if AIEnabled() {
		return "ARMED for this process (a call has been or will be made)"
	}
	return "not armed - no AI call is possible until --ai arms it"
}

// writeDoctorJSON emits the same facts as a JSON object.
func writeDoctorJSON(stdout, stderr io.Writer, corpusDir string, loaded *config.Loaded, loadErr error) int {
	type provider struct {
		ID           string `json:"id"`
		Kind         string `json:"kind"`
		Keyless      bool   `json:"keyless"`
		KeyResolves  bool   `json:"key_resolves"`
		DefaultModel string `json:"default_model"`
		Docs         string `json:"docs"`
	}
	provs := make([]provider, 0, len(ai.Providers()))
	for _, p := range ai.Providers() {
		provs = append(provs, provider{
			ID: p.ID, Kind: string(p.Kind), Keyless: p.Keyless,
			KeyResolves: resolveKeyQuietly(p), DefaultModel: p.DefaultModel, Docs: p.Docs,
		})
	}

	doc := struct {
		SchemaVersion int        `json:"schema_version"`
		ToolVersion   string     `json:"tool_version"`
		GoVersion     string     `json:"go_version"`
		Platform      string     `json:"platform"`
		Network       bool       `json:"network_armed"`
		AIEgress      bool       `json:"ai_egress_armed"`
		CorpusDir     string     `json:"corpus_dir"`
		ConfigOK      bool       `json:"config_ok"`
		ConfigError   string     `json:"config_error,omitempty"`
		Providers     []provider `json:"providers"`
	}{
		SchemaVersion: 1,
		ToolVersion:   Version,
		GoVersion:     goVersion(),
		Platform:      runtime.GOOS + "/" + runtime.GOARCH,
		Network:       NetworkEnabled(),
		AIEgress:      AIEnabled(),
		CorpusDir:     corpusDir,
		ConfigOK:      loadErr == nil,
		Providers:     provs,
	}
	if loadErr != nil {
		doc.ConfigError = errorLine(loadErr)
	}
	if loaded != nil {
		_ = loaded // the fields above are the contract; Sources is in the human form
	}
	return writeJSON(stdout, stderr, doc, cerr.ERender002)
}

// ─────────────────────────────────────────────────────────────────────────────
// clearance explain — the introspection surface.
//
// It answers questions about the program rather than about a project: what a
// code means, what the taxonomy contains, which providers exist. Phase 3 names
// it, and it exists because a user who meets `E-POLICY-001` in a CI log should
// be able to look it up without a browser.
// ─────────────────────────────────────────────────────────────────────────────

func runExplain(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("clearance explain")
	codes := fs.Bool("codes", false, "")
	providers := fs.Bool("providers", false, "")
	jsonOut := fs.Bool("json", false, "")
	if code, ok := parseFlags(fs, args, stdout, stderr, explainUsage); !ok {
		return code
	}

	if *providers {
		return explainProviders(stdout, stderr, *jsonOut)
	}
	if *codes {
		return explainCodes(stdout, stderr, *jsonOut)
	}

	if fs.NArg() == 0 {
		fmt.Fprint(stdout, explainUsage)
		return cerr.ExitOK
	}

	// One code.
	arg := strings.TrimSpace(fs.Arg(0))
	spec, ok := cerr.Lookup(cerr.Code(arg))
	if !ok {
		fmt.Fprintf(stderr, "clearance: %q is not an error code in this build\n", arg)
		fmt.Fprintf(stderr, "  run 'clearance explain --codes' for the list\n")
		return cerr.ExitConfig
	}
	if *jsonOut {
		return writeJSON(stdout, stderr, spec, cerr.ERender002)
	}

	fmt.Fprintf(stdout, "%s\n", spec.Code)
	fmt.Fprintf(stdout, "  domain:    %s\n", spec.Domain)
	fmt.Fprintf(stdout, "  class:     %s\n", spec.Class)
	fmt.Fprintf(stdout, "  exit code: %d\n", spec.Exit)
	fmt.Fprintf(stdout, "  message:   %s\n", spec.Message)
	fmt.Fprintf(stdout, "  recovery:  %s\n", spec.Recovery)
	return cerr.ExitOK
}

func explainCodes(stdout, stderr io.Writer, asJSON bool) int {
	specs := cerr.Specs()
	if asJSON {
		return writeJSON(stdout, stderr, specs, cerr.ERender002)
	}
	fmt.Fprintf(stdout, "%d error codes\n\n", len(specs))
	fmt.Fprintf(stdout, "%-14s %-10s %-9s %s\n", "CODE", "DOMAIN", "CLASS", "MESSAGE")
	for _, s := range specs {
		msg := s.Message
		if len(msg) > 64 {
			msg = msg[:64] + "…"
		}
		fmt.Fprintf(stdout, "%-14s %-10s %-9s %s\n", s.Code, s.Domain, s.Class, msg)
	}
	return cerr.ExitOK
}

func explainProviders(stdout, stderr io.Writer, asJSON bool) int {
	provs := ai.Providers()
	if asJSON {
		return writeJSON(stdout, stderr, provs, cerr.ERender002)
	}
	fmt.Fprintf(stdout, "%d AI providers\n\n", len(provs))
	fmt.Fprintf(stdout, "%-20s %-14s %-22s %s\n", "ID", "KIND", "KEY ENV", "DEFAULT MODEL")
	for _, p := range provs {
		key := p.KeyEnv
		if p.Keyless {
			key = "(keyless)"
		}
		fmt.Fprintf(stdout, "%-20s %-14s %-22s %s\n", p.ID, p.Kind, key, orNone(p.DefaultModel))
	}
	fmt.Fprintf(stdout, "\nSet ai.provider in clearance.config.yml, or pass --ai-provider.\n")
	fmt.Fprintf(stdout, "Any endpoint speaking the OpenAI chat-completions shape works via 'openai-compatible'.\n")
	return cerr.ExitOK
}
