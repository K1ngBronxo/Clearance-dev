package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/clearance-dev/clearance/internal/ai"
	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/corpus"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/policyfile"
	"github.com/clearance-dev/clearance/internal/report"
	"github.com/clearance-dev/clearance/internal/scanner"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// checkFlags is the parsed command line. It exists as a struct so that the
// pipeline below reads as a sequence of named steps rather than a wall of
// pointer dereferences, and so that a test can build one directly.
type checkFlags struct {
	root        string
	configPath  string
	format      report.Format
	offline     bool
	strict      bool
	failOn      string
	allowMedium bool
	outputPath  string
	noColor     bool
	quiet       bool
	verbose     bool
	timeout     time.Duration
	corpusDir   string
	today       string

	// sbom is the dialect to export in addition to the report. Empty means no
	// export.
	sbom report.SBOMFormat

	// policy is the organisation's policy file, already loaded and validated.
	// Nil means none was supplied.
	policy *policyfile.Policy

	// ── the AI tier (T1 / T3). All of it is opt-in; the defaults are Tier 0.
	ai         bool
	noAI       bool
	aiProvider string
	aiModel    string
	aiJobs     []string
	aiOutput   string

	// apiKeyStdin makes the key arrive on stdin, so that it is never an argv and
	// therefore never in ps or the shell history.
	apiKeyStdin bool

	// stdin is the reader the key is taken from. It is a field rather than
	// os.Stdin so that a test can supply a key without a subprocess.
	stdin io.Reader
}

// permuteFlags moves positional arguments to the end so that flags may appear
// anywhere on the command line.
//
// Go's flag package stops parsing at the first token that does not begin with a
// hyphen. The consequence is that `clearance check . --format json` silently
// treats `--format` and `json` as two extra paths and fails with "check takes
// at most one path, got 3" — an error message that describes the symptom and
// hides the cause entirely.
//
// Rather than document the restriction, the arguments are reordered. A CLI
// whose flags only work in one position is a CLI that people get wrong, and
// this particular wrongness produces a message pointing at the wrong thing.
//
// Knowing which flags take a value is what makes the reorder safe: a non-bool
// flag consumes the token after it, so `--format json` stays together while a
// bare `json` would be a path. `--` ends flag parsing, and everything after it
// is positional — which is how a user escapes a path that genuinely begins with
// a hyphen.
func permuteFlags(fs *flag.FlagSet, args []string) []string {
	flags := make([]string, 0, len(args))
	positional := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		a := args[i]

		if a == "--" {
			// The separator itself is KEPT. Dropping it would leave the
			// tokens after it looking like flags again — `-- -weird-name`
			// would become a bare `-weird-name`, which the flag package would
			// reject as an undefined flag. The escape hatch has to survive the
			// reorder to be an escape hatch.
			flags = append(flags, a)
			positional = append(positional, args[i+1:]...)
			break
		}
		// A bare "-" is positional to the flag package, and so is anything
		// that does not start with a hyphen.
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}

		flags = append(flags, a)

		// `--flag=value` carries its own value; nothing to consume.
		if strings.ContainsRune(a, '=') {
			continue
		}

		// An unknown flag is left alone so that fs.Parse rejects it, which
		// keeps that error message in exactly one place.
		fl := fs.Lookup(strings.TrimLeft(a, "-"))
		if fl == nil || isBoolFlag(fl) {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positional...)
}

// isBoolFlag reports whether a flag was defined with Bool or BoolVar. The flag
// package signals this by giving the Value an IsBoolFlag method, so a type
// assertion is the supported way to ask — as opposed to keeping a second list
// of boolean flag names here, which would drift the first time someone added
// one.
func isBoolFlag(f *flag.Flag) bool {
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && bf.IsBoolFlag()
}

// runCheck is `clearance check`. It returns the process exit code and never
// calls os.Exit, so that every code path is reachable from a test.
func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clearance check", flag.ContinueOnError)
	// The flag package's own error output is suppressed so that errors are
	// rendered once, in this program's format, rather than twice in two
	// different ones.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	var (
		configPath  = fs.String("config", "", "")
		formatName  = fs.String("format", string(report.FormatHuman), "")
		offline     = fs.Bool("offline", false, "")
		strict      = fs.Bool("strict", false, "")
		failOn      = fs.String("fail-on", "BLOCK", "")
		allowMedium = fs.Bool("allow-medium-blockers", false, "")
		outputPath  = fs.String("output", "", "")
		noColor     = fs.Bool("no-color", false, "")
		quiet       = fs.Bool("quiet", false, "")
		verbose     = fs.Bool("verbose", false, "")
		timeout     = fs.Duration("timeout", 60*time.Second, "")
		corpusDir   = fs.String("corpus", "", "")
		todayFlag   = fs.String("today", "", "")
		sbom        = fs.String("sbom", "", "")
		policyPath  = fs.String("policy", "", "")
		jsonSchema  = fs.Bool("json-schema", false, "")

		aiFlag      = fs.Bool("ai", false, "")
		noAIFlag    = fs.Bool("no-ai", false, "")
		aiProvider  = fs.String("ai-provider", "", "")
		aiModel     = fs.String("ai-model", "", "")
		aiJobs      = fs.String("ai-jobs", "", "")
		aiOutput    = fs.String("ai-output", "", "")
		apiKeyStdin = fs.Bool("api-key-stdin", false, "")
	)

	if err := fs.Parse(permuteFlags(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, checkUsage)
			return cerr.ExitOK
		}
		fmt.Fprintf(stderr, "clearance: %v\n\n", err)
		fmt.Fprint(stderr, checkUsage)
		return cerr.ExitConfig
	}

	// ── validate the flags that are implemented ────────────────────────────
	format := report.Format(*formatName)
	if !format.Valid() {
		fmt.Fprintf(stderr, "clearance: invalid value for --format: %q\n", *formatName)
		fmt.Fprintf(stderr, "  expected: %s\n", formatList())
		return cerr.ExitConfig
	}

	sbomFormat := report.SBOMFormat(*sbom)
	if *sbom != "" && !sbomFormat.Valid() {
		fmt.Fprintf(stderr, "clearance: invalid value for --sbom: %q\n", *sbom)
		fmt.Fprintf(stderr, "  expected: %s\n", sbomList())
		return cerr.ExitConfig
	}

	// --json-schema is a query about the binary, not about a project, so it is
	// answered and the run ends. It used to be refused, on the theory that the
	// schema was a build artefact of the corpus tool — but the contract says
	// the binary embeds it, and a consumer that cannot get the schema from the
	// binary has to guess the version it is validating against.
	if *jsonSchema {
		return writeJSONSchema(stdout, stderr)
	}

	var orgPolicy *policyfile.Policy
	if *policyPath != "" {
		p, err := policyfile.Load(*policyPath)
		if err != nil {
			// The error already carries its code, message and recovery from
			// the taxonomy (INV-5), so it is rendered through the same path
			// every other coded error uses rather than being reformatted here.
			return fail(stderr, err)
		}
		orgPolicy = p
	}

	// --ai-jobs is validated here rather than at the point of use, so that a typo
	// fails before a scan rather than after one.
	var jobs []string
	for _, j := range strings.Split(*aiJobs, ",") {
		j = strings.ToLower(strings.TrimSpace(j))
		if j == "" {
			continue
		}
		switch ai.Job(j) {
		case ai.JobExplain, ai.JobRemediate, ai.JobTriage:
			jobs = append(jobs, j)
		default:
			fmt.Fprintf(stderr, "clearance: invalid value for --ai-jobs: %q\n", j)
			fmt.Fprintf(stderr, "  expected a comma-separated list of: explain, remediate, triage\n")
			return cerr.ExitConfig
		}
	}

	failWeight, ok := severityWeight(*failOn)
	if !ok {
		fmt.Fprintf(stderr, "clearance: invalid value for --fail-on: %q\n", *failOn)
		fmt.Fprintf(stderr, "  expected: BLOCK, CONDITION, NOTE\n")
		return cerr.ExitConfig
	}

	if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "clearance: check takes at most one path, got %d\n", fs.NArg())
		fmt.Fprint(stderr, checkUsage)
		return cerr.ExitConfig
	}

	f := checkFlags{
		root:        ".",
		configPath:  *configPath,
		format:      format,
		offline:     offlineForced(*offline),
		strict:      *strict,
		failOn:      strings.ToUpper(*failOn),
		allowMedium: *allowMedium,
		outputPath:  *outputPath,
		noColor:     *noColor,
		quiet:       *quiet,
		verbose:     *verbose,
		timeout:     *timeout,
		corpusDir:   *corpusDir,
		today:       *todayFlag,
		sbom:        sbomFormat,
		policy:      orgPolicy,

		ai:          *aiFlag,
		noAI:        *noAIFlag,
		aiProvider:  *aiProvider,
		aiModel:     *aiModel,
		aiJobs:      jobs,
		aiOutput:    *aiOutput,
		apiKeyStdin: *apiKeyStdin,
		stdin:       os.Stdin,
	}
	if fs.NArg() == 1 {
		f.root = fs.Arg(0)
	}
	if f.today == "" {
		// The clock is read here, once, at the process boundary. Nothing below
		// this layer may read it (INV-6).
		f.today = time.Now().Format("2006-01-02")
	}

	return runCheckWith(f, stdout, stderr, failWeight)
}

// runCheckWith is the pipeline, separated from flag parsing so that it can be
// exercised directly by tests and by any future non-CLI front end.
func runCheckWith(f checkFlags, stdout, stderr io.Writer, failWeight int) int {
	start := time.Now()

	// ── 1. intent ──────────────────────────────────────────────────────────
	// Loaded before anything is scanned. If the tool does not know what the
	// user intends to do, it has no basis for a verdict, and it says so and
	// stops rather than scanning and guessing (Principle 5, E-CFG-001/002).
	cfg, err := config.Load(config.Options{
		ExplicitPath: f.configPath,
		WorkDir:      f.root,
	})
	if err != nil {
		return fail(stderr, err)
	}
	for _, n := range cfg.Notices {
		if f.quiet {
			continue
		}
		noticeText(stderr, string(n.Code), n.Message)
	}

	// ── 2. corpus ──────────────────────────────────────────────────────────
	// The corpus is the only source of judgement in the system (ADR-003). A
	// missing corpus is fatal: without it the tool would have to decide for
	// itself, which is precisely what it must never do.
	//
	// LoadInstalled, not Load, and the difference is INV-9. A release ships a
	// compiled *signed* bundle, and only LoadInstalled routes through the bundle
	// loader that verifies it. Load reads the YAML source tree, which cannot
	// carry a signature — so calling it here would have meant the shipped binary
	// loaded the one shape it was not shipped with, and never verified anything.
	// See internal/corpus/installed.go.
	//
	// Note what is NOT a candidate: anything under f.root. See resolveCorpusDir.
	corpusPath, tried := resolveCorpusDir(f.corpusDir)
	if corpusPath == "" {
		return fail(stderr, cerr.New(cerr.ECorpus001, strings.Join(tried, "; ")))
	}
	c, err := corpus.LoadInstalled(corpus.LoadOptions{Dir: corpusPath, Today: f.today})
	if err != nil {
		return fail(stderr, err)
	}
	corpusVersion, corpusSigned := corpusIdentity(c)
	for _, n := range c.Notices {
		if f.quiet {
			continue
		}
		noticeText(stderr, n.Code, n.Message)
	}

	// ── 3. scan ────────────────────────────────────────────────────────────
	g, err := scanWithTimeout(f.root, scanner.Options{Intent: cfg.Intent}, f.timeout)
	if err != nil {
		return fail(stderr, err)
	}
	for _, w := range g.Warnings {
		if f.quiet {
			continue
		}
		noticeText(stderr, w.Code, warningText(w))
	}

	// ── 4. evaluate ────────────────────────────────────────────────────────
	eval, err := policy.Evaluate(g, c, cfg.Intent, policy.Options{
		AllowMediumBlockers: f.allowMedium,
		Today:               f.today,
		OrgPolicy:           f.policy,
	})
	if err != nil {
		return fail(stderr, err)
	}
	for _, n := range eval.Notices {
		if f.quiet {
			continue
		}
		noticeText(stderr, n.Code, n.Message)
	}

	// ── 5. fold ────────────────────────────────────────────────────────────
	v := verdict.Fold(verdict.Input{
		Findings:            eval.Findings,
		Undetermined:        eval.Undetermined,
		AllowMediumBlockers: f.allowMedium,
	})
	if tcErr := v.TotalityCheck(); tcErr != nil {
		return fail(stderr, tcErr)
	}

	// The summary counts come from the graph, which is the only layer that
	// counted anything. Counting them again here would be a second source of
	// truth for a number the user may quote.
	v.Project = projectName(cfg.Intent, f.root)
	v.Summary.Dependencies = len(g.Dependencies)
	v.Summary.WeightFiles = g.CountWeights()
	v.Summary.UpstreamCLIs = g.CountUpstreamCLIs()

	// Everything non-deterministic is injected here, at the boundary, and
	// nowhere else (INV-6, ADR-004).
	v.Meta = verdict.Meta{
		ToolVersion:     Version,
		CorpusVersion:   corpusVersion,
		CorpusSigned:    corpusSigned,
		IntentHash:      cfg.Intent.Hash(),
		ConfigPath:      strings.Join(cfg.Sources, ", "),
		ScannedAt:       time.Now().Unix(),
		DurationMS:      time.Since(start).Milliseconds(),
		BuildCommit:     Commit,
		BuildProvenance: Provenance,
	}

	// ── 6. render ──────────────────────────────────────────────────────────
	opts := report.Options{
		Color:   !f.noColor && colorEnabled(stdout),
		Strict:  f.strict,
		NoNotes: f.quiet,
		Verbose: f.verbose,
		Width:   0,
	}

	out, closer, err := openOutput(f.outputPath, stdout)
	if err != nil {
		return fail(stderr, err)
	}
	if err := report.Write(out, v, f.format, opts); err != nil {
		closeQuietly(closer)
		return fail(stderr, err)
	}
	// A failed close on a report file means the report may be truncated, which
	// is exactly the failure a licence tool must not have: a half-written
	// verdict that parses as valid JSON reads as a clean pass.
	if err := closeOutput(closer); err != nil {
		return fail(stderr, cerr.Wrap(cerr.ERender001, err, f.outputPath))
	}

	// ── 6b. SBOM export ────────────────────────────────────────────────────
	//
	// The SBOM goes to its own file, and it has to. `--output` carries the
	// verdict and `--sbom` carries the component list; writing both to one
	// destination would produce a file that is neither. So `--sbom` without
	// `--output` writes the SBOM to a name derived from the dialect, and the
	// report still goes to stdout.
	//
	// The exit code is unaffected: an SBOM is an export, not a second opinion.
	// A tool whose exit code depended on which exports you asked for would be a
	// tool whose CI behaves differently depending on a flag that changes
	// nothing about the project.
	if f.sbom != "" {
		if code := writeSBOM(v, g, f, stdout, stderr); code != cerr.ExitOK {
			return code
		}
	}

	// ── 6c. the AI tier (opt-in, and never part of the verdict) ────────────
	//
	// It runs here — after the verdict is rendered, before the exit code is
	// computed — for one reason: the verdict must already exist on the user's
	// terminal before a model is asked to explain it. A feature that could delay
	// or replace the decision would be a feature that could hide it.
	//
	// The exit code is computed from the verdict and nothing else. A model being
	// down, rate-limited, or hostile cannot change what `clearance check` says a
	// build should do.
	if code, stop := runAIStep(f, cfg, v, c, stdout, stderr); stop {
		return code
	}

	// ── 7. exit ────────────────────────────────────────────────────────────
	return exitFor(v, failWeight, f.strict)
}

// writeSBOM writes the SBOM export beside the report.
//
// It returns an exit code rather than an error because it has two failure modes
// with different recoveries — an unwritable path and a marshalling bug — and
// they are already distinguished by the codes on the errors it can produce.
func writeSBOM(v verdict.Verdict, g *graph.Graph, f checkFlags, stdout, stderr io.Writer) int {
	path := f.outputPath
	if path == "" {
		path = defaultSBOMName(f.sbom, v.Project)
	} else {
		// The user asked for a specific destination for the verdict. The SBOM
		// must not overwrite it, so it goes beside it with a dialect suffix —
		// `verdict.json` becomes `verdict.cdx.json`.
		path = sbomNameBeside(path, f.sbom)
	}

	out, closer, err := openOutput(path, stdout)
	if err != nil {
		return fail(stderr, err)
	}
	if err := report.WriteSBOM(out, v, g, f.sbom); err != nil {
		closeQuietly(closer)
		return fail(stderr, err)
	}
	if err := closeOutput(closer); err != nil {
		return fail(stderr, cerr.Wrap(cerr.ERender005, err, path))
	}
	if !f.quiet {
		fmt.Fprintf(stderr, "clearance: wrote %s SBOM to %s\n", f.sbom, path)
	}
	return cerr.ExitOK
}

// defaultSBOMName derives the SBOM's file name from the dialect and project.
func defaultSBOMName(f report.SBOMFormat, project string) string {
	base := sanitiseFileName(project)
	if base == "" {
		base = "project"
	}
	if f == report.SBOMSPDX {
		return base + ".spdx.json"
	}
	return base + ".cdx.json"
}

// sbomNameBeside puts the SBOM next to the verdict file rather than on top of
// it.
func sbomNameBeside(verdictPath string, f report.SBOMFormat) string {
	dir := filepath.Dir(verdictPath)
	base := filepath.Base(verdictPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)

	suffix := ".cdx"
	if f == report.SBOMSPDX {
		suffix = ".spdx"
	}
	name := stem + suffix + ".json"
	if dir == "." || dir == "" {
		return name
	}
	return filepath.Join(dir, name)
}

// sanitiseFileName reduces a project name to something safe to use as a file
// name.
//
// The project name comes from clearance.config.yml, which is a file in the
// repository being scanned. A name containing `../` would otherwise let a
// project choose where the tool writes — the same class of bug as the corpus
// resolution rule, and prevented for the same reason rather than trusted.
func sanitiseFileName(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), ".-")
	// A name that is nothing but dots would still be a traversal.
	if strings.Contains(out, "..") {
		out = strings.ReplaceAll(out, "..", "_")
	}
	return out
}

// ─── steps ─────────────────────────────────────────────────────────────────

// scanWithTimeout runs the walk under a deadline.
//
// The walk is *abandoned* rather than cancelled. safefs has no cancellation
// channel, and threading one through the walk, the parsers and every read would
// be a large change for a feature whose entire purpose is to stop the user
// waiting. The abandoned goroutine finishes on its own and writes into a
// buffered channel that nobody reads, so it neither blocks nor leaks anything
// that outlives the process — which is about to exit anyway.
//
// A zero or negative timeout means no deadline, which is what `--timeout 0`
// should mean rather than "fail immediately".
func scanWithTimeout(dir string, opts scanner.Options, d time.Duration) (*graph.Graph, error) {
	if d <= 0 {
		return scanner.Scan(dir, opts)
	}

	type result struct {
		g   *graph.Graph
		err error
	}
	// Buffered to 1 so the abandoned goroutine can always send and exit, even
	// though nothing will ever receive.
	ch := make(chan result, 1)
	go func() {
		g, err := scanner.Scan(dir, opts)
		ch <- result{g, err}
	}()

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case r := <-ch:
		return r.g, r.err
	case <-timer.C:
		return nil, cerr.New(cerr.EScan019, d.String())
	}
}

// exitFor maps a verdict to a process exit code, honouring --fail-on.
//
// The default threshold is BLOCK, and at that setting this function is exactly
// the frozen table in ADR-008: DO NOT SHIP is 1, everything else is 0 except
// UNDETERMINED under --strict, which is 5.
//
// --fail-on raises the bar. It does not change the verdict the tool reports —
// the verdict is still printed as SHIP CONDITIONAL — it changes whether the
// *build* fails. That separation matters: a user who sets --fail-on CONDITION
// wants CI to stop, not to be told a different truth about their licences.
func exitFor(v verdict.Verdict, failWeight int, strict bool) int {
	if v.Verdict == verdict.DoNotShip {
		return cerr.ExitDoNotShip
	}
	if failWeight <= classWeight(v.Verdict) {
		return cerr.ExitDoNotShip
	}
	return v.Verdict.ExitCode(strict)
}

// classWeight ranks a verdict class for --fail-on comparison.
//
// UNDETERMINED is ranked with SHIP_CONDITIONAL rather than with SHIP, because
// the fold itself ranks unknown above known: rule (b) fires before rule (c).
// Ranking it any lower here would let --fail-on CONDITION pass a build whose
// verdict was "I could not tell" — the one outcome that must never be quiet.
func classWeight(c verdict.Class) int {
	switch c {
	case verdict.DoNotShip:
		return 3
	case verdict.ShipConditional, verdict.Undetermined:
		return 2
	case verdict.Ship:
		return 0
	}
	return 0
}

// severityWeight maps a --fail-on name to a comparable weight.
func severityWeight(name string) (int, bool) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "BLOCK":
		return 3, true
	case "CONDITION":
		return 2, true
	case "NOTE", "INFO":
		return 1, true
	}
	return 0, false
}

// openOutput returns the writer to render into. An empty path means stdout,
// which is the common case and involves no file handle at all.
func openOutput(path string, stdout io.Writer) (io.Writer, *os.File, error) {
	if path == "" {
		return stdout, nil, nil
	}
	// O_WRONLY rather than os.Create's O_RDWR: the report is written, never
	// read back, and a file opened read-write is a file an attacker with a
	// symlink can use to clobber something. See the arch test's rule that
	// os.OpenFile appears only in write mode outside safefs.
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, nil, cerr.Wrap(cerr.ERender001, err, path)
	}
	return fh, fh, nil
}

func closeOutput(fh *os.File) error {
	if fh == nil {
		return nil
	}
	return fh.Close()
}

func closeQuietly(fh *os.File) {
	if fh != nil {
		_ = fh.Close()
	}
}

// resolveCorpusDir finds the corpus. The search order is documented in
// `clearance check --help`, and it is ordered so that the most specific
// instruction wins:
//
//  1. --corpus, because an explicit flag is an explicit instruction.
//  2. $CLEARANCE_CORPUS, because CI sets environment variables more easily
//     than it threads flags through wrapper scripts.
//  3. <binary dir>/corpus, because that is where a release archive puts it, and
//     it means an installed binary works from any working directory.
//  4. <root>/corpus, which is how the repository itself is laid out and what
//     makes `go run ./cmd/clearance check .` work during development.
//
// The last two are probed with os.Stat purely to *choose a candidate*. Nothing
// is read through os.Stat, and the chosen directory is then opened through
// safefs like every other read in the program.
// resolveCorpusDir finds the corpus, and returns every location it tried so
// that a failure can say where it looked.
//
// THE RULE THAT MATTERS: the corpus is never read from inside the directory
// being scanned.
//
// An earlier version of this function fell back to `<root>/corpus`, where root
// is the project under audit. That is a supply-chain hole and a serious one.
// The corpus is the only source of judgement in the system (ADR-003), so a
// project that shipped its own `corpus/` directory could hand Clearance a
// permissive replacement and be told SHIP. The artefact being audited would be
// choosing its own verdict — which is the single failure this product exists to
// prevent, and it would have been reachable by creating one directory.
//
// The fallback is gone. TestCorpusIsNeverReadFromTheScannedTree asserts it
// stays gone, and it is written to fail if anyone reintroduces a candidate path
// that sits under the scan root.
//
// The order is: the explicit flag, the environment, next to the binary, one
// level up from the binary (which covers the `dist/` and `bin/` layouts a
// developer and a package manager both produce), then the per-user data
// directory. Refusing to guess is the last resort, and it is the right one:
// running against the wrong corpus produces a confident, wrong verdict, and
// there is no way for the user to tell.
func resolveCorpusDir(flagValue string) (string, []string) {
	tried := make([]string, 0, 8)

	consider := func(what, p string) string {
		if p == "" {
			return ""
		}
		tried = append(tried, what+": "+p)
		if isDir(p) {
			return p
		}
		return ""
	}

	if p := consider("--corpus", flagValue); p != "" {
		return p, tried
	}
	if p := consider("$CLEARANCE_CORPUS", os.Getenv("CLEARANCE_CORPUS")); p != "" {
		return p, tried
	}

	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if p := consider("next to the binary", filepath.Join(dir, "corpus")); p != "" {
			return p, tried
		}
		if p := consider("one level above the binary", filepath.Join(dir, "..", "corpus")); p != "" {
			return p, tried
		}
	}

	// The per-user location.
	//
	// os.UserConfigDir is preferred, but on Windows it is derived solely from
	// %AppData% and returns an error when that is unset — which is true in a
	// stripped CI container and in a bare shell, and was true of the
	// environment this was developed in. Falling back to $HOME/.clearance
	// means the location exists on every platform rather than on most of them.
	if cfg, err := os.UserConfigDir(); err == nil {
		if p := consider("user data directory", filepath.Join(cfg, "clearance", "corpus")); p != "" {
			return p, tried
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		if p := consider("user home directory", filepath.Join(home, ".clearance", "corpus")); p != "" {
			return p, tried
		}
	}

	return "", tried
}

// isDir reports whether path names a directory.
//
// The gosec finding below is a taint false positive. Every candidate path in
// resolveCorpusDir comes from either the operator's own flag, the operator's
// own environment, or the process's own executable and home directory. Nothing
// the scanned project controls reaches this call — which is the point of the
// function: an earlier version fell back to a corpus inside the scanned tree
// and that was removed as a supply-chain hole. Statting a path the operator
// named is the feature, not a traversal.
func isDir(path string) bool {
	st, err := os.Stat(path) // #nosec G703 -- operator-supplied candidate, not project input
	return err == nil && st.IsDir()
}

// corpusIdentity reads the version and signature state for the verdict's meta
// block. These come from the loaded Corpus rather than from a second read of
// the manifest: the corpus already parsed it, and re-reading it here would
// create a second source of truth for the version a verdict was computed
// against — which is the one field a user may quote in an audit.
func corpusIdentity(c *corpus.Corpus) (string, bool) {
	if c == nil {
		return "", false
	}
	return c.Version, c.Signed
}

// projectName prefers the name the user declared, because that is the name they
// will recognise in CI output, and falls back to the directory name.
func projectName(in *config.Intent, root string) string {
	if in != nil && strings.TrimSpace(in.Project.Name) != "" {
		return in.Project.Name
	}
	if abs, err := filepath.Abs(root); err == nil {
		return filepath.Base(abs)
	}
	return filepath.Base(root)
}

// warningText renders a scanner warning for the terminal. The code carries the
// machine meaning; the message carries the human one.
func warningText(w graph.Warning) string {
	if w.Path == "" {
		return w.Message
	}
	return w.Message + " (" + w.Path + ")"
}
