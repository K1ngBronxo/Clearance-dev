// Package cerr is the typed-error layer. It is L0: it imports nothing but the
// standard library, and every other package in the project imports it.
//
// INV-5: "No errors.New in product paths. Every failure is a typed error with a
// stable code, a severity, a human message, and a machine-readable detail
// payload."
//
// The 102 codes below are the complete taxonomy from
// PLAN/02-SPECIFICATIONS/09-error-taxonomy.md. A code that is not in that file
// may not exist here, and TestEveryErrorCodeIsDocumented asserts both
// directions of that statement.
package cerr

import "strings"

// Code is a stable error identifier. Codes are never renumbered and never
// reused. ADR-008: the exit codes are a frozen contract.
type Code string

// Class decides everything about how an error behaves.
//
//	FATAL     stop; the tool cannot produce a trustworthy verdict
//	DEGRADE   continue, but record a gap in the verdict
//	WARN      continue; the verdict is complete, the message is informational
//	INTERNAL  stop; this is a bug in Clearance and must be reported
type Class string

const (
	ClassFatal    Class = "FATAL"
	ClassDegrade  Class = "DEGRADE"
	ClassWarn     Class = "WARN"
	ClassInternal Class = "INTERNAL"
)

// Process exit codes. Frozen forever (ADR-008). A CI pipeline written against
// these today must still work in five years.
const (
	ExitOK           = 0 // verdict produced; no blocker (or CI mode disabled)
	ExitDoNotShip    = 1 // DO NOT SHIP
	ExitConfig       = 2 // configuration error
	ExitCorpus       = 3 // corpus error
	ExitInternal     = 4 // internal error
	ExitUndetermined = 5 // UNDETERMINED and --strict was passed
)

// The configuration domain. Every config error is FATAL with exit 2, because
// no intent means no answer: guessing intent is forbidden (Principle 5).
const (
	ECfg001 Code = "E-CFG-001" // no config found
	ECfg002 Code = "E-CFG-002" // required use.* field missing
	ECfg003 Code = "E-CFG-003" // invalid licence_model
	ECfg004 Code = "E-CFG-004" // invalid territory
	ECfg005 Code = "E-CFG-005" // ignore rule without a reason
	ECfg006 Code = "E-CFG-006" // policy tries to downgrade a corpus severity
	ECfg007 Code = "E-CFG-007" // invalid SPDX id in never_allow
	ECfg008 Code = "E-CFG-008" // unsupported schema_version
	ECfg009 Code = "E-CFG-009" // project/user config disagree (WARN)
	ECfg010 Code = "E-CFG-010" // ignore targets the root or a lockfile
	ECfg011 Code = "E-CFG-011" // the org policy file is missing, unreadable or invalid
	ECfg012 Code = "E-CFG-012" // a policy exception has expired
	ECfg013 Code = "E-CFG-013" // a repository config enables AI egress (WARN)
)

// The scanner / filesystem domain.
const (
	EScan001 Code = "E-SCAN-001" // root does not exist / not a directory
	EScan002 Code = "E-SCAN-002" // root not readable
	EScan003 Code = "E-SCAN-003" // file-count budget exceeded
	EScan004 Code = "E-SCAN-004" // symlink resolves outside the root
	EScan005 Code = "E-SCAN-005" // symlink cycle
	EScan006 Code = "E-SCAN-006" // file exceeds MaxFileSize
	EScan007 Code = "E-SCAN-007" // permission denied mid-walk
	EScan008 Code = "E-SCAN-008" // depth budget exceeded
	EScan009 Code = "E-SCAN-009" // no manifest and no lockfile
	EScan010 Code = "E-SCAN-010" // weight file, no licence resolvable
	EScan011 Code = "E-SCAN-011" // unrecognised licence text
	EScan012 Code = "E-SCAN-012" // weight header truncated
	EScan013 Code = "E-SCAN-013" // terms live in a PDF
	EScan014 Code = "E-SCAN-014" // source file exceeds the AST limit
	EScan015 Code = "E-SCAN-015" // manifest newer than its lockfile (a stale lockfile)
	EScan016 Code = "E-SCAN-016" // multiple lockfiles for one ecosystem
	EScan017 Code = "E-SCAN-017" // .env in a vendored dependency (not read)
	EScan018 Code = "E-SCAN-018" // file changed during the scan
	EScan019 Code = "E-SCAN-019" // scan timed out
	EScan020 Code = "E-SCAN-020" // an ignore rule matched >50% of the tree
	EScan021 Code = "E-SCAN-021" // a process spawn's command name is not a literal
)

// The parsing domain. All DEGRADE except the two config-parse codes, because
// refusing a malicious file and continuing is the correct behaviour: the scan
// of the rest of the tree is still valid (INV-10).
const (
	EParse001 Code = "E-PARSE-001" // lockfile unparseable
	EParse002 Code = "E-PARSE-002" // manifest unparseable
	EParse003 Code = "E-PARSE-003" // config YAML invalid (FATAL, exit 2)
	EParse004 Code = "E-PARSE-004" // config too large (FATAL, exit 2)
	EParse005 Code = "E-PARSE-005" // model config.json unparseable
	EParse006 Code = "E-PARSE-006" // JSON nesting exceeds the depth limit
	EParse007 Code = "E-PARSE-007" // unsupported SBOM specVersion
	EParse008 Code = "E-PARSE-008" // YAML anchor/alias bomb refused
	EParse009 Code = "E-PARSE-009" // disallowed YAML tag refused
	EParse010 Code = "E-PARSE-010" // unsupported declared encoding
)

// The corpus domain.
const (
	ECorpus001 Code = "E-CORPUS-001" // corpus file missing
	ECorpus002 Code = "E-CORPUS-002" // signature invalid or missing
	ECorpus003 Code = "E-CORPUS-003" // schema version unsupported
	ECorpus004 Code = "E-CORPUS-004" // a corpus entry or corpus-wide condition could not be used (not fatal)
	ECorpus005 Code = "E-CORPUS-005" // duplicate spdx_id (build-time)
	ECorpus006 Code = "E-CORPUS-006" // confidence rose without a correction (INV-8)
	ECorpus007 Code = "E-CORPUS-007" // citation URL unreachable (build-time)
	ECorpus008 Code = "E-CORPUS-008" // last_verified is in the future
	ECorpus009 Code = "E-CORPUS-009" // signed with an unknown key
	ECorpus010 Code = "E-CORPUS-010" // predicate references an unknown intent field
	ECorpus011 Code = "E-CORPUS-011" // last_verified is older than the staleness window
	ECorpus012 Code = "E-CORPUS-012" // loaded without a previous version (INV-8 comparison skipped)
)

// The policy / verdict domain.
const (
	EPolicy001 Code = "E-POLICY-001" // no corpus entry for an SPDX id
	EPolicy002 Code = "E-POLICY-002" // a citation did not resolve
	EPolicy003 Code = "E-POLICY-003" // predicate references an unknown field
	EPolicy004 Code = "E-POLICY-004" // predicate type mismatch
	EPolicy005 Code = "E-POLICY-005" // predicate recursion depth exceeded
	EPolicy006 Code = "E-POLICY-006" // policy tries to downgrade a severity
	EPolicy007 Code = "E-POLICY-007" // finding constructed without a confidence
	EPolicy008 Code = "E-POLICY-008" // two corpus entries disagree
	EPolicy009 Code = "E-POLICY-009" // obligation UNKNOWN because intent is undeclared
	EPolicy010 Code = "E-POLICY-010" // the verdict fold produced no result
)

// The rendering domain. Every renderer *failure* is FATAL and INTERNAL: a
// renderer is a pure function, so if it fails, it is a bug.
//
// The one exception is E-RENDER-007, an unsupported output format. That is not
// a renderer failure but a refusal of caller input, so it is FATAL with exit 2
// — the same exit code the CLI returns for a bad --format or --sbom flag
// (internal/cli/cmd_check.go). A renderer that is handed a format outside its
// closed set refuses it rather than approximating it, and the code says so.
const (
	ERender001 Code = "E-RENDER-001" // output path not writable
	ERender002 Code = "E-RENDER-002" // JSON marshalling failed
	ERender003 Code = "E-RENDER-003" // SARIF schema validation failed
	ERender004 Code = "E-RENDER-004" // statement renderer failed
	ERender005 Code = "E-RENDER-005" // SBOM renderer failed
	ERender006 Code = "E-RENDER-006" // colour requested but stdout is not a TTY
	ERender007 Code = "E-RENDER-007" // unsupported output format (refused, not approximated)
)

// The network domain. No network error is ever fatal: the local corpus always
// works and the product must work on a plane.
const (
	ENet001 Code = "E-NET-001" // corpus host unreachable
	ENet002 Code = "E-NET-002" // TLS certificate validation failed
	ENet003 Code = "E-NET-003" // downloaded corpus failed signature verification
	ENet004 Code = "E-NET-004" // a network call was blocked by --offline
	ENet005 Code = "E-NET-005" // update check timed out
	ENet006 Code = "E-NET-006" // UNEXPECTED outbound call blocked (INV-3 tripwire)
	ENet007 Code = "E-NET-007" // redirect to a non-allowlisted host refused
	ENet008 Code = "E-NET-008" // corpus download exceeded the size limit
)

// The AI domain. Added by PLAN/02-SPECIFICATIONS/10-ai-provider-spec.md §8.
//
// # THE SHAPE OF THIS DOMAIN IS THE FEATURE
//
// Five of these ten are DEGRADE, and that is deliberate rather than incidental.
// The engine has already produced the verdict before any AI code runs, so a
// failure here can only cost an explanation — never a decision. A user whose
// Wi-Fi dropped still gets their verdict and still gets the right exit code,
// because the exit code is a CI contract (ADR-008) and it must not depend on a
// third party's availability.
//
// The FATALs are all configuration errors: a typo in a provider name, a missing
// key that was explicitly requested, a key file the world can read, a base_url
// aimed at a named provider. Every one of them is the user's to fix and none of
// them can be papered over.
const (
	EAi001 Code = "E-AI-001" // no key for the selected provider (FATAL, exit 2)
	EAi002 Code = "E-AI-002" // 401 / 403 from the provider (FATAL, exit 2)
	EAi003 Code = "E-AI-003" // 429 rate-limited (DEGRADE)
	EAi004 Code = "E-AI-004" // network down or timed out (DEGRADE)
	EAi005 Code = "E-AI-005" // malformed or unvalidatable response (DEGRADE)
	EAi006 Code = "E-AI-006" // a suggestion would create, remove or alter a finding (DEGRADE)
	EAi007 Code = "E-AI-007" // unknown provider id (FATAL, exit 2)
	EAi008 Code = "E-AI-008" // keys.yml is group- or world-readable (FATAL, exit 2)
	EAi009 Code = "E-AI-009" // base_url supplied for a named provider (FATAL, exit 2)
	EAi010 Code = "E-AI-010" // the response exceeded the size cap (DEGRADE)
	EAi011 Code = "E-AI-011" // a provider's required config field was not supplied (FATAL, exit 2)
	EAi012 Code = "E-AI-012" // --ai and --offline were both passed (FATAL, exit 2)
)

// The MCP domain. The server speaks JSON-RPC, so most of what it can go wrong
// with is answered inside the protocol rather than by exiting — but a refusal
// still needs a stable identity, because the whole point of a stable code is
// that a stranger can look it up. The two that terminate the process are the
// two that make the stream unusable.
const (
	EMcp001 Code = "E-MCP-001" // a tool was asked for a path outside the declared workspace root (FATAL, exit 2)
	EMcp002 Code = "E-MCP-002" // a tool or method that does not exist was called (WARN, exit 0)
	EMcp003 Code = "E-MCP-003" // a message exceeded the frame size cap (WARN, exit 0)
)

// The internal domain. Every one of these is a bug. They exist so that a bug
// produces a clear, reportable message rather than a stack trace.
const (
	EInt001 Code = "E-INT-001" // architectural import rule violated at runtime
	EInt002 Code = "E-INT-002" // recovered from a panic
	EInt003 Code = "E-INT-003" // an invariant assertion failed
	EInt004 Code = "E-INT-004" // unreachable state reached
	EInt005 Code = "E-INT-005" // no corpus public key embedded
	EInt006 Code = "E-INT-006" // binary/corpus version compatibility note
)

// Spec is the documentation record for one code. Message is a template: `%s`
// placeholders are filled by the constructor, and the rendered string is the
// exact text the user sees.
type Spec struct {
	Code     Code
	Domain   string
	Class    Class
	Exit     int
	Message  string
	Recovery string
}

// domains maps a code's domain segment to its canonical name.
//
// A code is `E-<DOMAIN>-<NNN>`. The domain is everything between the leading
// `E-` and the final `-`, which matters because two domains are longer than
// three letters (SCAN, CORPUS, POLICY, RENDER, PARSE). An earlier draft took
// a fixed three-character slice, which silently mislabelled every one of them.
func domainOf(c Code) string {
	s := string(c)
	if len(s) < 5 || s[0] != 'E' || s[1] != '-' {
		return ""
	}
	rest := s[2:]
	i := strings.LastIndexByte(rest, '-')
	if i <= 0 {
		return ""
	}
	switch rest[:i] {
	case "CFG":
		return "config"
	case "SCAN":
		return "scan"
	case "PARSE":
		return "parse"
	case "CORPUS":
		return "corpus"
	case "POLICY":
		return "policy"
	case "RENDER":
		return "render"
	case "NET":
		return "net"
	case "AI":
		return "ai"
	case "MCP":
		return "mcp"
	case "INT":
		return "internal"
	}
	return ""
}

// specs is the single source of truth for code metadata. The order of this
// slice is the canonical order used by `clearance explain --codes` and by the
// documentation test; do not sort it at runtime.
var specs = []Spec{
	// ── Configuration ────────────────────────────────────────────────────────
	{ECfg001, "config", ClassFatal, ExitConfig, "No clearance.config.yml found in the project root.", "Create clearance.config.yml there. fixtures/mixed/clearance.config.yml is a minimal working example."},
	{ECfg002, "config", ClassFatal, ExitConfig, "Config is missing required fields: %s. Intent must be declared, not inferred.", "Add the listed fields"},
	{ECfg003, "config", ClassFatal, ExitConfig, "Invalid licence_model '%s'. Expected one of: closed-source, open-source, dual, internal-only.", "Fix the value"},
	{ECfg004, "config", ClassFatal, ExitConfig, "Invalid territory '%s'. Use ISO-3166 alpha-2 or one of: EU, EEA, US, GB, APAC, global.", "Fix the entry"},
	{ECfg005, "config", ClassFatal, ExitConfig, "Policy ignore rule for '%s' has no reason. Every ignore must state why.", "Add a reason"},
	{ECfg006, "config", ClassFatal, ExitConfig, "Policy cannot downgrade severity for all of %s. Policy may escalate or narrowly whitelist, never globally weaken.", "Narrow the rule or remove it"},
	{ECfg007, "config", ClassFatal, ExitConfig, "'%s' is not a valid SPDX identifier.", "Fix the id"},
	{ECfg008, "config", ClassFatal, ExitConfig, "Config schema_version %s is not supported by this binary (max %s). Upgrade Clearance.", "Upgrade, or downgrade the config"},
	{ECfg009, "config", ClassWarn, ExitOK, "Project config overrides user config for '%s'.", "None - informational"},
	{ECfg010, "config", ClassFatal, ExitConfig, "Cannot ignore the project root or a lockfile: '%s'.", "Narrow the rule"},
	{ECfg011, "config", ClassFatal, ExitConfig, "The org policy file '%s' is invalid: %s.", "Fix the policy file"},
	{ECfg012, "config", ClassWarn, ExitOK, "The policy exception for '%s' expired on %s and no longer applies.", "Renew it with a new expiry and owner, or remove it"},
	{ECfg013, "config", ClassWarn, ExitOK, "This repository's config enables AI egress (ai.enabled: true in '%s'). Passing --no-ai overrides it.", "None if you trust the repository; otherwise pass --no-ai"},

	// ── Scanner / filesystem ─────────────────────────────────────────────────
	{EScan001, "scan", ClassFatal, ExitConfig, "Path '%s' is not a directory.", "Pass a valid path"},
	{EScan002, "scan", ClassFatal, ExitConfig, "Cannot read '%s': permission denied.", "Fix permissions"},
	{EScan003, "scan", ClassDegrade, ExitOK, "Scan truncated: %s of ~%s files. Results may be incomplete.", "Scan a subdirectory, or raise --max-files"},
	{EScan004, "scan", ClassWarn, ExitOK, "Skipped symlink '%s' -> '%s' (outside project root).", "Expected; no action"},
	{EScan005, "scan", ClassWarn, ExitOK, "Skipped symlink cycle at '%s'.", "Expected; no action"},
	{EScan006, "scan", ClassDegrade, ExitOK, "Skipped '%s' (%s) - too large to parse. Recorded but not classified.", "Expected for weight files; no action"},
	{EScan007, "scan", ClassDegrade, ExitOK, "Cannot read '%s': permission denied. Skipped.", "Fix permissions if the file matters"},
	{EScan008, "scan", ClassDegrade, ExitOK, "Stopped descending at '%s' (depth > %s).", "Raise --max-depth"},
	{EScan009, "scan", ClassFatal, ExitConfig, "No dependency manifest found in '%s'. Point Clearance at a project root (a directory containing package.json, pyproject.toml, go.mod or Cargo.toml).", "Point at the right directory"},
	{EScan010, "scan", ClassDegrade, ExitOK, "Weight file '%s' has no licence statement in config.json, README.md, MODEL_CARD.md or a sibling LICENSE.", "Locate the licence, or remove the file"},
	{EScan011, "scan", ClassDegrade, ExitOK, "Unrecognised licence text at '%s'. A human should read it.", "Read the file, or contribute a corpus entry"},
	{EScan012, "scan", ClassDegrade, ExitOK, "Cannot read the metadata header of '%s'.", "Check the file is not corrupted"},
	{EScan013, "scan", ClassDegrade, ExitOK, "'%s' references a PDF for its terms. Clearance cannot read PDFs. Read it yourself.", "Read the PDF"},
	{EScan014, "scan", ClassDegrade, ExitOK, "Skipped AST analysis of '%s' (%s). Falling back to string signals.", "Expected; no action"},
	{EScan015, "scan", ClassWarn, ExitOK, "'%s' is newer than '%s'. Using the lockfile, which may be stale.", "Regenerate the lockfile if the manifest changed"},
	{EScan016, "scan", ClassWarn, ExitOK, "Found both %s. Using %s.", "Remove one if unintended"},
	{EScan017, "scan", ClassDegrade, ExitOK, "A vendored dependency contains a .env file. Clearance records its existence only; contents are never read.", "Check it does not contain real secrets"},
	{EScan018, "scan", ClassWarn, ExitOK, "'%s' changed during the scan; results reflect the version read.", "Re-run on a stable tree"},
	{EScan019, "scan", ClassFatal, ExitConfig, "Scan timed out after %s.", "Raise --timeout, or scan a subdirectory"},
	{EScan020, "scan", ClassDegrade, ExitOK, "Ignore rule '%s' excluded %s of files. This may be hiding dependencies.", "Narrow the ignore"},
	{EScan021, "scan", ClassWarn, ExitOK, "A process is spawned at '%s' with a command name that is not a literal. Clearance cannot tell which tool is invoked, so it records the spawn and nothing more.", "None — the name is genuinely dynamic"},

	// ── Parsing ──────────────────────────────────────────────────────────────
	{EParse001, "parse", ClassDegrade, ExitOK, "Cannot parse '%s': %s. Falling back to the manifest.", "Fix the lockfile, or regenerate it"},
	{EParse002, "parse", ClassDegrade, ExitOK, "Cannot parse '%s': %s.", "Fix the manifest"},
	{EParse003, "parse", ClassFatal, ExitConfig, "Cannot parse %s: %s", "Fix the config"},
	{EParse004, "parse", ClassFatal, ExitConfig, "%s is %s; the limit is %s.", "Shrink the config"},
	{EParse005, "parse", ClassDegrade, ExitOK, "Cannot parse '%s'. Skipping this licence source.", "Fix the file"},
	{EParse006, "parse", ClassDegrade, ExitOK, "'%s' is nested too deeply (depth > %s). Refused to parse.", "Inspect the file - this may be a bomb"},
	{EParse007, "parse", ClassDegrade, ExitOK, "SBOM specVersion %s is not supported (min %s). Falling back to a filesystem scan.", "Regenerate the SBOM"},
	{EParse008, "parse", ClassDegrade, ExitOK, "Refused to parse '%s': excessive YAML aliases.", "Inspect the file - this is a known attack pattern"},
	{EParse009, "parse", ClassDegrade, ExitOK, "Refused to parse '%s': disallowed tag '%s'.", "Inspect the file"},
	{EParse010, "parse", ClassDegrade, ExitOK, "'%s' declares charset '%s'; only UTF-8 is supported.", "Re-save as UTF-8"},

	// ── Corpus ───────────────────────────────────────────────────────────────
	{ECorpus001, "corpus", ClassFatal, ExitCorpus, "Corpus not found at '%s'. Reinstall Clearance, or run 'clearance corpus update'.", "Reinstall or update"},
	{ECorpus002, "corpus", ClassFatal, ExitCorpus, "Corpus signature is invalid. Refusing to verdict. The previous corpus is unchanged.", "Re-download the release, or check for tampering"},
	{ECorpus003, "corpus", ClassFatal, ExitCorpus, "Corpus schema v%s is not supported by this binary (max %s). Upgrade Clearance.", "Upgrade the binary"},
	{ECorpus004, "corpus", ClassDegrade, ExitOK, "Corpus entry '%s' could not be used and was skipped.", "Report it; a dependency needing it becomes UNDETERMINED"},
	{ECorpus005, "corpus", ClassFatal, ExitCorpus, "Duplicate spdx_id '%s' in the corpus.", "Fix the corpus source"},
	{ECorpus006, "corpus", ClassFatal, ExitCorpus, "Corpus entry '%s' raised its confidence without a correction record. Refusing to load.", "Add a correction block"},
	{ECorpus007, "corpus", ClassWarn, ExitOK, "Citation URL is unreachable: '%s'.", "Fix the URL or mark it stale"},
	{ECorpus008, "corpus", ClassWarn, ExitOK, "Corpus entry '%s' has a future last_verified date. Treating it as LOW confidence.", "Fix the date"},
	{ECorpus009, "corpus", ClassFatal, ExitCorpus, "Corpus was signed with an unknown key. Refusing to load.", "Re-download from the official release"},
	{ECorpus010, "corpus", ClassDegrade, ExitOK, "Corpus entry '%s' references an unknown field. Entry skipped.", "Report it; it is a corpus bug"},
	{ECorpus011, "corpus", ClassWarn, ExitOK, "Corpus entry '%s' was last verified on %s, which is outside its %s-day staleness window. Its clauses are reported one confidence level lower.", "Re-verify the entry against the primary source and update last_verified"},
	{ECorpus012, "corpus", ClassWarn, ExitOK, "Loaded without a previous corpus version; confidence rises could not be compared. Supply the previous version to enforce INV-8 in full.", "Supply the previous corpus version so the INV-8 comparison can run"},

	// ── Policy / verdict ─────────────────────────────────────────────────────
	{EPolicy001, "policy", ClassDegrade, ExitOK, "No corpus entry for licence '%s' (%s).", "Contribute an entry; the dependency is UNDETERMINED"},
	{EPolicy002, "policy", ClassInternal, ExitInternal, "Internal error: citation '%s' did not resolve. This is a corpus bug.", "Report it - a release guard should have caught this"},
	{EPolicy003, "policy", ClassInternal, ExitInternal, "Internal error: unknown field '%s' in predicate.", "Report it - caught at corpus build"},
	{EPolicy004, "policy", ClassInternal, ExitInternal, "Internal error: predicate type mismatch at '%s'.", "Report it - caught at corpus build"},
	{EPolicy005, "policy", ClassInternal, ExitInternal, "Internal error: predicate too deeply nested.", "Report it"},
	{EPolicy006, "policy", ClassFatal, ExitConfig, "Policy cannot downgrade %s. Escalate or whitelist narrowly.", "Fix the policy"},
	{EPolicy007, "policy", ClassInternal, ExitInternal, "Internal error: finding without confidence.", "Report it (INV-2 - should be impossible)"},
	{EPolicy008, "policy", ClassWarn, ExitOK, "Corpus inconsistency for '%s': two obligations share an id.", "Report it"},
	{EPolicy009, "policy", ClassDegrade, ExitOK, "Cannot determine '%s' - declare it in clearance.config.yml for a definitive verdict.", "Declare the field"},
	{EPolicy010, "policy", ClassInternal, ExitInternal, "Internal error: the verdict fold produced no result.", "Report it - the fold must be total"},

	// ── Rendering ────────────────────────────────────────────────────────────
	{ERender001, "render", ClassFatal, ExitInternal, "Cannot write to '%s': permission denied.", "Fix the path"},
	{ERender002, "render", ClassFatal, ExitInternal, "Internal error: failed to serialise the verdict.", "Report it"},
	{ERender003, "render", ClassFatal, ExitInternal, "Internal error: SARIF output is invalid.", "Report it"},
	{ERender004, "render", ClassFatal, ExitInternal, "Internal error: statement generation failed.", "Report it"},
	{ERender005, "render", ClassFatal, ExitInternal, "Internal error: SBOM generation failed.", "Report it"},
	{ERender006, "render", ClassWarn, ExitOK, "Colour output disabled: stdout is not a TTY.", "None"},
	{ERender007, "render", ClassFatal, ExitConfig, "Unsupported output format '%s'.", "Run 'clearance check --help' for the supported formats"},

	// ── Network ──────────────────────────────────────────────────────────────
	{ENet001, "net", ClassDegrade, ExitOK, "Cannot reach %s. Using the local corpus (%s).", "Check connectivity; the local corpus still works"},
	{ENet002, "net", ClassDegrade, ExitOK, "Corpus host certificate is invalid. Refusing to download.", "Do not proceed; report it"},
	{ENet003, "net", ClassDegrade, ExitOK, "Downloaded corpus failed signature verification. Discarded. The local corpus is unchanged.", "Report it; check for a compromised mirror"},
	{ENet004, "net", ClassDegrade, ExitOK, "Network call blocked (--offline).", "Expected; no action"},
	{ENet005, "net", ClassDegrade, ExitOK, "Corpus update check timed out. Continuing with the local corpus.", "None - non-blocking"},
	{ENet006, "net", ClassDegrade, ExitOK, "Internal error: an unexpected outbound call was blocked.", "Report it immediately - this is INV-3 firing"},
	{ENet007, "net", ClassDegrade, ExitOK, "Refused to follow a redirect to '%s'.", "Report it if unexpected"},
	{ENet008, "net", ClassDegrade, ExitOK, "Corpus bundle exceeds %s. Refused.", "Report it"},

	// ── AI ───────────────────────────────────────────────────────────────────
	{EAi001, "ai", ClassFatal, ExitConfig, "No API key for provider '%s'. Set %s, or pass --api-key-stdin.", "Set the environment variable, or pipe the key in with --api-key-stdin"},
	{EAi002, "ai", ClassFatal, ExitConfig, "Provider '%s' rejected the key (HTTP %s). A bad key is a configuration error, not a degraded run.", "Check the key, then retry"},
	{EAi003, "ai", ClassDegrade, ExitOK, "Provider '%s' rate-limited the request (HTTP 429). The verdict is unaffected.", "Retry later, or switch provider"},
	{EAi004, "ai", ClassDegrade, ExitOK, "Cannot reach '%s': %s. The verdict is unaffected.", "Check connectivity; the verdict stands"},
	{EAi005, "ai", ClassDegrade, ExitOK, "Discarded an AI response that could not be validated: %s. The verdict is unaffected.", "None - the explanation is optional"},
	{EAi006, "ai", ClassDegrade, ExitOK, "Discarded an AI suggestion that would have altered finding '%s'. The model may explain a verdict, never change one.", "None - this is the INV-1 guard firing correctly"},
	{EAi007, "ai", ClassFatal, ExitConfig, "Unknown AI provider '%s'. Run 'clearance doctor' for the list of supported providers.", "Fix ai.provider, or use 'openai-compatible'"},
	{EAi008, "ai", ClassFatal, ExitConfig, "The key file '%s' is readable by other users (mode %s). Refusing to read a key that is exposed.", "chmod 600 the file"},
	{EAi009, "ai", ClassFatal, ExitConfig, "ai.base_url is set for provider '%s', which is not openai-compatible. Use provider 'openai-compatible' to target a custom endpoint.", "Remove base_url, or set provider: openai-compatible"},
	{EAi010, "ai", ClassDegrade, ExitOK, "Discarded an AI response larger than %s. The verdict is unaffected.", "None - the response was refused, not truncated"},
	{EAi011, "ai", ClassFatal, ExitConfig, "Provider '%s' needs '%s', which was not supplied.", "Set the field in the ai: block of clearance.config.yml"},
	{EAi012, "ai", ClassFatal, ExitConfig, "--ai and --offline were both passed. The first requires the network and the second forbids it.", "Drop one of the two flags"},

	// ── MCP ──────────────────────────────────────────────────────────────────
	{EMcp001, "mcp", ClassFatal, ExitConfig, "The MCP request asked for '%s', which is outside the declared workspace root. The server reads only within the root it was started in.", "Restart 'clearance mcp serve' with --root set to the directory you want read"},
	{EMcp002, "mcp", ClassWarn, ExitOK, "The MCP client called '%s', which is not a tool this server exposes. The call was answered with a JSON-RPC error and the server is still running.", "Call tools/list to see what is available"},
	{EMcp003, "mcp", ClassWarn, ExitOK, "An MCP message exceeded the %s frame cap and was skipped. The server is still running.", "Send smaller requests; a project path is not a payload"},

	// ── Internal ─────────────────────────────────────────────────────────────
	{EInt001, "internal", ClassFatal, ExitInternal, "Internal error: architectural violation detected.", "Report it"},
	{EInt002, "internal", ClassFatal, ExitInternal, "Internal error: recovered from a panic in %s.", "Report it with the stack trace"},
	{EInt003, "internal", ClassFatal, ExitInternal, "Internal error: invariant %s violated.", "Report it"},
	{EInt004, "internal", ClassFatal, ExitInternal, "Internal error: unreachable state in %s.", "Report it"},
	{EInt005, "internal", ClassFatal, ExitInternal, "Internal error: no corpus public key embedded.", "Reinstall"},
	{EInt006, "internal", ClassWarn, ExitOK, "Binary v%s expects corpus <= v%s; found v%s.", "None - informational"},
}

// specsByCode is the lookup index, built once at init from the ordered slice.
var specsByCode = func() map[Code]Spec {
	m := make(map[Code]Spec, len(specs))
	for _, s := range specs {
		if _, dup := m[s.Code]; dup {
			panic("cerr: duplicate code in the taxonomy: " + string(s.Code))
		}
		if s.Domain != domainOf(s.Code) {
			panic("cerr: domain mismatch for " + string(s.Code))
		}
		m[s.Code] = s
	}
	return m
}()

// Lookup returns the documentation record for a code. The second result is
// false for an unknown code, which is itself an internal error at the call
// site (an unknown code cannot have been constructed by this package).
func Lookup(c Code) (Spec, bool) {
	s, ok := specsByCode[c]
	return s, ok
}

// Specs returns every code in canonical order. The returned slice is a copy:
// callers may not mutate the taxonomy.
func Specs() []Spec {
	out := make([]Spec, len(specs))
	copy(out, specs)
	return out
}

// Domain returns the domain name of a code ("config", "scan", …) or "" if the
// code is not a known shape.
func Domain(c Code) string { return domainOf(c) }
