package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/safefs"
	"github.com/clearance-dev/clearance/internal/safeyaml"
)

// MaxConfigBytes is the documented config size limit (E-PARSE-004). A config
// larger than this is not a config, it is a mistake.
const MaxConfigBytes = 256 << 10

// Notice is a WARN-class message produced during loading. It is rendered into
// the verdict's notes, because a user should be able to see that their project
// config quietly overrode their user config.
type Notice struct {
	Code    cerr.Code
	Message string
}

// Options controls discovery. Every field exists so that a test can pin the
// search path without touching the real filesystem layout.
type Options struct {
	// ExplicitPath is `--config <path>`. When set, nothing else is searched:
	// an explicit path that does not load is an error, not a fallback.
	ExplicitPath string

	// WorkDir is the project root to search. Defaults to ".".
	WorkDir string

	// UserConfigPath overrides the user-level config location. Empty means
	// ~/.config/clearance/config.yml. "-" disables the user level entirely.
	UserConfigPath string

	// Limits bounds the YAML parse. The zero value takes the defaults.
	Limits safeyaml.Limits
}

// Loaded is the result of a successful load.
type Loaded struct {
	Intent  *Intent
	Notices []Notice
	// Sources lists the files consulted, in precedence order, so the verdict's
	// meta block can name the config that produced it.
	Sources []string
}

// Load discovers, parses, merges and validates the intent.
//
// The order of operations matters and is deliberate:
//
//	discover → parse each file → merge the trees → validate the merged result
//
// Validation happens on the merged tree rather than per file, because a user
// config is allowed to supply a default that the project config overrides, and
// requiring every required field in both files would make the user config
// unusable for its stated purpose.
func Load(opts Options) (*Loaded, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}
	lim := opts.Limits
	if lim.MaxBytes == 0 {
		lim = safeyaml.Limits{MaxBytes: MaxConfigBytes, MaxDepth: 32}
	}

	type candidate struct {
		path string
		kind string // "explicit" | "project" | "user"
	}
	var candidates []candidate

	if opts.ExplicitPath != "" {
		candidates = append(candidates, candidate{opts.ExplicitPath, "explicit"})
	} else {
		candidates = append(candidates,
			candidate{filepath.Join(workDir, "clearance.config.yml"), "project"},
			candidate{filepath.Join(workDir, ".clearance", "config.yml"), "project"},
		)
		// The user level is searched last and merged underneath. "-" disables
		// it, which is what the test suite uses so that a developer's real
		// ~/.config cannot change a test outcome.
		if opts.UserConfigPath != "-" {
			up := opts.UserConfigPath
			if up == "" {
				if home, err := os.UserHomeDir(); err == nil && home != "" {
					up = filepath.Join(home, ".config", "clearance", "config.yml")
				}
			}
			if up != "" {
				candidates = append(candidates, candidate{up, "user"})
			}
		}
	}

	type parsed struct {
		path string
		kind string
		node *safeyaml.Node
	}
	var found []parsed
	var sources []string
	for _, c := range candidates {
		data, err := readFileBounded(c.path, MaxConfigBytes)
		if err != nil {
			// A candidate that is simply absent is not an error; it is how
			// discovery works. An explicit path that is absent IS an error.
			if isNotExist(err) {
				if c.kind == "explicit" {
					return nil, cerr.New(cerr.ECfg001)
				}
				continue
			}
			// A candidate that exists but cannot be read is a hard error: the
			// user pointed us at something, and silently ignoring it would mean
			// scanning with an intent they did not declare.
			if c.kind == "explicit" {
				return nil, err
			}
			continue
		}
		node, err := safeyaml.Parse(data, lim)
		if err != nil {
			// errors.As, not a type assertion: a syntax error that arrives
			// wrapped is still a syntax error, and without this it would fall
			// through to the generic path and lose the E-PARSE-003 code.
			var se *safeyaml.SyntaxError
			if errors.As(err, &se) {
				return nil, cerr.New(cerr.EParse003, displayPath(c.path), se.Error())
			}
			if e, ok := cerr.As(err); ok && e.Code() == cerr.EParse004 {
				return nil, cerr.New(cerr.EParse004, displayPath(c.path), humanBytes(int64(len(data))), humanBytes(int64(MaxConfigBytes)))
			}
			return nil, err
		}
		found = append(found, parsed{c.path, c.kind, node})
		sources = append(sources, c.path)
	}

	if len(found) == 0 {
		return nil, cerr.New(cerr.ECfg001)
	}

	// Merge: later candidates are weaker. A project config overrides a user
	// config field by field, and a notice is emitted for each field where the
	// project actually won, so the override is visible rather than silent.
	var notices []Notice
	var merged *safeyaml.Node
	var mergedFrom string
	for _, p := range found {
		if merged == nil {
			merged = p.node
			mergedFrom = p.path
			continue
		}
		if p.kind == "user" {
			// The user config is weaker: it fills gaps only.
			merged, notices = mergeNodes(merged, p.node, "", notices, p.path)
			continue
		}
		// A project config over a previously-seen project config (both
		// `clearance.config.yml` and `.clearance/config.yml` present). The
		// first one found wins and the second is reported, because two project
		// configs is a mistake a user must see.
		notices = append(notices, Notice{
			Code:    cerr.ECfg009,
			Message: "Ignoring " + displayPath(p.path) + ": " + displayPath(mergedFrom) + " takes precedence.",
		})
	}

	intent, err := decodeIntent(merged, mergedFrom)
	if err != nil {
		return nil, err
	}
	if err := Validate(intent); err != nil {
		return nil, err
	}
	intent.SourcePath = displayPath(mergedFrom)

	return &Loaded{Intent: intent, Notices: notices, Sources: sources}, nil
}

// mergeNodes merges base (stronger) with over (weaker): a key present in base
// wins, a key absent from base is taken from over. Nested mappings are merged
// recursively so that a user config setting `scale.mau` and a project config
// setting `use.commercial` both survive.
func mergeNodes(base, over *safeyaml.Node, prefix string, notices []Notice, overPath string) (*safeyaml.Node, []Notice) {
	if base == nil {
		return over, notices
	}
	if over == nil {
		return base, notices
	}
	if base.Kind != safeyaml.MappingNode || over.Kind != safeyaml.MappingNode {
		return base, notices
	}

	out := &safeyaml.Node{Kind: safeyaml.MappingNode, Line: base.Line}
	seen := map[string]bool{}
	for i, k := range base.Keys {
		seen[k] = true
		bv := base.Values[i]
		if ov, ok := over.Get(k); ok {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			if bv.Kind == safeyaml.MappingNode && ov.Kind == safeyaml.MappingNode {
				var sub []Notice
				bv, sub = mergeNodes(bv, ov, path, notices, overPath)
				notices = sub
			} else if !nodesEqual(bv, ov) {
				// The project config wins and the user config said something
				// different. Saying so is the difference between a tool that
				// overrides quietly and one that tells you it did.
				notices = append(notices, Notice{
					Code:    cerr.ECfg009,
					Message: "Project config overrides user config for '" + path + "'.",
				})
			}
		}
		out.Keys = append(out.Keys, k)
		out.Values = append(out.Values, bv)
	}
	for i, k := range over.Keys {
		if seen[k] {
			continue
		}
		out.Keys = append(out.Keys, k)
		out.Values = append(out.Values, over.Values[i])
	}
	return out, notices
}

func nodesEqual(a, b *safeyaml.Node) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case safeyaml.ScalarNode:
		return a.Str() == b.Str() && (a.Value == nil) == (b.Value == nil)
	case safeyaml.SequenceNode:
		if len(a.Items) != len(b.Items) {
			return false
		}
		for i := range a.Items {
			if !nodesEqual(a.Items[i], b.Items[i]) {
				return false
			}
		}
		return true
	case safeyaml.MappingNode:
		if len(a.Keys) != len(b.Keys) {
			return false
		}
		for i, k := range a.Keys {
			bv, ok := b.Get(k)
			if !ok || !nodesEqual(a.Values[i], bv) {
				return false
			}
		}
		return true
	}
	return false
}

// decodeIntent fills an Intent from the merged tree and records which optional
// paths were declared.
func decodeIntent(n *safeyaml.Node, source string) (*Intent, error) {
	intent := &Intent{Declared: map[string]bool{}}

	// schema_version first: a document from a future schema may use a key this
	// binary would reject as unknown, and the useful error is "upgrade
	// Clearance", not "unknown key".
	if sv, ok := n.Get("schema_version"); ok {
		v, isInt := sv.Int()
		if !isInt {
			return nil, cerr.New(cerr.ECfg008, sv.Str(), "1")
		}
		if int(v) > SchemaVersion {
			return nil, cerr.New(cerr.ECfg008, itoa(v), itoa(SchemaVersion))
		}
		intent.SchemaVersion = int(v)
	} else {
		// A config without a schema_version is treated as version 1. The field
		// is documented as required but its absence is unambiguous: there has
		// only ever been one version.
		intent.SchemaVersion = SchemaVersion
	}

	// Required use.* fields: collect every missing one so the user fixes the
	// config once instead of six times.
	var missing []string
	for _, path := range RequiredUseFields() {
		if !hasPath(n, path) {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		return nil, cerr.New(cerr.ECfg002, strings.Join(missing, ", "))
	}

	// Decode. A safeyaml error here is a type or unknown-key error; it is a
	// config error, not a parse error, and the message already names the field.
	if err := safeyaml.Decode(n, intent); err != nil {
		return nil, cerr.New(cerr.EParse003, displayPath(source), err.Error())
	}

	if err := validateAI(intent.AI); err != nil {
		return nil, err
	}

	// Record declared optional paths.
	for _, p := range []string{"scale.mau", "scale.employees", "scale.revenue_eur", "ai.redact_project_name"} {
		if hasPath(n, p) {
			intent.Declared[p] = true
		}
	}
	if hasPath(n, "territories") {
		intent.Declared["territories"] = true
	}
	if hasPath(n, "project.name") {
		intent.Declared["project.name"] = true
	}

	// Project name defaults to the directory name; it appears in the verdict
	// header and is cosmetic, so a default is honest here in a way it would not
	// be for a field that changes a decision.
	if intent.Project.Name == "" {
		intent.Project.Name = filepath.Base(mustAbs(source))
	}

	return intent, nil
}

// FromDocument decodes and validates an intent from an in-memory YAML document.
//
// # WHY THIS IS EXPORTED, AND WHAT IT IS NOT FOR
//
// `Load` does three things: discover files, merge them, and turn the merged
// document into a validated Intent. Two of those are about the filesystem. The
// third is the part an in-process caller needs, and until this existed the only
// way to reach it was to write a file.
//
// The caller is `internal/mcp`, which accepts an inline intent from an agent.
// That server may not write — C9 says it never writes — so the document arrives
// as bytes and this is the entry point.
//
// It is NOT a second loading path with softer rules. It calls decodeIntent,
// which is the same function Load calls, so an inline intent is validated
// exactly as strictly as a file on disk: the same required use.* fields, the
// same schema-version refusal, the same unknown-key rejection, and the same
// Declared bookkeeping that makes `mau` omitted different from `mau: 0`.
//
// source names where the document came from. It appears in error messages and
// supplies the default project name, so a caller passing a placeholder gets a
// placeholder in both.
func FromDocument(data []byte, source string) (*Intent, error) {
	node, err := safeyaml.Parse(data, safeyaml.Limits{MaxBytes: MaxConfigBytes, MaxDepth: 32})
	if err != nil {
		return nil, err
	}
	return decodeIntent(node, source)
}

// Validate enforces every config rule. Each failure names its code.
func Validate(in *Intent) error {
	if in == nil {
		return cerr.New(cerr.ECfg001)
	}

	// E-CFG-008 — schema version.
	if in.SchemaVersion > SchemaVersion {
		return cerr.New(cerr.ECfg008, itoa(int64(in.SchemaVersion)), itoa(SchemaVersion))
	}

	// E-CFG-003 — licence_model enum.
	if !in.Use.LicenceModel.Valid() {
		return cerr.New(cerr.ECfg003, string(in.Use.LicenceModel))
	}

	// E-CFG-004 — territories.
	for _, t := range in.Territories {
		if !ValidTerritory(t) {
			return cerr.New(cerr.ECfg004, t)
		}
	}

	// E-CFG-007 — never_allow must contain real SPDX identifiers. A typo here
	// silently disables a safety rule, which is the single worst place for a
	// typo to be invisible, so the check is strict.
	for _, id := range in.Policy.NeverAllow {
		if !ValidSPDX(id) {
			return cerr.New(cerr.ECfg007, id)
		}
	}

	// E-CFG-005 / E-CFG-010 — ignore rules.
	lockfiles := map[string]bool{
		"package-lock.json": true, "pnpm-lock.yaml": true, "yarn.lock": true,
		"poetry.lock": true, "uv.lock": true, "Pipfile.lock": true,
		"go.sum": true, "Cargo.lock": true,
	}
	for _, r := range in.Policy.Ignore {
		if strings.TrimSpace(r.Reason) == "" {
			return cerr.New(cerr.ECfg005, r.Path)
		}
		p := strings.ReplaceAll(strings.TrimSpace(r.Path), "\\", "/")
		trimmed := strings.TrimSuffix(strings.TrimSuffix(p, "/**"), "/*")
		if trimmed == "" || trimmed == "." || trimmed == "/" {
			return cerr.New(cerr.ECfg010, r.Path)
		}
		if lockfiles[filepath.Base(trimmed)] {
			return cerr.New(cerr.ECfg010, r.Path)
		}
	}

	// E-CFG-006 — no global downgrade.
	if err := validateNoGlobalDowngrade(in); err != nil {
		return err
	}

	// Required use.* fields, once more on the decoded value. This catches the
	// case where a field was present but decoded to its zero value in a way
	// that a caller of Validate (rather than Load) would otherwise miss.
	for _, path := range RequiredUseFields() {
		if !in.IsDeclared(path) {
			return cerr.New(cerr.ECfg002, path)
		}
	}

	return nil
}

// validateNoGlobalDowngrade refuses the two ways a policy can weaken the corpus
// globally rather than escalate.
func validateNoGlobalDowngrade(in *Intent) error {
	// 1. block_on that omits BLOCK means a blocker no longer fails CI. That is
	//    the definition of a global downgrade.
	blockOn := in.Policy.BlockOn
	if len(blockOn) > 0 {
		hasBlock := false
		for _, s := range blockOn {
			if strings.EqualFold(strings.TrimSpace(s), "BLOCK") {
				hasBlock = true
				break
			}
		}
		if !hasBlock {
			return cerr.New(cerr.ECfg006, "every licence")
		}
	}

	// 2. An allow_if rule naming a wildcard licence would reduce severity for
	//    everything. A whitelist must name what it whitelists.
	for _, r := range in.Policy.AllowIf {
		l := strings.TrimSpace(r.Licence)
		switch strings.ToLower(l) {
		case "", "*", "all", "any", "everything":
			return cerr.New(cerr.ECfg006, l)
		}
		if strings.ContainsAny(l, "*?") {
			return cerr.New(cerr.ECfg006, l)
		}
	}
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

// hasPath reports whether a dotted path exists in a node tree.
func hasPath(n *safeyaml.Node, path string) bool {
	parts := strings.Split(path, ".")
	cur := n
	for _, p := range parts {
		if cur == nil || cur.Kind != safeyaml.MappingNode {
			return false
		}
		next, ok := cur.Get(p)
		if !ok {
			return false
		}
		cur = next
	}
	return true
}

// readFileBounded reads a config file through safefs, so that the ban on bare
// os.Open outside safefs holds absolutely, and so that the size bound is
// enforced before the read rather than after it.
func readFileBounded(path string, max int64) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, cerr.Wrap(cerr.ECfg001, err)
	}
	root, err := safefs.New(filepath.Dir(abs), safefs.Limits{MaxFileSize: max})
	if err != nil {
		return nil, err
	}
	return root.ReadFile(filepath.Base(abs), max)
}

func isNotExist(err error) bool {
	if e, ok := cerr.As(err); ok {
		switch e.Code() {
		case cerr.EScan001, cerr.EScan007:
			return true
		}
	}
	return os.IsNotExist(err)
}

func displayPath(p string) string {
	if p == "" {
		return ""
	}
	if rel, err := filepath.Rel(mustGetwd(), p); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(p)
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return itoa(n) + " B"
	}
	units := []string{"KiB", "MiB", "GiB"}
	v := float64(n)
	for i, u := range units {
		v /= unit
		if v < unit || i == len(units)-1 {
			return trimFloat(v) + " " + u
		}
	}
	return itoa(n) + " B"
}

func trimFloat(v float64) string {
	whole := int64(v)
	frac := int64((v - float64(whole)) * 10)
	if frac == 0 {
		return itoa(whole)
	}
	return itoa(whole) + "." + itoa(frac)
}
