// Package scanner reads a project tree and produces a dependency graph.
//
// LAYER: L1 Discovery. It may import L0 only. Every filesystem read in the
// program happens here or in internal/safefs, and it all goes through safefs so
// that the root boundary is enforced in one place. It makes no network calls,
// executes nothing and installs nothing (INV-3, INV-4).
//
// # WHAT IT DOES NOT DO
//
// It does not decide anything. It reports facts: this dependency exists, here is
// the licence text found for it, here is where it was seen. Whether a licence is
// acceptable is the corpus's judgement and the policy engine's arithmetic.
// Keeping that line sharp is what makes the decision layer testable without a
// filesystem — and it is why a dependency whose licence could not be resolved is
// returned with Licence.Resolved=false rather than being converted into an
// Undetermined here. The policy engine owns that conversion, and it already
// does it (internal/policy/engine.go, "licence_unresolved").
package scanner

import (
	"path"
	"strings"
	"time"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/parsers"
	"github.com/clearance-dev/clearance/internal/safefs"
)

// Options configures a scan.
type Options struct {
	// Limits bounds the walk. The zero value is safe: safefs fills in the
	// documented defaults rather than walking without a bound.
	Limits safefs.Limits

	// Intent supplies the ignore rules. It is optional: a scan with no config
	// is a legitimate scan, it simply cannot skip anything.
	Intent *config.Intent

	// MaxLicenceFileSize bounds a licence file read for recognition. A real
	// licence is under 40 KiB, so the default is generous.
	MaxLicenceFileSize int64
}

func (o Options) licenceLimit() int64 {
	if o.MaxLicenceFileSize <= 0 {
		return 256 << 10
	}
	return o.MaxLicenceFileSize
}

// staleLockfileWindow is the grace period E-SCAN-015 applies before it calls a
// lockfile stale.
//
// # WHY A WINDOW, AND WHY ONE MINUTE
//
// The rule compares two file modification times, which is the weakest evidence
// this scanner uses, and a bare comparison produces a claim the tool cannot
// stand behind. `git clone` and `git checkout` write every file at checkout
// time, so any project whose manifest happens to be written after its lockfile
// — a matter of milliseconds, and of the order git happens to use — would be
// told its lockfile is stale on a pristine tree. That is false, and it fires in
// CI, where a false warning costs a reader's attention on every run. It was
// measured rather than assumed: three of this repository's own fixtures have a
// package.json exactly 1 ms newer than their package-lock.json as checked out,
// which is what turned this from a hypothesis into a defect report.
//
// A window is what makes the sentence true rather than merely arithmetically
// true. Files written by one checkout land within milliseconds of each other; a
// package manager writes a lockfile seconds after touching the manifest; only a
// human edit separates the two by minutes or more. One minute is therefore
// above every machine-written spread this scanner is likely to meet and below
// the shortest human edit worth reporting.
//
// The cost is bounded and stated: a manifest edited and scanned within the same
// minute is not reported. That finding is a WARN whose only consequence is that
// the reader re-resolves, so a missing one costs a re-resolve while a false one
// costs the reader's trust in every other warning the tool prints.
const staleLockfileWindow = time.Minute

// Scan walks a directory and returns its dependency graph.
//
// A graph is returned whenever a graph could be produced, even a partial one,
// because a partial graph with visible warnings is more useful than no answer.
// An error is returned only when no graph can be produced at all: the path is
// not a directory, it is unreadable, or it contains no dependency manifest.
func Scan(dir string, opts Options) (*graph.Graph, error) {
	root, err := safefs.New(dir, opts.Limits)
	if err != nil {
		return nil, err
	}

	entries, skips, err := root.Walk()
	if err != nil {
		return nil, err
	}

	g := &graph.Graph{Root: root.Abs()}

	// Every refusal the walk made becomes a visible warning. An incomplete scan
	// is trustworthy only when it is *visibly* incomplete.
	for _, s := range skips {
		if s.Err == nil {
			continue
		}
		g.Warnings = append(g.Warnings, graph.Warning{
			Code:    string(s.Code()),
			Message: s.Message(),
		})
	}

	entries = applyIgnore(entries, opts.Intent, g)

	projects := findProjects(entries)

	sc := &scan{root: root, g: g, opts: opts, projects: projects}
	for _, p := range projects {
		sc.scanProject(p)
	}
	sc.attachVendoredLicences(entries)

	// The detectors for things that are not packages. They run on the walk
	// entries, not on projects, because a weight file, an upstream-CLI usage or
	// a brand asset is a unit carrying terms whether or not a package manifest
	// happens to sit beside it.
	sc.detectWeights(entries)
	sc.detectUpstream(entries)
	sc.detectAssets(entries)

	// The "no manifest" refusal moved below the detectors, and it now asks a
	// broader question. A directory holding model weights and nothing else is a
	// legitimate thing to scan — it is the `weights-no-licence` fixture, and a
	// user pointing the tool at a downloaded model expects an answer about the
	// weights, not "no dependency manifest found". The refusal is still a
	// refusal; it just fires only when the tree held nothing at all to judge.
	if len(projects) == 0 && len(g.Dependencies) == 0 {
		// The path the user typed, not the absolute path: an error message that
		// repeats back a normalised path is harder to act on than the one they
		// wrote.
		return nil, cerr.New(cerr.EScan009, dir)
	}

	g.Stats = sc.stats()
	g.Normalise()

	if err := g.Validate(); err != nil {
		// Validate failing is a scanner bug, never a user error, so it is an
		// internal error and never a degraded result. Reporting it as a
		// warning would let a structurally broken graph reach the verdict.
		return nil, cerr.New(cerr.EInt001).WithDetail("graph", err.Error())
	}
	return g, nil
}

// scan carries the state of one scan.
type scan struct {
	root     *safefs.Root
	g        *graph.Graph
	opts     Options
	projects []project
}

// scanProject reads one (directory, ecosystem) pair.
//
// It never returns an error for a parse failure. A file that cannot be parsed is
// a DEGRADE — the graph gets weaker and says so — not a reason to abandon a scan
// that may have twenty other ecosystems to read.
func (s *scan) scanProject(p project) {
	// Lockfiles the parser recognises and refuses to parse. Reported, never
	// ignored: silently falling back to the manifest would make a weaker scan
	// look like a normal one, and the range caveat is the whole point.
	for _, rel := range p.UnsupportedLockfiles {
		s.warn(cerr.EParse001, rel,
			"Cannot parse '"+rel+"': this lockfile format is not supported. Falling back to the manifest.")
	}

	manifestRes, manifestOK := s.tryParse(p, p.Manifest, false)
	lockRes, lockOK := s.tryParse(p, p.Lockfile, true)

	// Direct-ness always comes from the manifest, even when the lockfile
	// supplies the versions: a lockfile records the whole transitive tree and
	// cannot say which entries the developer actually asked for.
	direct := map[string]bool{}
	for _, d := range manifestRes.Declared {
		if d.Direct {
			direct[d.Name] = true
		}
	}

	if p.Dir == "." && s.g.ProjectLicence == "" && manifestRes.OwnLicence != "" {
		s.g.ProjectLicence = manifestRes.OwnLicence
	}

	// A lockfile resolves; a manifest only declares. So the lockfile wins when
	// it parsed, and the manifest is the fallback. This is the rule the whole
	// package exists to implement.
	chosen := manifestRes.Declared
	fromLock := false
	if lockOK && len(lockRes.Declared) > 0 {
		chosen = lockRes.Declared
		fromLock = true
	} else if p.Lockfile != "" && !lockOK {
		// The fallback already produced a warning; this one records that the
		// graph is now range-based rather than resolution-based, so a reader of
		// the JSON can see why versions look like ranges.
		s.g.Warnings = append(s.g.Warnings, graph.Warning{
			Code:    string(cerr.EParse001),
			Message: "Using '" + p.Manifest + "' instead of '" + p.Lockfile + "': versions are requirements, not resolutions.",
		})
	}

	// A manifest edited after its lockfile was generated means the lockfile is
	// stale, and we are about to trust it. That is worth saying out loud — but
	// only when the difference is bigger than a checkout, which is what
	// staleLockfileWindow is for. Read the comment on that constant before
	// changing this comparison: the naive form of it is a false alarm on a
	// pristine clone, and the fixtures caught it.
	if manifestOK && lockOK && p.Manifest != "" && p.Lockfile != "" {
		mt, lt := s.modTime(p.Manifest), s.modTime(p.Lockfile)
		if !mt.IsZero() && !lt.IsZero() && mt.Sub(lt) > staleLockfileWindow {
			s.warn(cerr.EScan015, p.Lockfile,
				"'"+p.Manifest+"' is newer than '"+p.Lockfile+"'. Using the lockfile, which may be stale.")
		}
	}

	for _, d := range chosen {
		s.addDeclaration(d, p, direct, fromLock)
	}
}

// tryParse reads and parses one file. A failure is reported and swallowed.
func (s *scan) tryParse(p project, rel string, lock bool) (parsers.Result, bool) {
	if rel == "" {
		return parsers.Result{}, false
	}
	data, err := s.root.ReadFile(rel, s.root.Limits().MaxFileSize)
	if err != nil {
		s.warnErr(err, rel)
		return parsers.Result{}, false
	}

	var res parsers.Result
	if lock {
		res, err = p.Parser.ParseLockfile(rel, data)
	} else {
		res, err = p.Parser.ParseManifest(rel, data)
	}
	if err != nil {
		s.warnErr(err, rel)
		return parsers.Result{}, false
	}
	// A parser can succeed while telling us it skipped something it could not
	// follow. That warning is part of the result, so it is never dropped.
	if res.Warning != nil {
		s.g.Warnings = append(s.g.Warnings, graph.Warning{
			Code:    string(res.Warning.Code()),
			Message: res.Warning.Message(),
			Path:    rel,
		})
	}
	return res, true
}

// addDeclaration turns one parsed declaration into a graph dependency.
func (s *scan) addDeclaration(d parsers.Declared, p project, direct map[string]bool, fromLock bool) {
	if d.Name == "" {
		// A declaration with no name cannot be reported, fixed or cited, so it
		// is dropped rather than added anonymously.
		return
	}

	source := "manifest"
	if fromLock {
		source = "lockfile"
	}

	dep := graph.Dependency{
		ID:        graph.PackageID(d.Ecosystem, d.Name, d.Version),
		Kind:      graph.KindPackage,
		Name:      d.Name,
		Version:   d.Version,
		Ecosystem: d.Ecosystem,
		Direct:    direct[d.Name] || d.Direct,
		Scope:     p.Dir,
		Evidence:  []graph.Evidence{{Path: d.SourcePath, LineStart: d.Line, LineEnd: d.Line}},
		Licence:   LicenceRefFromString(d.LicenceRaw, source),
	}

	var meta map[string]string
	setMeta(&meta, "dev", d.Dev)
	setMeta(&meta, "optional", d.Optional)
	setMeta(&meta, "version_is_requirement", d.IsRange)

	if d.Local {
		if d.PathDep == "" {
			// A workspace member or the project itself. The tree scan already
			// covers its files, so counting it would double-count the project's
			// own licences — and, worse, let the project block itself on its own
			// licence.
			return
		}
		if s.insideRoot(path.Join(p.Dir, d.PathDep)) {
			// A path dependency inside the root is part of the project, for the
			// same reason.
			return
		}
		// Outside the root. INV-4 forbids reading it, so its licence is
		// genuinely unknown. It stays in the graph with Resolved=false, and the
		// policy engine turns that into UNDETERMINED — which is the honest
		// answer, not a gap.
		setMeta(&meta, "path_dependency", true)
		setMetaValue(&meta, "path", d.PathDep)
		setMeta(&meta, "outside_root", true)
		dep.Metadata = meta
		s.g.Add(dep)
		return
	}

	dep.Metadata = meta
	s.g.Add(dep)
}

// insideRoot reports whether a project-relative path stays inside the root.
// It is safefs' containment check, used here as a question rather than a guard:
// a path dependency either resolves inside the root or it does not.
func (s *scan) insideRoot(rel string) bool {
	_, err := s.root.Resolve(rel)
	return err == nil
}

func (s *scan) modTime(rel string) time.Time {
	if rel == "" {
		return time.Time{}
	}
	st, err := s.root.Stat(rel)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

func (s *scan) stats() graph.Stats {
	filesSeen, filesSkipped, bytesRead, dirsVisited, maxDepth, truncated := s.root.Counters()
	return graph.Stats{
		FilesSeen:    filesSeen,
		FilesSkipped: filesSkipped,
		BytesRead:    bytesRead,
		DirsVisited:  dirsVisited,
		MaxDepthSeen: maxDepth,
		Truncated:    truncated,
	}
}

// ── warnings ─────────────────────────────────────────────────────────────────

func (s *scan) warn(code cerr.Code, relPath, message string) {
	s.g.Warnings = append(s.g.Warnings, graph.Warning{
		Code:    string(code),
		Message: message,
		Path:    relPath,
	})
}

// warnErr records a typed error as a warning, preserving its code and message
// so that the user sees the same text the taxonomy defines for it.
func (s *scan) warnErr(err error, relPath string) {
	if e, ok := cerr.As(err); ok {
		s.g.Warnings = append(s.g.Warnings, graph.Warning{
			Code:    string(e.Code()),
			Message: e.Message(),
			Path:    relPath,
		})
		return
	}
	// An untyped error should be impossible (INV-5), but if one reaches here it
	// is reported as an internal problem rather than silently dropped.
	s.g.Warnings = append(s.g.Warnings, graph.Warning{
		Code:    string(cerr.EInt002),
		Message: "Internal error: recovered from a panic in scanner.",
		Path:    relPath,
	})
}

// setMeta records a metadata key only when it is true, so that an absent key
// means "false" rather than "unknown" and the map stays empty for the common
// dependency that has nothing extra to say.
func setMeta(m *map[string]string, key string, on bool) {
	if !on {
		return
	}
	if *m == nil {
		*m = map[string]string{}
	}
	(*m)[key] = "true"
}

// setMetaValue records a metadata key with a value. An empty value is not
// recorded, for the same reason setMeta skips false: an absent key is the
// single representation of "nothing to say".
func setMetaValue(m *map[string]string, key, value string) {
	if value == "" {
		return
	}
	if *m == nil {
		*m = map[string]string{}
	}
	(*m)[key] = value
}

// LicenceRefFromString interprets a licence string found in a manifest or
// lockfile.
//
// It handles the two shapes that occur in practice: a single SPDX identifier,
// and an SPDX expression such as "MIT OR Apache-2.0". An expression is recorded
// faithfully with Expression=true and its atoms in Metadata, and it is left for
// the policy layer to interpret — because whether "OR" permits choosing the
// permissive branch is a question about obligations, and the scanner does not
// hold opinions about obligations.
//
// A string that is neither is returned with Resolved=false and its raw text
// intact. That is deliberate: "SEE LICENSE IN COPYING" is a real and common
// value, and inventing an identifier for it would attach the wrong obligations
// to the dependency.
func LicenceRefFromString(raw, source string) graph.LicenceRef {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return graph.LicenceRef{Source: source}
	}

	if isExpression(trimmed) {
		atoms, ok := expressionAtoms(trimmed)
		if ok {
			return graph.LicenceRef{
				SPDX:       trimmed,
				Raw:        trimmed,
				Source:     source,
				Expression: true,
				Resolved:   true,
				Confidence: "medium",
			}
		}
		_ = atoms
		return graph.LicenceRef{Raw: trimmed, Source: source, Confidence: "low"}
	}

	if norm := config.NormaliseSPDX(trimmed); config.ValidSPDX(norm) {
		return graph.LicenceRef{
			SPDX:       norm,
			Raw:        trimmed,
			Source:     source,
			Resolved:   true,
			Confidence: "high",
		}
	}
	return graph.LicenceRef{Raw: trimmed, Source: source, Confidence: "low"}
}

// isExpression reports whether a licence string uses SPDX expression operators.
func isExpression(s string) bool {
	up := strings.ToUpper(s)
	return strings.Contains(up, " OR ") || strings.Contains(up, " AND ") || strings.Contains(up, " WITH ")
}

// expressionAtoms splits an SPDX expression into its identifiers and reports
// whether every atom is a licence this build knows about. An expression built
// from unknown identifiers is not a resolution, and saying so is the point.
func expressionAtoms(s string) ([]string, bool) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '(' || r == ')' || r == '\t'
	})
	var atoms []string
	for _, f := range fields {
		switch strings.ToUpper(f) {
		case "OR", "AND", "WITH":
			continue
		}
		atoms = append(atoms, f)
	}
	if len(atoms) == 0 {
		return nil, false
	}
	for _, a := range atoms {
		if !config.ValidSPDX(a) {
			return atoms, false
		}
	}
	return atoms, true
}
