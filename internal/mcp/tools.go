package mcp

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/obligations"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/report"
	"github.com/clearance-dev/clearance/internal/safejson"
	"github.com/clearance-dev/clearance/internal/scanner"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// The tool names. They are constants because the schemas, the dispatcher and
// the tests all refer to them, and a tool whose name is spelled differently in
// two of those three places is a tool that answers method-not-found to a client
// following the documentation.
const (
	ToolCheck         = "clearance_check"
	ToolExplain       = "clearance_explain"
	ToolCorpusInfo    = "clearance_corpus_info"
	ToolLicenceLookup = "clearance_license_lookup"
)

// toolSchemas is what `tools/list` returns.
//
// # WHY THE DESCRIPTIONS ARE LONGER THAN USUAL
//
// Because the reader is a model deciding whether to call the tool, and a model
// that does not understand the difference between "this project has a GPL
// dependency" and "you may not ship this" will misuse a licence checker in the
// direction that costs money. The description of `clearance_check` therefore
// states the output shape — a verdict, one of four values — rather than saying
// "scans a project". A tool description is documentation that is actually read.
//
// The schemas are hand-written rather than reflected from the Go types. Two
// reasons: the Go types carry fields the protocol should not expose, and a
// reflected schema changes shape whenever someone renames a field, which is a
// protocol break that would look like a refactor.
func toolSchemas() []map[string]any {
	return []map[string]any{
		{
			"name": ToolCheck,
			"description": "Produce a licence verdict for a project. Returns one of SHIP, " +
				"SHIP CONDITIONAL, DO NOT SHIP or UNDETERMINED, with the findings behind it. " +
				"This is a decision, not a report: DO NOT SHIP means a blocker with a cited " +
				"clause. Read-only.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Project directory, relative to the workspace root. Defaults to the root itself.",
					},
					"intent": map[string]any{
						"type":        "object",
						"description": "The declared intent, overriding the project's clearance.config.yml. Intent is declared, never inferred: a project with no config and no intent is UNDETERMINED, not a pass.",
					},
				},
				"additionalProperties": false,
			},
		},
		{
			"name": ToolExplain,
			"description": "Return the primary-source clause behind a finding, by citation id. " +
				"Use this when a human asks why a verdict came out the way it did. Read-only.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"citation_id": map[string]any{
						"type":        "string",
						"description": "A citation id as it appears on a finding, e.g. 'agpl-3.0-only#13'.",
					},
				},
				"required":             []string{"citation_id"},
				"additionalProperties": false,
			},
		},
		{
			"name": ToolCorpusInfo,
			"description": "Report the corpus version, whether its signature verified, and its " +
				"counts. Use this to check that the knowledge behind a verdict is current and signed. Read-only.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"additionalProperties": false,
			},
		},
		{
			"name": ToolLicenceLookup,
			"description": "Return one licence's obligations and traps from the corpus, by SPDX " +
				"identifier. This describes the LICENCE, not a project. Read-only.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"spdx_id": map[string]any{
						"type":        "string",
						"description": "An SPDX identifier, e.g. 'AGPL-3.0-only'.",
					},
				},
				"required":             []string{"spdx_id"},
				"additionalProperties": false,
			},
		},
	}
}

// callTool dispatches `tools/call`.
//
// The params were already decoded with safejson when the frame was parsed, so
// there is nothing left to validate here except the shape the specification
// requires: an object with a `name`, and an optional `arguments` object.
func (s *Server) callTool(req request) (any, *rpcError, error) {
	if req.ParamsInvalid {
		return nil, invalidParams("tools/call requires an object as 'params', not an array"), nil
	}

	name := req.Params.String("name")
	if name == "" {
		return nil, invalidParams("tools/call requires a 'name'"), nil
	}

	// `arguments` is optional: three of the four tools take none, and the
	// protocol lets a client omit it entirely. An absent one and an empty one
	// mean the same thing, and Object() returns the zero value for both.
	args := req.Params.Object("arguments")

	switch name {
	case ToolCheck:
		return s.toolCheck(args)
	case ToolExplain:
		return s.toolExplain(args)
	case ToolCorpusInfo:
		return s.toolCorpusInfo()
	case ToolLicenceLookup:
		return s.toolLicenceLookup(args)
	}
	return nil, methodNotFound(name), nil
}

// toolCheck runs the whole pipeline and returns the canonical verdict JSON.
//
// # THE ONE PLACE A FIXTURE COULD LIE
//
// Every other tool reads the corpus. This one reads the project, and it is the
// only tool whose output can say DO NOT SHIP. So it is also the only tool where
// a wrong answer is expensive, and the composition below mirrors
// cli.runCheckWith step for step for that reason: intent, corpus, scan,
// evaluate, fold, and nothing in between. A second pipeline that diverged from
// the CLI's would be a second product.
func (s *Server) toolCheck(args safejson.Object) (any, *rpcError, error) {
	projectDir, err := resolveInRoot(s.root, args.String("path"))
	if err != nil {
		// E-MCP-001 ends the session. See the package comment.
		//
		// The error is narrowed with cerr.As rather than a bare type
		// assertion: err.(*cerr.Error) panics on anything the error chain has
		// wrapped, and a panic inside a tool call kills the whole session
		// instead of ending it cleanly. This is the same narrowing every other
		// tool below uses; this one predated it.
		e, ok := cerr.As(err)
		if !ok {
			return nil, &rpcError{Code: rpcInternalError, Message: err.Error()}, err
		}
		return nil, clearanceError(e), err
	}

	cfg, rpcErr := s.intentFor(projectDir, args)
	if rpcErr != nil {
		return nil, rpcErr, nil
	}

	g, err := scanner.Scan(projectDir, scanner.Options{Intent: cfg.Intent})
	if err != nil {
		if e, ok := cerr.As(err); ok {
			return nil, clearanceError(e), nil
		}
		return nil, &rpcError{Code: rpcInternalError, Message: err.Error()}, nil
	}

	eval, err := policy.Evaluate(g, s.corpus, cfg.Intent, policy.Options{Today: s.opts.Today})
	if err != nil {
		if e, ok := cerr.As(err); ok {
			return nil, clearanceError(e), nil
		}
		return nil, &rpcError{Code: rpcInternalError, Message: err.Error()}, nil
	}

	v := verdict.Fold(verdict.Input{
		Findings:     eval.Findings,
		Undetermined: eval.Undetermined,
	})
	if err := v.TotalityCheck(); err != nil {
		if e, ok := cerr.As(err); ok {
			return nil, clearanceError(e), nil
		}
		return nil, &rpcError{Code: rpcInternalError, Message: err.Error()}, nil
	}

	v.Project = projectLabel(cfg.Intent, projectDir)
	v.Summary.Dependencies = len(g.Dependencies)
	v.Summary.WeightFiles = g.CountWeights()
	v.Summary.UpstreamCLIs = g.CountUpstreamCLIs()

	// The same injected metadata the CLI writes, minus the duration and the
	// timestamp — a server answers the same question with the same answer, and
	// a wall-clock field in the response would make two identical calls look
	// different (INV-6). The corpus version and the intent hash are kept
	// because they are what makes a verdict reproducible.
	v.Meta = verdict.Meta{
		ToolVersion:     s.opts.Version,
		CorpusVersion:   s.corpus.Version,
		CorpusSigned:    s.corpus.Signed,
		IntentHash:      cfg.Intent.Hash(),
		ConfigPath:      s.configPathFor(cfg),
		BuildCommit:     s.opts.Commit,
		BuildProvenance: s.opts.Provenance,
	}

	var buf bytes.Buffer
	if err := report.Write(&buf, v, report.FormatJSON, report.Options{}); err != nil {
		if e, ok := cerr.As(err); ok {
			return nil, clearanceError(e), nil
		}
		return nil, &rpcError{Code: rpcInternalError, Message: err.Error()}, nil
	}

	return textResult(buf.String()), nil, nil
}

// intentFor builds the intent for a project.
//
// # WHY AN INLINE INTENT IS DECODED HERE RATHER THAN WRITTEN TO DISK
//
// The obvious implementation of "check with this intent" is to write a
// temporary clearance.config.yml and let config.Load read it. That would break
// the capability boundary in the one way that matters: the server would write,
// and C9 says it never writes. It would also make two concurrent calls race on
// one filename.
//
// So the client's object is rendered as a YAML document in memory (see yaml.go
// for why that is a rendering rather than a re-encode) and handed to
// config.FromDocument, which runs the identical decode and validation a file on
// disk gets. A project with no config and no inline intent is E-CFG-001, which
// is the product's central refusal: intent is declared, never inferred.
//
// The `source` passed to FromDocument is the project directory. That is not
// cosmetic: decodeIntent derives a default project name from it when the client
// omits `project.name`, and a directory name is a far better label than a
// placeholder would be.
func (s *Server) intentFor(projectDir string, args safejson.Object) (*config.Loaded, *rpcError) {
	raw, hasIntent := args.Get("intent")
	if !hasIntent || raw == nil {
		loaded, err := config.Load(config.Options{
			WorkDir: projectDir,
			// "-" disables the user-level config, exactly as the guard tests
			// do: a server whose answer depended on the operator's own
			// ~/.config would answer differently on two machines running the
			// same project.
			UserConfigPath: "-",
		})
		if err != nil {
			if e, ok := cerr.As(err); ok {
				return nil, clearanceError(e)
			}
			return nil, &rpcError{Code: rpcInternalError, Message: err.Error()}
		}
		return loaded, nil
	}

	blob := toYAML(raw)
	intent, err := config.FromDocument(blob, projectDir)
	if err != nil {
		// FromDocument runs the same validation a config file gets, so its
		// errors are the config errors a user already knows — E-CFG-002 for a
		// missing required field, E-CFG-008 for a future schema, E-PARSE-003
		// for an unknown key. Passing them through unchanged is the point:
		// an agent that sends a bad intent gets the same sentence a person
		// editing clearance.config.yml would get.
		if e, ok := cerr.As(err); ok {
			return nil, clearanceError(e)
		}
		return nil, invalidParams("intent is invalid: %v", err)
	}
	return &config.Loaded{Intent: intent, Sources: []string{"(mcp:inline)"}}, nil
}

// toolExplain returns the clause behind a citation id.
//
// # WHY THE ID IS LOOKED UP BY ITS RENDERED FORM
//
// `cite.Index` is keyed on the id a finding PRINTS — `url#section` — rather
// than on an opaque handle. That is what lets a human read a finding, copy the
// citation id out of the terminal, and ask this tool about it. A handle would
// have been cheaper to implement and useless to the person who is actually
// asking the question.
func (s *Server) toolExplain(args safejson.Object) (any, *rpcError, error) {
	id := strings.TrimSpace(args.String("citation_id"))
	if id == "" {
		return nil, invalidParams("citation_id is required"), nil
	}

	// A miss is not a protocol error. "I have no clause with that id" is a
	// successful answer to a question, and returning it as a failure would make
	// an agent retry a lookup whose answer cannot change.
	cit, ok := s.corpus.Citations.Get(id)
	if !ok {
		return textResult("No citation '" + id + "' in corpus v" + s.corpus.Version +
			".\nThis is not a judgement about the licence: it means no entry in this " +
			"corpus cites that clause."), nil, nil
	}

	var b strings.Builder
	b.WriteString("Citation: " + cit.URL + "#" + cit.Section + "\n")
	b.WriteString("URL:      " + cit.URL + "\n")
	b.WriteString("Section:  " + cit.Section + "\n")
	if cit.ExcerptKind != "" {
		// The kind is printed rather than assumed, because the renderer's rule
		// is that only a verbatim excerpt may appear in quotation marks. An
		// agent relaying this to a human needs the same distinction.
		b.WriteString("Excerpt:  (" + string(cit.ExcerptKind) + ")\n")
	}
	if strings.TrimSpace(cit.Excerpt) != "" {
		if cit.ExcerptKind.IsVerbatim() {
			b.WriteString("\n\"" + cit.Excerpt + "\"\n")
		} else {
			b.WriteString("\n" + cit.Excerpt + "\n")
		}
	}
	return textResult(b.String()), nil, nil
}

// toolCorpusInfo reports the corpus's identity and counts.
func (s *Server) toolCorpusInfo() (any, *rpcError, error) {
	st := s.corpus.Stats()
	status := "unsigned"
	if s.corpus.Signed {
		status = "signature verified"
	}
	var b strings.Builder
	b.WriteString("Corpus " + s.corpus.Version + " (" + status + ")\n")
	b.WriteString("Built:        " + s.corpus.BuiltAt + "\n")
	b.WriteString("Licences:     " + itoa(st.Licences) + "\n")
	b.WriteString("Obligations:  " + itoa(st.Obligations) + "\n")
	b.WriteString("Traps:        " + itoa(st.Traps) + "\n")
	b.WriteString("Platforms:    " + itoa(st.ToS) + "\n")
	b.WriteString("Territories:  " + itoa(st.Territories) + "\n")
	b.WriteString("Citations:    " + itoa(st.Citations) + "\n")
	b.WriteString("Today:        " + s.opts.Today + "\n")
	return textResult(b.String()), nil, nil
}

// toolLicenceLookup returns one licence entry's obligations and traps.
//
// # WHY IT RETURNS THE OBLIGATIONS AND NOT A VERDICT
//
// Because there is no project. This tool answers "what does AGPL-3.0-only
// require?", and the answer does not depend on who is asking. Returning a
// verdict here would be inventing an intent, which is the one thing this
// product refuses to do.
func (s *Server) toolLicenceLookup(args safejson.Object) (any, *rpcError, error) {
	spdx := strings.TrimSpace(args.String("spdx_id"))
	if spdx == "" {
		return nil, invalidParams("spdx_id is required"), nil
	}

	entry, ok := s.corpus.Resolve(spdx)
	if !ok {
		return textResult("No corpus entry for '" + spdx + "'. This is not a pass: " +
			"a dependency under this licence would be UNDETERMINED."), nil, nil
	}

	var b strings.Builder
	b.WriteString(entry.Name + " (" + entry.SPDXID + ")\n")
	b.WriteString("Family: " + entry.Family + "\n")
	b.WriteString("Confidence: " + entry.Confidence + "\n")
	if entry.LastVerified != "" {
		b.WriteString("Last verified: " + entry.LastVerified + "\n")
	}

	// Obligations go through the vocabulary, so the listing names a kind only
	// when it is one the product recognises. An entry that somehow carried an
	// unknown kind would be reported as such rather than printed as though it
	// were a kind — the same discipline the renderer applies.
	b.WriteString("\nObligations:\n")
	if len(entry.Obligations) == 0 {
		b.WriteString("  (none recorded)\n")
	}
	for i := range entry.Obligations {
		ob := &entry.Obligations[i]
		b.WriteString("  - " + ob.ID + " [" + kindLabel(ob.Kind) + ", " + ob.Severity +
			", " + ob.Confidence + "]\n")
		b.WriteString("    " + strings.TrimSpace(ob.Message) + "\n")
		if ob.Fix != nil {
			b.WriteString("    Fix (" + ob.Fix.Action + "): " + ob.Fix.Suggestion + "\n")
		}
	}

	b.WriteString("\nTraps:\n")
	if len(entry.Traps) == 0 {
		b.WriteString("  (none recorded)\n")
	}
	for i := range entry.Traps {
		tr := &entry.Traps[i]
		b.WriteString("  - " + tr.ID + ": " + tr.Title + " [" + tr.Severity + "]\n")
		b.WriteString("    " + strings.TrimSpace(tr.Summary) + "\n")
	}

	return textResult(b.String()), nil, nil
}

// configPathFor renders the config sources the way the CLI does: relative to
// the scanned root, never absolute.
//
// # WHY THIS IS NOT COSMETIC
//
// The CLI gets the relative form for free, because the user types a relative
// path and it is passed straight through to config.Load. The server is handed
// an ABSOLUTE root — resolveInRoot returns one, because safefs.Rel needs
// something to compare — so config.Load records absolute paths and the verdict
// would carry `C:\Users\<name>\...` into a document that gets logged by an
// agent, pasted into a ticket and, in the hosted tier, uploaded.
//
// That is the leak the privacy spine exists to prevent, and
// TestNoAbsolutePathsInOutput is the guard that catches it. This function is why
// that guard can stay green with an MCP server in the tree: the server puts the
// same relative form in the verdict that the CLI does, so a verdict is a
// function of the project rather than of the machine.
//
// A source that is not under the root is left as it is rather than mangled. It
// can only be the user-level config, and the CLI's own comment on
// resolveCorpusDir explains why that is a different thing.
func (s *Server) configPathFor(loaded *config.Loaded) string {
	if loaded == nil || len(loaded.Sources) == 0 {
		return ""
	}
	parts := make([]string, 0, len(loaded.Sources))
	for _, src := range loaded.Sources {
		if rel, ok := s.root.Rel(src); ok {
			parts = append(parts, filepath.ToSlash(rel))
			continue
		}
		parts = append(parts, filepath.ToSlash(src))
	}
	return strings.Join(parts, ", ")
}

// textResult wraps a string in the content envelope every MCP tool result uses.
//
// `isError` is deliberately absent. It is set only when a tool ran and failed;
// a tool that answers "I have no entry for that licence" succeeded at answering.
// Conflating the two would make an agent retry a question whose answer will
// never change.
func textResult(text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
	}
}

// kindLabel names an obligation kind, going through the closed vocabulary so an
// unrecognised value is visible rather than printed as though it were a kind.
func kindLabel(kind string) string {
	if k, ok := obligations.KindOf(kind); ok {
		return string(k)
	}
	return "UNKNOWN(" + strings.TrimSpace(kind) + ")"
}

// projectLabel mirrors cli.projectName: the declared name, or the directory.
//
// It prefers the declared name because a verdict is a document that gets pasted
// into a ticket, and "acme-api" is a better label there than "acme-api-3f2a1b".
// The fallback is the base of the directory rather than the whole path, because
// the whole path leaks the machine's layout.
func projectLabel(in *config.Intent, dir string) string {
	if in != nil && strings.TrimSpace(in.Project.Name) != "" {
		return in.Project.Name
	}
	return baseName(dir)
}

// baseName is filepath.Base without the import, kept here so this file's import
// block stays a list of the packages the protocol actually needs.
func baseName(p string) string {
	p = strings.TrimRight(strings.ReplaceAll(p, "\\", "/"), "/")
	if p == "" {
		return "project"
	}
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	if p == "" {
		return "project"
	}
	return p
}

// itoa avoids pulling strconv in for three call sites.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
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
