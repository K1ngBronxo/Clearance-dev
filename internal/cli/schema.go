// `--json-schema` and the two flag-value lists.
//
// # WHY THE SCHEMA IS EMBEDDED RATHER THAN GENERATED
//
// The frozen contract says the schema is
// "published at clearance.dev/schema/v1/verdict.json and embedded in the binary
// (`--json-schema`)". The second half is the part that matters to a CI author:
// the schema a consumer validates against must be the schema *this binary*
// produced, and fetching it from a website couples the check to the network and
// to whatever the site is serving today.
//
// So the schema lives here, as a literal, and a test asserts it agrees with the
// structs it describes — TestJSONSchemaMatchesTheContract walks the verdict
// type and fails if a field is missing from the schema or the schema names a
// field the type does not have. Without that test this file would be a second
// description of the output, and the two would drift.
//
// # WHY IT IS NOT A `report` FUNCTION
//
// `report` is L4 and renders a verdict. This renders a *description* of a
// verdict, which is a different kind of thing, and it is the interface layer's
// job to answer a question about the binary rather than about a project.
package cli

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/report"
)

// formatList renders the accepted --format values from the renderer's own list,
// so the help text cannot name a format the binary rejects.
func formatList() string {
	names := make([]string, 0, len(report.Formats()))
	for _, f := range report.Formats() {
		names = append(names, string(f))
	}
	return strings.Join(names, ", ")
}

// sbomList renders the accepted --sbom values from the exporter's own list.
func sbomList() string {
	names := make([]string, 0, len(report.SBOMFormats()))
	for _, f := range report.SBOMFormats() {
		names = append(names, string(f))
	}
	return strings.Join(names, ", ")
}

// writeJSONSchema prints the embedded schema and exits.
//
// It never scans, so it never produces a verdict, so it never returns a verdict
// exit code: a caller asking for the schema gets 0 or a configuration error.
func writeJSONSchema(stdout, stderr io.Writer) int {
	b, err := json.MarshalIndent(verdictSchema(), "", "  ")
	if err != nil {
		// Unreachable for a literal map, but an error path that returns 0
		// would make `clearance check --json-schema | jq` succeed on empty
		// input, which is the silent-success family this codebase documents.
		return fail(stderr, cerr.Wrap(cerr.ERender002, err))
	}
	if _, err := stdout.Write(append(b, '\n')); err != nil {
		return fail(stderr, cerr.Wrap(cerr.ERender001, err, "stdout"))
	}
	return cerr.ExitOK
}

// verdictSchema is the JSON Schema for the verdict document.
//
// It is JSON Schema draft 2020-12. `additionalProperties` is false throughout:
// the contract says a consumer must be able to reject a verdict it does not
// understand, and a schema that tolerated unknown fields would accept a
// document from a future version whose extra fields changed the meaning of the
// ones it does know.
//
// It is deliberately not exhaustive about *values* — `severity` is an enum
// because the vocabulary is frozen, but `kind` is a string because the corpus
// adds kinds without a release. The schema pins the shape; the corpus pins the
// vocabulary.
func verdictSchema() map[string]any {
	str := func() map[string]any { return map[string]any{"type": "string"} }
	arr := func(items map[string]any) map[string]any {
		return map[string]any{"type": "array", "items": items}
	}

	citation := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"url", "section"},
		"properties": map[string]any{
			"url":          str(),
			"section":      str(),
			"excerpt":      str(),
			"excerpt_kind": map[string]any{"type": "string", "enum": []string{"verbatim", "unverified"}},
			"retrieved_at": str(),
		},
	}

	evidence := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"path"},
		"properties": map[string]any{
			"path":       str(),
			"line_start": map[string]any{"type": "integer"},
			"line_end":   map[string]any{"type": "integer"},
			"excerpt":    str(),
		},
	}

	fix := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"action", "suggestion"},
		"properties": map[string]any{
			"action":      str(),
			"suggestion":  str(),
			"alternative": str(),
			"confidence":  str(),
		},
	}

	finding := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required": []string{
			"id", "dependency_id", "kind", "severity", "confidence",
			"title", "reason", "citation", "licence", "evidence",
		},
		"properties": map[string]any{
			"id":            str(),
			"dependency_id": str(),
			"kind":          str(),
			"severity": map[string]any{
				"type": "string", "enum": []string{"BLOCK", "CONDITION", "NOTE", "INFO"},
			},
			"confidence": map[string]any{
				"type": "string", "enum": []string{"HIGH", "MEDIUM", "LOW"},
			},
			"title":              str(),
			"reason":             str(),
			"citation":           citation,
			"licence":            str(),
			"evidence":           arr(evidence),
			"fix":                fix,
			"trap_id":            str(),
			"undetermined_field": str(),
		},
	}

	undetermined := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"id", "kind", "reason", "detail", "evidence"},
		"properties": map[string]any{
			"id":         str(),
			"kind":       str(),
			"reason":     str(),
			"detail":     str(),
			"evidence":   arr(evidence),
			"error_code": str(),
		},
	}

	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$id":     "https://clearance.dev/schema/v1/verdict.json",
		"title":   "Clearance verdict",
		"type":    "object",
		// additionalProperties is false at the top level too. A consumer that
		// accepted an unknown top-level key would accept a document with, say,
		// a second verdict field, and would have to guess which one won.
		"additionalProperties": false,
		"required": []string{
			"schema_version", "verdict", "project", "summary",
			"blockers", "conditions", "notes", "undetermined", "meta",
		},
		"properties": map[string]any{
			"schema_version": map[string]any{"type": "integer", "const": 1},
			"verdict": map[string]any{
				"type": "string",
				"enum": []string{"SHIP", "SHIP_CONDITIONAL", "DO_NOT_SHIP", "UNDETERMINED"},
			},
			"project": str(),
			"summary": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required": []string{
					"dependencies", "weight_files", "upstream_clis",
					"blockers", "conditions", "undetermined",
				},
				"properties": map[string]any{
					"dependencies":  map[string]any{"type": "integer", "minimum": 0},
					"weight_files":  map[string]any{"type": "integer", "minimum": 0},
					"upstream_clis": map[string]any{"type": "integer", "minimum": 0},
					"blockers":      map[string]any{"type": "integer", "minimum": 0},
					"conditions":    map[string]any{"type": "integer", "minimum": 0},
					"undetermined":  map[string]any{"type": "integer", "minimum": 0},
				},
			},
			// The three finding arrays and the undetermined array are required
			// even when empty, and the contract says why: a consumer must never
			// have to null-check. `null` and `[]` are different claims, and only
			// one of them means "we looked and found nothing".
			"blockers":     arr(finding),
			"conditions":   arr(finding),
			"notes":        arr(finding),
			"undetermined": arr(undetermined),
			"meta": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required": []string{
					"tool_version", "corpus_version", "corpus_signed",
					"intent_hash", "config_path", "scanned_at", "duration_ms",
					"build_commit", "build_provenance",
				},
				"properties": map[string]any{
					"tool_version":     str(),
					"corpus_version":   str(),
					"corpus_signed":    map[string]any{"type": "boolean"},
					"intent_hash":      str(),
					"config_path":      str(),
					"scanned_at":       map[string]any{"type": "integer"},
					"duration_ms":      map[string]any{"type": "integer"},
					"build_commit":     str(),
					"build_provenance": str(),
				},
			},
		},
	}
}
