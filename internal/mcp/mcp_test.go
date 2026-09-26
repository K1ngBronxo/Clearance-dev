package mcp

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/clearance-dev/clearance/internal/safejson"
)

// testCorpusDir is the corpus that ships with the module, resolved relative to
// this package's directory.
//
// The tests need a real corpus rather than a stub: half of what the server does
// is read one, and a stub would let the licence-lookup and explain tools pass
// while resolving nothing. The path is a sibling of internal/, which is where
// the corpus actually lives.
const testCorpusDir = "../../corpus"

// testToday is injected everywhere so that no test reads the clock. A server
// whose verdict depends on the calendar is a server whose tests fail in March
// for a reason that has nothing to do with the code (INV-6).
const testToday = "2026-09-24"

// newTestServer builds a server over a temporary directory.
func newTestServer(t *testing.T, root string) *Server {
	t.Helper()
	srv, err := New(Options{
		Root:      root,
		CorpusDir: filepath.FromSlash(testCorpusDir),
		Today:     testToday,
		Version:   "test",
	})
	if err != nil {
		t.Fatalf("starting the server: %v", err)
	}
	return srv
}

// serve runs a batch of frames through the server and returns the decoded
// responses in order.
func serve(t *testing.T, srv *Server, frames ...string) []map[string]any {
	t.Helper()
	var out strings.Builder
	_ = srv.Serve(strings.NewReader(strings.Join(frames, "\n")+"\n"), &out)

	var got []map[string]any
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("the server wrote a line that is not JSON: %v\n%s", err, line)
		}
		got = append(got, m)
	}
	return got
}

// ── the handshake ────────────────────────────────────────────────────────────

// TestInitializeDeclaresExactlyOneCapability pins the capability surface.
//
// # WHY "EXACTLY" IS THE ASSERTION
//
// MCP servers advertise what they can do, and every field advertised is a field
// a client will try to use. This server reads files inside one root and does
// nothing else, so it may claim `tools` and nothing more. A future edit that
// added `resources` or `prompts` "for completeness" would be advertising
// behaviour that does not exist, and the client would find out by calling it.
//
// The check is on the exact key set rather than on the absence of two names, so
// a new capability has to be added here deliberately.
func TestInitializeDeclaresExactlyOneCapability(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)

	if len(got) != 1 {
		t.Fatalf("initialize produced %d responses, want 1", len(got))
	}
	result, ok := got[0]["result"].(map[string]any)
	if !ok {
		t.Fatalf("initialize returned no result: %v", got[0])
	}

	if pv, _ := result["protocolVersion"].(string); pv != protocolVersion {
		t.Errorf("protocolVersion = %q, want %q", pv, protocolVersion)
	}

	caps, ok := result["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("initialize declared no capabilities: %v", result)
	}
	if len(caps) != 1 {
		t.Errorf("the server declares %d capabilities, want exactly 1.\n"+
			"Got: %v\nEvery capability a server advertises is one a client will "+
			"try to use, and this server does nothing but read files inside one "+
			"root.", len(caps), keysOf(caps))
	}
	if _, hasTools := caps["tools"]; !hasTools {
		t.Errorf("the server does not declare `tools`, which is the only thing it "+
			"can do. Got: %v", keysOf(caps))
	}

	info, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatalf("initialize declared no serverInfo")
	}
	if name, _ := info["name"].(string); name != ServerName {
		t.Errorf("serverInfo.name = %q, want %q", name, ServerName)
	}

	// The instructions must state the scope, because a human reading a client's
	// log is the audience for them.
	instr, _ := result["instructions"].(string)
	if !strings.Contains(instr, "fs.read") {
		t.Errorf("the instructions do not name the capability: %q", instr)
	}
	if !strings.Contains(instr, srv.Root()) {
		t.Errorf("the instructions do not name the root the capability is scoped to: %q", instr)
	}
}

// TestNotificationIsNeverAnswered asserts the rule every MCP client library
// treats as fatal when it is broken.
//
// JSON-RPC 2.0: a message with no `id` is a notification and MUST NOT be
// answered. A client that sends one and receives a response with a null id has
// no way to associate it, and several implementations disconnect on the
// mismatch.
func TestNotificationIsNeverAnswered(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"tools/list"}`,
		`{"jsonrpc":"2.0","method":"nonsense/notification"}`,
		`{"jsonrpc":"2.0","id":7,"method":"ping"}`,
	)

	if len(got) != 1 {
		t.Fatalf("three notifications and one call produced %d responses, want 1.\n"+
			"A response to a notification is a protocol violation: the client has "+
			"no id to match it against.\nGot: %v", len(got), got)
	}
	if id, _ := got[0]["id"].(float64); id != 7 {
		t.Errorf("the single response answered id %v, want the ping's 7", got[0]["id"])
	}
}

// TestBlankLinesAreNotAnswered asserts that the transport tolerates the framing
// several implementations actually emit.
//
// A blank line between frames is legal and common — some clients delimit with
// "\n" and leave a trailing one — and answering it would be answering a
// notification that does not exist.
func TestBlankLinesAreNotAnswered(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	var out strings.Builder
	_ = srv.Serve(strings.NewReader("\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\n\n"), &out)

	lines := nonEmptyLines(out.String())
	if len(lines) != 1 {
		t.Fatalf("blank lines produced %d responses, want 1: %v", len(lines), lines)
	}
}

// TestParseErrorCarriesANullID asserts the one case where the specification
// requires an answer with no id to echo.
func TestParseErrorCarriesANullID(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv, `{"jsonrpc":"2.0","id":1,"method":`)

	if len(got) != 1 {
		t.Fatalf("a truncated frame produced %d responses, want 1", len(got))
	}
	errObj, ok := got[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("a truncated frame produced no error: %v", got[0])
	}
	if code, _ := errObj["code"].(float64); int(code) != rpcParseError {
		t.Errorf("a truncated frame produced error code %v, want %d", errObj["code"], rpcParseError)
	}
	if id, present := got[0]["id"]; !present || id != nil {
		t.Errorf("a parse error must carry a null id, got %v", got[0]["id"])
	}
}

// TestUnknownMethodIsMethodNotFound asserts that an unknown method is an
// ordinary protocol error rather than a crash.
func TestUnknownMethodIsMethodNotFound(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv, `{"jsonrpc":"2.0","id":3,"method":"resources/list"}`)

	if len(got) != 1 {
		t.Fatalf("got %d responses, want 1", len(got))
	}
	errObj, ok := got[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("an unknown method produced no error: %v", got[0])
	}
	if code, _ := errObj["code"].(float64); int(code) != rpcMethodNotFound {
		t.Errorf("error code = %v, want %d", errObj["code"], rpcMethodNotFound)
	}
}

// ── tools ────────────────────────────────────────────────────────────────────

// TestToolsListIsTheFourTools pins the published tool surface.
//
// # WHY THE NAMES AND THE SCHEMAS BOTH
//
// Because a tool whose name and whose schema disagree is a tool a client cannot
// call, and because the count is part of the contract: the interface spec
// (the interface spec §5) names four, and a fifth added without a
// documentation change is a tool nobody knows exists.
func TestToolsListIsTheFourTools(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	if len(got) != 1 {
		t.Fatalf("tools/list produced %d responses, want 1", len(got))
	}
	result, _ := got[0]["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != 4 {
		t.Fatalf("tools/list published %d tools, want 4: %v", len(tools), tools)
	}

	want := map[string]bool{
		ToolCheck: false, ToolExplain: false,
		ToolCorpusInfo: false, ToolLicenceLookup: false,
	}
	for _, raw := range tools {
		tool, _ := raw.(map[string]any)
		name, _ := tool["name"].(string)
		if _, known := want[name]; !known {
			t.Errorf("tools/list published an unexpected tool %q", name)
			continue
		}
		want[name] = true

		if d, _ := tool["description"].(string); strings.TrimSpace(d) == "" {
			t.Errorf("tool %q has no description.\nA tool description is the only "+
				"documentation a model reads before deciding to call it.", name)
		}
		schema, ok := tool["inputSchema"].(map[string]any)
		if !ok {
			t.Errorf("tool %q has no inputSchema", name)
			continue
		}
		if typ, _ := schema["type"].(string); typ != "object" {
			t.Errorf("tool %q has inputSchema.type %q, want object", name, typ)
		}
		// additionalProperties:false is what makes a typo in an argument name a
		// refusal rather than a silently ignored field. A tool that accepted
		// `spdx` for `spdx_id` would answer with an empty lookup and the agent
		// would report a clean result.
		if ap, present := schema["additionalProperties"]; !present || ap != false {
			t.Errorf("tool %q does not set additionalProperties:false.\n"+
				"Without it a misspelled argument is silently ignored and the call "+
				"succeeds with the wrong answer.", name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("tools/list did not publish %q", name)
		}
	}
}

// TestCallToolRequiresAName asserts the shape check.
func TestCallToolRequiresAName(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`)

	errObj, ok := got[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("a nameless tools/call produced no error: %v", got[0])
	}
	if code, _ := errObj["code"].(float64); int(code) != rpcInvalidParams {
		t.Errorf("error code = %v, want %d", errObj["code"], rpcInvalidParams)
	}
}

// TestToolsCallParamsThatAreNotAnObjectAreRefused asserts the shape check on
// params itself.
//
// JSON-RPC allows array params, and the specification requires an object for
// tools/call. Distinguishing the two is the difference between "you sent
// nothing" and "you sent the wrong shape", which are different fixes.
func TestToolsCallParamsThatAreNotAnObjectAreRefused(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[1,2,3]}`)

	errObj, ok := got[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("array params produced no error: %v", got[0])
	}
	msg, _ := errObj["message"].(string)
	if !strings.Contains(msg, "object") {
		t.Errorf("the refusal does not say the params must be an object: %q", msg)
	}
}

// TestUnknownToolIsAnOrdinaryError asserts that an agent guessing a tool name
// does not take the server down.
func TestUnknownToolIsAnOrdinaryError(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"clearance_scan"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
	)

	if len(got) != 2 {
		t.Fatalf("got %d responses, want 2 — an unknown tool must not end the session.\n"+
			"An agent that guesses a name is an ordinary event in a long session.", len(got))
	}
	errObj, ok := got[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("an unknown tool produced no error: %v", got[0])
	}
	if code, _ := errObj["code"].(float64); int(code) != rpcMethodNotFound {
		t.Errorf("error code = %v, want %d", errObj["code"], rpcMethodNotFound)
	}
	data, _ := errObj["data"].(map[string]any)
	if got, _ := data["clearance_code"].(string); got != string("E-MCP-002") {
		t.Errorf("the refusal carries clearance_code %q, want E-MCP-002.\n"+
			"A refusal inside the protocol still has to be traceable to the "+
			"taxonomy, or a user cannot look it up.", got)
	}
}

// ── the two read-only tools ──────────────────────────────────────────────────

// TestCorpusInfoReportsTheCorpus asserts the introspection tool answers.
//
// It checks the fields are present and that the date is the injected one. The
// layout is checked separately, in TestCorpusInfoAlignsItsValueColumn.
func TestCorpusInfoReportsTheCorpus(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"clearance_corpus_info"}}`)

	text := resultText(t, got[0])
	for _, want := range []string{
		"Corpus ", "Built:", "Licences:", "Obligations:",
		"Traps:", "Platforms:", "Territories:", "Citations:", "Today:",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("corpus_info does not report %q.\nGot:\n%s", want, text)
		}
	}

	// The date must be the injected one rather than the machine's clock. A
	// server that read time.Now() here would answer differently tomorrow for
	// the same request, which is precisely what INV-6 forbids — and the
	// difference would be invisible to every substring check above.
	lines := nonEmptyLines(text)
	for _, line := range lines {
		if !strings.HasPrefix(line, "Today:") {
			continue
		}
		if !strings.HasSuffix(strings.TrimRight(line, " "), testToday) {
			t.Errorf("corpus_info reports %q, want the injected date %q.\n"+
				"Reading the clock instead makes the same request answer "+
				"differently tomorrow (INV-6).", line, testToday)
		}
		return
	}
	t.Errorf("corpus_info has no Today line.\nGot:\n%s", text)
}

// TestCorpusInfoAlignsItsValueColumn asserts the field block renders as a table.
//
// This is checked structurally rather than by substring because the padding is
// the whole point: an agent relays this block verbatim, and a renderer that
// padded some labels and not others would still satisfy every "contains" check
// while producing something that no longer lines up in a terminal.
func TestCorpusInfoAlignsItsValueColumn(t *testing.T) {
	// The offset the value column starts at. It is a constant in the renderer;
	// naming it here means a deliberate re-pad has to change two places, and an
	// accidental one changes only one.
	const wantColumn = 14

	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"clearance_corpus_info"}}`)
	text := resultText(t, got[0])

	checked := 0
	for _, line := range nonEmptyLines(text) {
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue // the header line carries no colon
		}
		rest := line[colon+1:]
		indent := len(rest) - len(strings.TrimLeft(rest, " "))
		if got := colon + 1 + indent; got != wantColumn {
			t.Errorf("value column is %d in %q, want %d.\n"+
				"Every field's value has to start at the same offset or the "+
				"block stops reading as a table.", got, line, wantColumn)
		}
		checked++
	}
	if checked < 5 {
		t.Errorf("only %d field lines were checked; the block looks truncated:\n%s", checked, text)
	}
}

// TestLicenceLookupNamesAKnownKind asserts that the obligation listing goes
// through the closed vocabulary.
//
// The corpus ships AGPL-3.0-only with a NETWORK_DISCLOSURE obligation, so a
// listing that did not print that name would mean the kind was not reaching the
// output at all — and the "UNKNOWN(...)" fallback would be invisible.
func TestLicenceLookupNamesAKnownKind(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"clearance_license_lookup","arguments":{"spdx_id":"AGPL-3.0-only"}}}`)

	text := resultText(t, got[0])
	if !strings.Contains(text, "AGPL-3.0-only") {
		t.Errorf("the lookup does not name the licence:\n%s", text)
	}
	if !strings.Contains(text, "NETWORK_DISCLOSURE") {
		t.Errorf("the lookup does not name the obligation kind.\n"+
			"AGPL-3.0-only's whole point is the network-disclosure clause; a "+
			"listing that omits the kind has lost the finding.\nGot:\n%s", text)
	}
	if strings.Contains(text, "UNKNOWN(") {
		t.Errorf("the lookup rendered an unrecognised kind:\n%s", text)
	}
}

// TestLicenceLookupMissIsNotAPass asserts the honesty rule for a licence the
// corpus does not carry.
//
// The tool must say that this is not a pass, because an agent reading a bare
// "no entry" would reasonably conclude the licence is fine.
func TestLicenceLookupMissIsNotAPass(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"clearance_license_lookup","arguments":{"spdx_id":"WTFPL"}}}`)

	if _, isErr := got[0]["error"]; isErr {
		t.Fatalf("a missing licence produced a protocol error rather than an answer: %v", got[0])
	}
	text := resultText(t, got[0])
	if !strings.Contains(text, "not a pass") {
		t.Errorf("a missing corpus entry does not say that it is not a pass.\n"+
			"An agent reading a bare 'no entry' would conclude the licence is "+
			"fine, which is the false pass this product exists to prevent.\nGot:\n%s", text)
	}
}

// TestLicenceLookupRequiresAnArgument asserts the required-argument check.
func TestLicenceLookupRequiresAnArgument(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"clearance_license_lookup"}}`)

	if _, ok := got[0]["error"]; !ok {
		t.Fatalf("a lookup with no spdx_id succeeded: %v", got[0])
	}
}

// ── explain ──────────────────────────────────────────────────────────────────

// TestExplainMissIsASuccessfulAnswer asserts that an unknown citation id is an
// answer rather than a failure.
//
// "I have no clause with that id" is a successful response to a question, and
// returning it as a failure would make an agent retry a lookup whose answer
// cannot change.
func TestExplainMissIsASuccessfulAnswer(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	got := serve(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"clearance_explain","arguments":{"citation_id":"https://example.invalid#1"}}}`)

	if _, isErr := got[0]["error"]; isErr {
		t.Fatalf("an unknown citation produced a protocol error: %v", got[0])
	}
	text := resultText(t, got[0])
	if !strings.Contains(text, "No citation") {
		t.Errorf("an unknown citation produced an unclear answer:\n%s", text)
	}
}

// TestExplainQuotesOnlyAVerbatimExcerpt asserts the excerpt-kind rule survives
// the MCP surface.
//
// # WHY THIS MATTERS HERE AS MUCH AS IN THE RENDERER
//
// The corpus stores paraphrases and quotations in the same field, and the rule
// is that only a verbatim excerpt may appear in quotation marks. An agent
// relaying this text to a human is relaying a claim about what a licence says,
// so printing a paraphrase in quotes through the MCP surface would fabricate a
// quotation just as surely as printing it in the terminal would.
func TestExplainQuotesOnlyAVerbatimExcerpt(t *testing.T) {
	srv := newTestServer(t, t.TempDir())

	// Walk the corpus for one of each, so the test asserts the rule rather than
	// one hand-picked citation that could be reworded out of the corpus.
	var verbatimID, paraphraseID string
	for _, id := range srv.corpus.Citations.IDs() {
		cit, ok := srv.corpus.Citations.Get(id)
		if !ok || strings.TrimSpace(cit.Excerpt) == "" {
			continue
		}
		if cit.ExcerptKind.IsVerbatim() {
			if verbatimID == "" {
				verbatimID = id
			}
		} else if paraphraseID == "" {
			paraphraseID = id
		}
	}
	if verbatimID == "" || paraphraseID == "" {
		t.Skipf("the corpus has no pair of verbatim and non-verbatim excerpts to compare "+
			"(verbatim=%q paraphrase=%q)", verbatimID, paraphraseID)
	}

	frame := func(id int, citation string) string {
		return `{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"tools/call","params":{"name":"clearance_explain","arguments":{"citation_id":` + jsonString(citation) + `}}}`
	}
	got := serve(t, srv, frame(1, verbatimID), frame(2, paraphraseID))
	if len(got) != 2 {
		t.Fatalf("got %d responses, want 2", len(got))
	}

	verbatimText := resultText(t, got[0])
	paraphraseText := resultText(t, got[1])

	verbatim, _ := srv.corpus.Citations.Get(verbatimID)
	paraphrase, _ := srv.corpus.Citations.Get(paraphraseID)

	if !strings.Contains(verbatimText, `"`+verbatim.Excerpt+`"`) {
		t.Errorf("a verbatim excerpt was not quoted.\nID: %s\nGot:\n%s", verbatimID, verbatimText)
	}
	if strings.Contains(paraphraseText, `"`+paraphrase.Excerpt+`"`) {
		t.Errorf("a paraphrase was rendered inside quotation marks, which fabricates a "+
			"quotation.\nID: %s\nGot:\n%s", paraphraseID, paraphraseText)
	}
}

// ── the transport ────────────────────────────────────────────────────────────

// TestOversizedFrameIsSkippedAndTheSessionContinues asserts the denial-of-
// service property: one large message must not end a session.
//
// # WHY THIS IS NOT A HYPOTHETICAL
//
// bufio.Scanner's response to an oversized token is to stop permanently with
// ErrTooLong, and the obvious implementation of a frame reader uses one. A
// server that dies because a client sent one large frame has a trivial denial of
// service, and the fix is not a bigger buffer — it is to discard the offending
// line and resynchronise.
func TestOversizedFrameIsSkippedAndTheSessionContinues(t *testing.T) {
	srv := newTestServer(t, t.TempDir())

	huge := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"clearance_corpus_info","arguments":{"pad":"` +
		strings.Repeat("x", MaxFrameBytes+1024) + `"}}}`
	small := `{"jsonrpc":"2.0","id":2,"method":"ping"}`

	var out strings.Builder
	_ = srv.Serve(strings.NewReader(huge+"\n"+small+"\n"), &out)

	lines := nonEmptyLines(out.String())
	if len(lines) != 1 {
		t.Fatalf("an oversized frame followed by a ping produced %d responses, want 1.\n"+
			"The oversized frame must be skipped and the stream must resynchronise: "+
			"a server that ends here has a trivial denial of service.\nGot: %v",
			len(lines), lines)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("the surviving response is not JSON: %v", err)
	}
	if id, _ := m["id"].(float64); id != 2 {
		t.Errorf("the surviving response answered id %v, want the ping's 2.\n"+
			"If the tail of the oversized frame were parsed as the head of the "+
			"next one, the server would answer a request nobody made.", m["id"])
	}
}

// TestServeEndsCleanlyOnAnEmptyStream asserts that closing stdin is a clean
// exit rather than an error.
//
// An agent that finishes its work and closes the pipe must not leave a non-zero
// exit code behind, because a CI step that reads it would report a failure.
func TestServeEndsCleanlyOnAnEmptyStream(t *testing.T) {
	srv := newTestServer(t, t.TempDir())
	var out strings.Builder
	if err := srv.Serve(strings.NewReader(""), &out); err != nil {
		t.Fatalf("an empty stream produced an error: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("an empty stream produced output: %q", out.String())
	}
}

// ── the scope ────────────────────────────────────────────────────────────────

// TestDisplayableDropsTheMachinePrefix asserts that a refusal does not leak the
// operator's directory layout.
//
// The message travels to a client that logs it and from there into a ticket.
// The last two segments are enough for a human to recognise what was asked for.
func TestDisplayableDropsTheMachinePrefix(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/etc/passwd", "/etc/passwd"},
		{"/etc/ssl/private/key.pem", "…/private/key.pem"},
		{`C:\Users\someone\secrets\keys.txt`, "…/secrets/keys.txt"},
		{"../../etc/passwd", "…/etc/passwd"},
		{"", "."},
	}
	for _, tc := range cases {
		if got := displayable(tc.in); got != tc.want {
			t.Errorf("displayable(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// The property that matters, asserted directly rather than through the
	// table: no machine prefix survives.
	home := "/home/someone/projects/secret-project"
	if got := displayable(home); strings.Contains(got, "/home/someone") {
		t.Errorf("displayable leaked the directory layout: %q", got)
	}
}

// TestResolveInRootAcceptsTheRootAndItsChildren asserts the capability's
// positive direction, which the guard suite covers end-to-end and this covers at
// the unit.
func TestResolveInRootAcceptsTheRootAndItsChildren(t *testing.T) {
	srv := newTestServer(t, t.TempDir())

	if got, err := resolveInRoot(srv.root, ""); err != nil || got != srv.Root() {
		t.Errorf("an empty path resolved to (%q, %v), want the root itself", got, err)
	}
	if got, err := resolveInRoot(srv.root, "."); err != nil {
		t.Errorf("the root was refused: %v (%q)", err, got)
	}
	if _, err := resolveInRoot(srv.root, ".."); err == nil {
		t.Error("the parent directory was accepted")
	}
}

// ── the YAML bridge ──────────────────────────────────────────────────────────

// TestToYAMLQuotesEveryString asserts the decision that makes the inline-intent
// path safe.
//
// # WHY QUOTING EVERYTHING IS THE ASSERTION
//
// Because the alternative is a classifier deciding which strings are safe bare,
// and every YAML implementation answers differently. `no` is a boolean in YAML
// 1.1 and a string in 1.2; `1.0` is a float; `null` is null. A project named
// "no" would silently become the wrong type, and the failure would surface three
// layers away from the client that sent it.
func TestToYAMLQuotesEveryString(t *testing.T) {
	cases := []struct {
		name  string
		value safejson.Value
		want  string
	}{
		{"a bare word", "commercial", `"commercial"`},
		{"a yaml boolean", "no", `"no"`},
		{"a yaml null", "null", `"null"`},
		{"a number as a string", "1.0", `"1.0"`},
		{"a colon", "a: b", `"a: b"`},
		{"an embedded quote", `say "hi"`, `"say \"hi\""`},
		{"a backslash", `a\b`, `"a\\b"`},
		{"a true boolean", true, "true"},
		{"a false boolean", false, "false"},
		{"an integer", int64(42), "42"},
		{"nil", nil, "null"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := yamlScalar(tc.value); got != tc.want {
				t.Errorf("yamlScalar(%#v) = %s, want %s", tc.value, got, tc.want)
			}
		})
	}
}

// TestToYAMLIndentsCollections asserts the shape of a nested document, because
// the parser is line-oriented and a wrong indent is a parse error rather than a
// wrong value.
func TestToYAMLIndentsCollections(t *testing.T) {
	doc := map[string]any{
		"project": map[string]any{"name": "x"},
		"scale":   map[string]any{"mau": 10},
		"use": map[string]any{
			"commercial": true,
		},
	}
	v, err := safejson.Decode(marshalJSON(t, doc), safejson.Limits{})
	if err != nil {
		t.Fatalf("decoding the fixture: %v", err)
	}

	got := string(toYAML(v))
	for _, want := range []string{
		`"project":` + "\n" + `  "name": "x"`,
		`"scale":` + "\n" + `  "mau": 10`,
		`"commercial": true`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the document does not contain %q.\nGot:\n%s", want, got)
		}
	}
	if strings.Contains(got, "{") || strings.Contains(got, "}") {
		t.Errorf("the emitter produced flow syntax, which the line-oriented parser "+
			"cannot read as a mapping:\n%s", got)
	}
}

// ── small helpers ────────────────────────────────────────────────────────────

func resultText(t *testing.T, resp map[string]any) string {
	t.Helper()
	if errObj, isErr := resp["error"]; isErr {
		t.Fatalf("expected a result, got an error: %v", errObj)
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("the response has no result object: %v", resp)
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("the result has no content: %v", result)
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	if text == "" {
		t.Fatalf("the content block carries no text: %v", first)
	}
	return text
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func marshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling the fixture: %v", err)
	}
	return b
}
