// Package mcp exposes the engine as an MCP server over stdio.
//
// # WHAT THIS IS
//
// `clearance mcp serve` speaks JSON-RPC 2.0 to an agent. It publishes four
// tools — check, explain, corpus_info, license_lookup — and every one of them
// is read-only and idempotent. The server writes nothing, executes nothing and
// makes no outbound call.
//
// # WHY AN MCP SERVER IS WORTH THE CODE
//
// Because in the world this product is for, agents discover tools, not people.
// A licence question arrives as "is it safe to ship this?" in a coding agent's
// context, and the cheapest way to be the thing that answers it is to be
// reachable from where the question is asked. The interface contract
// (PLAN/01-ARCHITECTURE/09-interfaces-and-contracts.md §5) calls it the
// cheapest distribution channel available, and it costs days rather than weeks.
//
// # THE CAPABILITY BOUNDARY, WHICH IS THE WHOLE SECURITY STORY
//
// The server declares exactly one capability: `fs.read`, scoped to the root it
// was started in. That is not a comment, it is the code in scope.go: every path
// a tool is handed is resolved against the root before anything touches it, and
// a path that leaves the root is E-MCP-001 and terminates the server.
//
// It terminates rather than refusing politely because a request for a path
// outside the declared root is not a mistake in the protocol. It is an attempt
// to use a licence checker as a confused deputy to read a file the client
// cannot read itself, and the honest response to the first attempt is to stop.
// This is the difference between C9's threat ("elevation of privilege") being a
// paragraph in a threat model and being a property of the binary.
//
// # LAYER
//
// L5, the interface layer, beside `internal/cli`. It composes the engine
// (config → corpus → scanner → policy → verdict) the same way the CLI does, and
// like the CLI it is given the corpus path rather than resolving it: resolution
// reads the environment and the filesystem, and the caller at the edge is the
// right place for that.
//
// It deliberately does NOT import `internal/cli`. It would be a cycle — the CLI
// imports this package to dispatch `mcp serve` — and it would also be wrong:
// the CLI owns argument parsing and exit codes, and a server that reached back
// into flag handling would have two ways to be configured.
package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/corpus"
	"github.com/clearance-dev/clearance/internal/safefs"
)

// MaxFrameBytes bounds one message.
//
// 1 MiB, which is three orders of magnitude more than any legitimate request —
// the largest thing a client sends is a project path and a small intent object.
// The cap exists because the alternative is a server that grows its heap until
// the machine stops, and because an MCP server is fed by whatever an agent
// decides to run rather than by a person typing.
const MaxFrameBytes = 1 << 20

// protocolVersion is the MCP revision this server implements.
//
// It is echoed back in `initialize`. A client that needs a different revision
// will say so, and the honest answer at that point is to say what we speak
// rather than to pretend.
const protocolVersion = "2025-06-18"

// ProtocolVersion reports the revision this server speaks, for the startup
// banner. It is exported so that the CLI does not keep a second copy of the
// string — a banner that disagreed with the handshake would be worse than no
// banner.
func ProtocolVersion() string { return protocolVersion }

// ServerName is what `initialize` reports. It is a constant rather than an
// option because a server that could be renamed would make its own audit trail
// ambiguous.
const ServerName = "clearance"

// Options configure a server. Everything the server needs is passed in: it
// resolves no paths of its own, so a test can construct one over a temporary
// directory with no environment at all.
type Options struct {
	// Root is the declared workspace root — the single scope of the fs.read
	// capability. Every path a tool is given must resolve inside it.
	Root string

	// CorpusDir is the already-resolved corpus directory. The caller resolves
	// it (see cli.resolveCorpusDir) because resolution reads the environment
	// and the filesystem, which is the edge's job.
	CorpusDir string

	// Today is the date the evaluation uses for the staleness rule. Injected
	// for the same reason the CLI injects it: a verdict must not depend on the
	// wall clock (INV-6).
	Today string

	// Version is the tool version reported in `initialize` and stamped onto
	// every verdict the server produces.
	Version string

	// Commit and Provenance travel into the verdict's meta block, exactly as
	// they do for the CLI. A verdict is a document that outlives the process
	// that wrote it, so it carries the build that wrote it.
	Commit     string
	Provenance string
}

// Server is a loaded, ready-to-serve MCP endpoint.
//
// The corpus is loaded once, in New, rather than per request. That is the
// difference between a session that answers forty questions in a second and one
// that re-verifies an Ed25519 signature forty times, and the corpus cannot
// change under a running server anyway — it is a signed, immutable bundle.
type Server struct {
	opts   Options
	root   *safefs.Root
	corpus *corpus.Corpus
}

// New loads the corpus and prepares the scope check.
//
// Every failure here is fatal to the server rather than to a request. A server
// that started without a corpus would answer every `clearance_check` with an
// error, which is a worse experience than refusing to start: the client would
// see a healthy server and forty failures rather than one clear message.
func New(opts Options) (*Server, error) {
	root, err := safefs.New(opts.Root, safefs.Limits{})
	if err != nil {
		return nil, err
	}
	c, err := corpus.LoadInstalled(corpus.LoadOptions{Dir: opts.CorpusDir, Today: opts.Today})
	if err != nil {
		return nil, err
	}
	return &Server{opts: opts, root: root, corpus: c}, nil
}

// Corpus exposes the loaded corpus. It is here for the tests and for the CLI's
// `doctor` output, not for the protocol.
func (s *Server) Corpus() *corpus.Corpus { return s.corpus }

// Root is the absolute workspace root the capability is scoped to.
func (s *Server) Root() string { return s.root.Abs() }

// errFrameTooLong is the internal signal that a message exceeded MaxFrameBytes.
// It never escapes the package: Serve turns it into an E-MCP-003 warning and
// keeps reading, because one oversized frame from a chatty client is not a
// reason to end a session.
var errFrameTooLong = errors.New("mcp: frame exceeded the size cap")

// Serve reads frames from in and writes responses to out until in is exhausted.
//
// # IT NEVER PANICS OUT AND NEVER os.Exit
//
// A server that dies on a malformed frame is a server an agent has to restart
// by hand, mid-task. The recover below is the same discipline `cli.Main`
// applies for the same reason: the caller is a program, and a program that
// receives a stack trace has no way to continue.
//
// The two errors that DO terminate the session are both deliberate:
//
//   - E-MCP-001, a path outside the root. See the package comment.
//   - An I/O error on the transport, which means the pipe is gone.
func (s *Server) Serve(in io.Reader, out io.Writer) (err error) {
	defer func() {
		if r := recover(); r != nil {
			// A panic here is a bug in this package or below it. It is
			// reported as E-INT-002 — the taxonomy's code for exactly this —
			// and it ends the session, because a server that panicked once is
			// not a server to keep trusting with the rest of the stream.
			err = cerr.New(cerr.EInt002, "mcp server")
		}
	}()

	r := bufio.NewReaderSize(in, 64<<10)
	w := bufio.NewWriter(out)
	defer w.Flush()
	enc := json.NewEncoder(w)

	for {
		frame, readErr := readFrame(r)
		if readErr != nil {
			if errors.Is(readErr, errFrameTooLong) {
				// Skip and continue. See errFrameTooLong.
				continue
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
		if len(bytes.TrimSpace(frame)) == 0 {
			// A blank line between frames is legal and common: several
			// implementations delimit with "\n" and emit a trailing one. It is
			// not a parse error and answering it would be answering a
			// notification that does not exist.
			continue
		}

		done, handleErr := s.handleFrame(enc, w, frame)
		if handleErr != nil {
			return handleErr
		}
		if done {
			return nil
		}
	}
}

// handleFrame answers one frame. It returns done=true when the session should
// end cleanly (a shutdown request), and a non-nil error only for the two
// deliberate terminations described on Serve.
//
// The flush is not optional and not an optimisation to be removed later. This
// is a stdio server: the client is blocked on a read, and a response sitting in
// a buffer is indistinguishable from a server that has hung. Every write path
// below goes through this function, so there is exactly one place to get it
// right.
func (s *Server) handleFrame(enc *json.Encoder, w *bufio.Writer, frame []byte) (bool, error) {
	req, err := parseRequest(frame)
	if err != nil {
		// A frame that cannot be parsed has no id to answer, so the response
		// carries a null id. That is what the specification prescribes for a
		// parse error, and clients handle it because they must.
		_ = writeResponse(enc, nil, nil, &rpcError{
			Code:    rpcParseError,
			Message: err.Error(),
		})
		return false, w.Flush()
	}

	result, rpcErr, fatal := s.dispatch(req)

	// A notification is never answered, even when it failed. See
	// request.hasID.
	if req.hasID() {
		if rpcErr != nil {
			if werr := writeResponse(enc, req.ID, nil, rpcErr); werr != nil {
				return false, werr
			}
		} else if werr := writeResponse(enc, req.ID, result, nil); werr != nil {
			return false, werr
		}
		if ferr := w.Flush(); ferr != nil {
			return false, ferr
		}
	}

	if fatal != nil {
		return true, fatal
	}
	return false, nil
}

// dispatch routes a request to its handler.
//
// The third result is the deliberate session-ending error, and it is separate
// from rpcErr on purpose: an ordinary refusal is answered inside the protocol
// and the server keeps running, while E-MCP-001 is answered AND ends the
// session. Folding the two together would make the escape refusal look like a
// bad argument.
func (s *Server) dispatch(req request) (result any, rpcErr *rpcError, fatal error) {
	switch req.Method {
	case "initialize":
		return s.initialize(), nil, nil

	case "notifications/initialized", "initialized":
		// A notification. It is listed rather than falling through to
		// method-not-found so that the server does not answer it — answering a
		// notification is the one protocol error every client library treats
		// as fatal.
		return nil, nil, nil

	case "ping":
		return map[string]any{}, nil, nil

	case "tools/list":
		return map[string]any{"tools": toolSchemas()}, nil, nil

	case "tools/call":
		return s.callTool(req)

	case "shutdown":
		return map[string]any{}, nil, nil
	}

	return nil, methodNotFound(req.Method), nil
}

// initialize is the handshake.
//
// # WHY THE CAPABILITY BLOCK IS ALMOST EMPTY
//
// MCP servers advertise things they can do — subscribe to resource changes,
// emit log messages, complete arguments. This one advertises `tools` and
// nothing else, because it can do nothing else. Every field a server claims
// here is a field a client will try to use, and a server that claimed
// `resources` would be asked for them.
//
// The `fs.read` capability is not an MCP capability; it is the AIO-Core
// capability vocabulary the plan's security architecture uses, and it travels
// in `instructions` so that a human reading a client's logs can see the scope
// without reading this source file.
func (s *Server) initialize() map[string]any {
	return map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    ServerName,
			"version": s.opts.Version,
		},
		"instructions": "Clearance returns a licence verdict, not a report. " +
			"Capability: fs.read, scoped to " + s.root.Abs() + ". " +
			"Read-only and idempotent. The server never writes, never executes and never makes an outbound call.",
	}
}

// readFrame reads one newline-delimited frame.
//
// # WHY NOT bufio.Scanner
//
// Because Scanner's response to an oversized token is to stop permanently with
// ErrTooLong. A server that dies because a client sent one large frame is a
// server with a trivial denial of service, and the fix is not a bigger buffer —
// it is to discard the offending line and resynchronise, which needs a reader
// that can be told to keep going.
func readFrame(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		buf = append(buf, chunk...)

		if len(buf) > MaxFrameBytes {
			// Discard the remainder of this line so the next read starts on a
			// frame boundary. Without this the tail of the oversized message
			// would be parsed as the head of the next one, and the server would
			// answer a request nobody made.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
			return nil, errFrameTooLong
		}

		switch {
		case err == nil:
			return bytes.TrimRight(buf, "\r\n"), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			// A final line with no trailing newline is a complete frame. An
			// empty tail is the end of the stream.
			if len(bytes.TrimSpace(buf)) == 0 {
				return nil, io.EOF
			}
			return bytes.TrimRight(buf, "\r\n"), nil
		default:
			return nil, err
		}
	}
}
