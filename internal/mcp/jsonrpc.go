package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/safejson"
)

// The JSON-RPC 2.0 error codes. These are fixed by the specification and are
// NOT Clearance error codes — a client library matches on them, so they must
// not be renumbered, and `E-MCP-*` appears in the `data` field beside them
// rather than replacing them.
//
// The split matters for diagnosis. A client that sees `-32601` knows its own
// request was wrong; a human reading `data.clearance_code` knows which of the
// documented refusals fired and can look it up.
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcInternalError  = -32603
)

// rpcError is the error object of a JSON-RPC response.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`

	// Data carries the Clearance code when there is one, so that a refusal the
	// taxonomy documents is still traceable from inside the protocol.
	Data *rpcErrorData `json:"data,omitempty"`
}

// rpcErrorData is the Clearance-specific half of an error.
type rpcErrorData struct {
	ClearanceCode string `json:"clearance_code,omitempty"`
	Recovery      string `json:"recovery,omitempty"`
}

// request is one JSON-RPC message from the client.
//
// # WHY ID IS `any` AND NOT A STRING
//
// Because JSON-RPC lets a client use a number, and a server that echoed a
// stringified id back would break every client that used one. The value is kept
// exactly as `safejson` decoded it and re-encoded on the way out; an integer
// stays an integer because safejson decodes an integer into an int64 rather
// than a float64.
//
// # WHY Params IS A safejson.Object AND NOT json.RawMessage
//
// Because it was RawMessage, and it did not work. The params arrive as a
// safejson.Object, and the first version re-encoded that object with
// encoding/json to get raw bytes back. safejson.Object has EXPORTED Keys and
// Values slices — deliberately, so that iteration is deterministic — so
// encoding/json marshalled it as `{"Keys":[...],"Values":[...]}` rather than as
// the object it represents. Every `tools/call` therefore arrived with no
// `name`, and the server answered "tools/call requires a 'name'" to a request
// that plainly had one.
//
// The fix is to not make the round trip: the object is carried as itself, and
// the nested `arguments` object is read with Object(), which is the same
// accessor the frame parser already used.
type request struct {
	Method string
	ID     any

	// Params is the params object, or the zero value when params was absent or
	// was not an object. ParamsInvalid records the second case, because "you
	// sent no params" and "you sent an array where the specification requires
	// an object" are different messages to a client author.
	Params        safejson.Object
	ParamsInvalid bool
}

// hasID reports whether this message is a call rather than a notification.
//
// JSON-RPC 2.0 is explicit that a message with no `id` is a notification and
// MUST NOT be answered — including when it is malformed. Answering one is not
// merely untidy: a client that sends a notification and receives a response
// with a null id has no way to associate it, and some clients treat the
// mismatch as a protocol violation and disconnect.
func (r request) hasID() bool { return r.ID != nil }

// parseRequest decodes one frame into a request.
//
// It uses safejson rather than encoding/json for the same reason every other
// untrusted input in this product does: the parser is bounded in depth and key
// count, and it reports a syntax error as a typed E-PARSE code rather than as a
// raw *json.SyntaxError. The client on the other end of this pipe is not
// necessarily friendly — an MCP server is reached by whatever an agent decides
// to run — so the input is treated as untrusted even though it usually is not.
func parseRequest(frame []byte) (request, error) {
	o, err := safejson.DecodeObject(frame, safejson.Limits{
		MaxBytes: MaxFrameBytes, MaxDepth: 16, MaxKeys: 64,
	})
	if err != nil {
		return request{}, err
	}

	method := o.String("method")
	if method == "" {
		return request{}, cerr.New(cerr.EMcp002, "(no method)")
	}

	var req request
	req.Method = method
	if v, ok := o.Get("id"); ok {
		req.ID = v
	}
	if v, ok := o.Get("params"); ok {
		if obj, isObj := v.(safejson.Object); isObj {
			req.Params = obj
		} else {
			req.ParamsInvalid = true
		}
	}
	return req, nil
}

// writeResponse encodes and writes one response object.
//
// `omitempty` on Result is why a successful `tools/call` that returns an empty
// object still emits `"result":{}` — the value is a non-nil map, not a nil
// interface, so the field is present. That distinction is load-bearing: a
// response with neither `result` nor `error` is invalid JSON-RPC, and a client
// that receives one hangs waiting for a reply that has already arrived.
func writeResponse(w *json.Encoder, id any, result any, rpcErr *rpcError) error {
	msg := map[string]any{"jsonrpc": "2.0"}
	if id != nil {
		msg["id"] = id
	} else {
		msg["id"] = nil
	}
	if rpcErr != nil {
		msg["error"] = rpcErr
	} else {
		if result == nil {
			result = map[string]any{}
		}
		msg["result"] = result
	}
	return w.Encode(msg)
}

// clearanceError builds the rpcError for a typed Clearance refusal.
//
// The message is the taxonomy's own text, rendered with the code in front, so
// that a client showing the message to a human shows the same sentence the CLI
// would have. The recovery path travels in `data` because a JSON-RPC error
// message is one line and the recovery is a separate instruction.
func clearanceError(e *cerr.Error) *rpcError {
	return &rpcError{
		Code:    rpcInternalError,
		Message: e.Error(),
		Data: &rpcErrorData{
			ClearanceCode: string(e.Code()),
			Recovery:      e.Recovery(),
		},
	}
}

// invalidParams is the ordinary "your arguments were wrong" error.
func invalidParams(format string, args ...any) *rpcError {
	return &rpcError{Code: rpcInvalidParams, Message: fmt.Sprintf(format, args...)}
}

// methodNotFound is the ordinary "no such tool or method" error.
func methodNotFound(name string) *rpcError {
	return &rpcError{
		Code:    rpcMethodNotFound,
		Message: "no such method or tool: " + name,
		Data:    &rpcErrorData{ClearanceCode: string(cerr.EMcp002)},
	}
}
