package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/clearance-dev/clearance/internal/ai"
	"github.com/clearance-dev/clearance/internal/cerr"
)

// ─────────────────────────────────────────────────────────────────────────────
// INV-3: the scanner never phones home.
//
// This file is the whole of that invariant's enforcement. Two things make it
// structural rather than aspirational:
//
//  1. internal/arch_test.go asserts that `net/http` appears in exactly one file
//     in the repository, and that this is it. A future contributor who wants to
//     fetch something from the scanner has to delete that assertion, which is a
//     change a reviewer will notice.
//
//  2. Every outbound call must be constructed by newHTTPClient, and that
//     function refuses unless EnableNetwork has been called. Nothing in this
//     build calls it. So in this build the answer to "can clearance reach the
//     network?" is no, by construction, and the failure is a typed
//     E-NET-006 — the tripwire firing exactly as the taxonomy says it should.
//
// The privacy promise in the README is therefore not a policy the code is asked
// to respect. It is the only behaviour the code can express.
// ─────────────────────────────────────────────────────────────────────────────

// netAllowed is the process-wide egress switch. It starts false and stays false
// unless something explicitly arms it.
//
// It is a plain bool rather than an atomic because it is written once during
// single-threaded start-up and read thereafter. If a future change arms it
// concurrently, this must become an atomic.Bool — and the race detector will
// say so, because the test suite runs with -race.
var netAllowed bool

// EnableNetwork arms outbound networking for the remainder of the process.
//
// This is called by exactly one thing: the corpus updater, which is opt-in,
// user-initiated, and documented as the only network operation the tool has.
// It is deliberately not called anywhere in this build, so `clearance check`
// cannot make an outbound connection even if a bug tried to.
func EnableNetwork() { netAllowed = true }

// NetworkEnabled reports whether egress is armed. Used by tests and by
// `clearance version` to state plainly whether this binary can reach out.
func NetworkEnabled() bool { return netAllowed }

// offlineForced reports whether the user asked for no network, from either the
// flag or the environment.
//
// The environment variable is honoured because CI systems set environment
// variables far more easily than they thread flags through wrapper scripts, and
// a user who has exported CLEARANCE_OFFLINE has stated an intent that should
// survive a shell alias that forgets the flag.
func offlineForced(flagValue bool) bool {
	if flagValue {
		return true
	}
	return os.Getenv("CLEARANCE_OFFLINE") == "1"
}

// corpusHosts is the redirect and connection allowlist (E-NET-007).
//
// A redirect is the classic way an allowlisted fetch becomes an exfiltration:
// the corpus host is trusted, so a 302 to somewhere else would be followed
// silently. Only these hosts may be reached, and a redirect anywhere else is
// refused rather than followed.
var corpusHosts = map[string]bool{
	"corpus.clearance.dev":   true,
	"releases.clearance.dev": true,
}

// maxRedirectHops bounds how far a fetch may be bounced. Three hops is already
// more than a static release host should need, and every additional hop is
// another chance to be pointed somewhere unexpected.
const maxRedirectHops = 3

// redirectAllowed is the whole redirect policy, extracted from the client
// closure so that it is directly testable.
//
// The guard test TestNoUnexpectedEgress lives in this package and asserts that
// every host except the two corpus hosts is refused. It could not do that
// against the closure, because reaching into it requires constructing an
// *http.Request — and importing net/http in a test file would trip
// internal/arch_test.go's OnlyOneFileImportsNetHTTP rule, which pins that
// import to exactly one file in the repository. Extracting the decision rather
// than weakening the rule is the right way round: the rule is load-bearing
// (INV-3), and a policy that cannot be tested is a policy that will rot.
func redirectAllowed(hops int, host string) error {
	if hops >= maxRedirectHops {
		return cerr.New(cerr.ENet007, host)
	}
	if !corpusHosts[host] {
		return cerr.New(cerr.ENet007, host)
	}
	return nil
}

// newHTTPClient returns the only HTTP client this program can construct.
//
// The refusal order is deliberate. Offline is checked first because it is the
// user's explicit instruction and deserves the specific E-NET-004 explanation
// ("expected; no action") rather than the alarming E-NET-006. The switch is
// checked second, and reaching it means something tried to make a network call
// without the corpus updater having armed egress — which is INV-3 firing.
func newHTTPClient(offline bool) (*http.Client, error) {
	if offline {
		return nil, cerr.New(cerr.ENet004)
	}
	if !netAllowed {
		return nil, cerr.New(cerr.ENet006)
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return redirectAllowed(len(via), req.URL.Host)
		},
	}, nil
}

// assertNoEgress is the runtime tripwire, callable from anywhere.
//
// It exists so that a code path which *wants* to make a network call can be
// written with a single guard line rather than a comment asking future readers
// to be careful. In this build nothing calls it, because nothing wants to.
func assertNoEgress(offline bool) error {
	if offline {
		return cerr.New(cerr.ENet004)
	}
	if !netAllowed {
		return cerr.New(cerr.ENet006)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// The AI transport (Tier 1 / Tier 3).
//
// ADR-021 scoped INV-3 rather than reversing it: the *scanner* never phones
// home, no code path in L0–L4 may open a socket, and exactly one file may. This
// is that file, and it now carries two callers instead of one — the corpus
// updater and the AI layer.
//
// That is why the AI transport is here rather than in internal/ai. The AI
// package defines the interface and stays pure; the implementation lives where
// the single host allowlist lives, so a second outbound path cannot appear
// without checkOnlyOneFileImportsNetHTTP saying so.
// ─────────────────────────────────────────────────────────────────────────────

// aiAllowed arms AI egress. It is separate from netAllowed on purpose.
//
// The corpus updater and the AI layer are different privileges. A user who
// permits one has not permitted the other, and a single boolean would make
// `clearance corpus update` and `clearance check --ai` indistinguishable — which
// would mean a future feature that armed egress for the corpus could silently
// carry a prompt to a model vendor as well.
var aiAllowed bool

// EnableAI arms AI egress for the remainder of the process.
//
// It is called by exactly one thing: the AI step in `clearance check`, after the
// verdict has been rendered and only when `--ai` was passed and `--offline` was
// not. Nothing else may call it.
func EnableAI() { aiAllowed = true }

// AIEnabled reports whether AI egress is armed.
func AIEnabled() bool { return aiAllowed }

// aiTransport is the only implementation of ai.Transport.
//
// # WHAT IT REFUSES
//
//   - It refuses when `--offline` was passed, with E-NET-004 rather than the
//     alarming E-NET-006, because a user who asked for offline deserves the
//     specific explanation. `--ai --offline` is refused earlier, in the CLI, but
//     the check is repeated here so that the invariant does not depend on the
//     caller having remembered.
//   - It refuses when AI egress was never armed, with E-NET-006 — the tripwire
//     firing exactly as the taxonomy says it should.
//   - It refuses a redirect anywhere but the provider's own host, with E-NET-007.
//     The allowlist is derived from the provider row and nothing else, so a
//     provider that gained a second host would gain it in one place.
//   - It refuses a response larger than maxBytes, with E-AI-010. A hostile or
//     broken endpoint must not be able to make the tool allocate.
type aiTransport struct {
	client   *http.Client
	host     string
	maxBytes int64
}

// newAITransport builds the client for one provider.
//
// host is the allowlist, and it comes from the provider row. A redirect is
// compared against it with the port included, because the local runtimes are
// addressed by port and dropping it would make `127.0.0.1:11434` and
// `127.0.0.1:1234` the same host.
func newAITransport(host string, offline bool, timeout time.Duration) (*aiTransport, error) {
	if offline {
		return nil, cerr.New(cerr.ENet004)
	}
	if !aiAllowed {
		return nil, cerr.New(cerr.ENet006)
	}
	if host == "" {
		// A provider whose host could not be derived. Refusing is the only safe
		// direction: an empty allowlist entry would match nothing, and an
		// allowlist that matches nothing is indistinguishable from one that
		// matches everything if the comparison is ever inverted.
		return nil, cerr.New(cerr.EAi011, "provider", "base_url")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &aiTransport{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirectHops {
					return cerr.New(cerr.ENet007, req.URL.Host)
				}
				if req.URL.Host != host {
					return cerr.New(cerr.ENet007, req.URL.Host)
				}
				return nil
			},
		},
		host:     host,
		maxBytes: ai.MaxResponseBytes,
	}, nil
}

// Do performs one AI request.
//
// The key travels in a header, is copied into the request, and is never written
// anywhere else. Every error this function returns has been through ai.Redact,
// because the response body of a failing provider is the one place text this
// program did not write reaches an error message — and providers do echo keys
// back in authentication errors.
func (t *aiTransport) Do(ctx context.Context, req ai.HTTPRequest) (ai.HTTPResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return ai.HTTPResponse{}, cerr.Wrap(cerr.EAi004, err, t.host, "the request could not be built")
	}
	for _, h := range req.Headers {
		httpReq.Header.Set(h[0], h[1])
	}

	resp, err := t.client.Do(httpReq)
	if err != nil {
		// A context deadline is a timeout, which is a network condition rather
		// than a configuration error, and the message says so.
		msg := err.Error()
		if ctx.Err() != nil {
			msg = "the request timed out"
		}
		return ai.HTTPResponse{}, cerr.Wrap(cerr.EAi004, err, t.host, msg)
	}
	defer func() { _ = resp.Body.Close() }()

	// LimitReader plus one byte: reading one byte past the limit is how we tell
	// "exactly at the limit" from "over it" without trusting Content-Length,
	// which a hostile endpoint controls.
	body, err := io.ReadAll(io.LimitReader(resp.Body, t.maxBytes+1))
	if err != nil {
		return ai.HTTPResponse{}, cerr.Wrap(cerr.EAi004, err, t.host, "the response could not be read")
	}
	if int64(len(body)) > t.maxBytes {
		return ai.HTTPResponse{}, cerr.New(cerr.EAi010, humanBytes(t.maxBytes))
	}

	return ai.HTTPResponse{Status: resp.StatusCode, Body: body}, nil
}

// humanBytes renders a byte count for a message. It mirrors the one in
// internal/config, which is L0 and therefore importable — but that one is
// unexported, and exporting it to serve one message in L5 is a worse trade than
// four lines here.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return itoa(int(n>>20)) + " MiB"
	case n >= 1<<10:
		return itoa(int(n>>10)) + " KiB"
	}
	return itoa(int(n)) + " B"
}

// itoa renders a non-negative int without pulling strconv in for one call.
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
