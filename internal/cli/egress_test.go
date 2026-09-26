// TestNoUnexpectedEgress — INV-3's runtime half, and the reason this test is
// not in the guard suite's usual home.
//
// # WHY THIS FILE IS IN internal/cli
//
// Every other guard test lives in internal/ as an external test package, so
// that it can only use exported APIs. This one cannot: the egress switch, the
// client constructor and the redirect policy are unexported, and they must stay
// unexported — a caller that could construct an HTTP client directly would be a
// caller that bypasses the single allowlist.
//
// # WHY IT DOES NOT IMPORT net/http
//
// Reaching into the client's CheckRedirect closure requires building an
// *http.Request, which means importing net/http — and internal/arch_test.go
// pins that import to exactly one file in the whole repository
// (OnlyOneFileImportsNetHTTP), test files included. That rule is INV-3's
// structural enforcement and it is worth more than the convenience of a
// closure-shaped test. So the redirect decision was extracted into
// redirectAllowed, which is a pure function of (hops, host) and is what the
// closure now calls.
//
// Extracting the decision rather than relaxing the rule is the right way round:
// the rule is load-bearing, and a policy that cannot be tested is a policy that
// will rot.
package cli

import (
	"strings"
	"testing"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// TestNoUnexpectedEgress asserts that no outbound call can be constructed or
// followed unless it targets the corpus hosts.
//
// INV-3: "Its only permitted outbound call is the signed corpus update, to a
// fixed host, HTTPS-only, certificate-pinned, and disabled by default."
//
// The test has three parts, and all three are needed:
//
//  1. The switch. With egress unarmed, newHTTPClient must refuse with E-NET-006
//     — the tripwire firing, not a generic failure.
//  2. The allowlist. Even armed, a host that is not a corpus host must be
//     refused, so that a redirect cannot turn an allowlisted fetch into an
//     exfiltration.
//  3. The control. Armed and on an allowlisted host, the client must actually
//     be constructible. Without this, an egress policy that refused everything
//     would pass and the corpus updater would be dead code.
func TestNoUnexpectedEgress(t *testing.T) {
	// Save and restore the process-wide switch. `go test` runs the tests in a
	// package sequentially in one process, so a test that left egress armed
	// would change the meaning of every test that ran after it — and the
	// failure would appear in whichever test happened to be next.
	was := netAllowed
	t.Cleanup(func() { netAllowed = was })

	t.Run("egress is unarmed by default", func(t *testing.T) {
		netAllowed = false
		if NetworkEnabled() {
			t.Fatal("egress is armed in a fresh process; the product must be offline " +
				"by default, and nothing in this build calls EnableNetwork")
		}

		if _, err := newHTTPClient(false); err == nil {
			t.Fatal("newHTTPClient succeeded with egress unarmed.\n" +
				"This is the tripwire that makes INV-3 structural rather than " +
				"aspirational: a code path that tries to phone home must fail, and " +
				"fail with E-NET-006 so the failure is recognisable as the invariant " +
				"firing rather than as a network problem.")
		} else {
			assertCLICode(t, err, cerr.ENet006)
		}

		if err := assertNoEgress(false); err == nil {
			t.Fatal("assertNoEgress passed with egress unarmed")
		} else {
			assertCLICode(t, err, cerr.ENet006)
		}
	})

	t.Run("offline is refused with its own code", func(t *testing.T) {
		// --offline is the user's explicit instruction, and it deserves the
		// specific "expected; no action" explanation rather than the alarming
		// tripwire. Two different codes for two different situations, and this
		// asserts they have not been collapsed into one.
		if _, err := newHTTPClient(true); err == nil {
			t.Fatal("newHTTPClient succeeded with offline requested")
		} else {
			assertCLICode(t, err, cerr.ENet004)
		}
		if err := assertNoEgress(true); err == nil {
			t.Fatal("assertNoEgress passed with offline requested")
		} else {
			assertCLICode(t, err, cerr.ENet004)
		}
	})

	t.Run("only the corpus hosts are reachable", func(t *testing.T) {
		// The allowlist, asserted from the table rather than from a hardcoded
		// expectation, so that adding a host to corpusHosts without thinking
		// about it shows up here.
		if len(corpusHosts) == 0 {
			t.Fatal("the corpus host allowlist is empty; the corpus updater could " +
				"never work, and this guard would pass by checking nothing")
		}
		for host := range corpusHosts {
			if !strings.HasSuffix(host, ".clearance.dev") {
				t.Errorf("the allowlist admits %q, which is not under clearance.dev.\n"+
					"Every host on this list is a host the binary will connect to "+
					"and follow redirects to. A domain the project does not control "+
					"is an exfiltration target.", host)
			}
		}

		for host := range corpusHosts {
			if err := redirectAllowed(0, host); err != nil {
				t.Errorf("redirectAllowed(%q) = %v; an allowlisted host must be "+
					"reachable or the list is a lie", host, err)
			}
		}

		hostile := []string{
			"evil.example",
			"clearance.dev",                     // the parent domain is not on the list
			"corpus.clearance.dev.evil.example", // a suffix that starts with a real host
			"evilclearance.dev",
			"corpus.clearance.dev.", // trailing dot
			"",                      // empty
			"localhost",
			"127.0.0.1",
			"metadata.google.internal", // the classic cloud metadata endpoint
			"169.254.169.254",
		}
		for _, host := range hostile {
			if err := redirectAllowed(0, host); err == nil {
				t.Errorf("redirectAllowed(%q) succeeded.\n"+
					"A redirect is the classic way an allowlisted fetch becomes an "+
					"exfiltration: the corpus host is trusted, so a 302 to anywhere "+
					"else would be followed silently.", host)
			} else {
				assertCLICode(t, err, cerr.ENet007)
			}
		}
	})

	t.Run("a redirect chain is bounded", func(t *testing.T) {
		// Even an allowlisted host must not bounce the client indefinitely.
		// Each hop is another chance to be pointed somewhere unexpected, and
		// the bound is the only thing that stops a loop.
		if err := redirectAllowed(maxRedirectHops-1, "corpus.clearance.dev"); err != nil {
			t.Errorf("hop %d was refused; the bound is exclusive, not inclusive: %v",
				maxRedirectHops-1, err)
		}
		if err := redirectAllowed(maxRedirectHops, "corpus.clearance.dev"); err == nil {
			t.Errorf("hop %d was allowed; the redirect chain is unbounded", maxRedirectHops)
		} else {
			assertCLICode(t, err, cerr.ENet007)
		}
		if maxRedirectHops <= 0 {
			t.Error("maxRedirectHops is not positive")
		}
	})

	t.Run("arming egress allows the allowlisted host only", func(t *testing.T) {
		// The control, and the only place the switch is turned on. It proves
		// the refusals above are the policy working rather than the code being
		// unable to construct a client at all.
		netAllowed = false
		EnableNetwork()
		if !NetworkEnabled() {
			t.Fatal("EnableNetwork did not arm egress")
		}
		c, err := newHTTPClient(false)
		if err != nil {
			t.Fatalf("newHTTPClient failed after EnableNetwork: %v", err)
		}
		if c == nil {
			t.Fatal("newHTTPClient returned a nil client and a nil error")
		}
		if c.CheckRedirect == nil {
			t.Fatal("the client has no CheckRedirect; an allowlisted fetch would " +
				"follow a redirect to anywhere")
		}
		if c.Timeout <= 0 {
			t.Error("the client has no timeout; an unresponsive host would hang the " +
				"scan rather than degrade")
		}
	})
}

// assertCLICode asserts that err carries the given cerr code. It is a local
// copy of the helper in the guard suite because that suite is an external test
// package and cannot share unexported helpers across the package boundary.
func assertCLICode(t *testing.T, err error, want cerr.Code) {
	t.Helper()
	e, ok := cerr.As(err)
	if !ok {
		t.Fatalf("expected %s, got an untyped error: %v", want, err)
	}
	if e.Code() != want {
		t.Fatalf("got %s (%v), want %s", e.Code(), err, want)
	}
}
