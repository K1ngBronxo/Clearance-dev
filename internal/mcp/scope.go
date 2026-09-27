package mcp

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/safefs"
)

// resolveInRoot resolves a path a client sent against the declared workspace
// root, and refuses anything that leaves it.
//
// # THIS FUNCTION IS C9
//
// C9 is "capability-scoped
// MCP server" against "elevation of privilege", mitigated by the capability
// boundary. This is that boundary, and it is deliberately the only way a tool
// in this package obtains a path.
//
// The threat is not that the client is malicious — usually it is an agent
// doing its best. The threat is that an agent which can read a project through
// Clearance can be *talked into* reading something else: a prompt in a README,
// a task description, a tool result. An MCP server that accepted an arbitrary
// path would be a file-read primitive reachable from whatever text the agent
// happened to process, which is a confused deputy with a licence checker for a
// face. Scoping to the root the operator started the server in is what makes
// that impossible rather than merely discouraged.
//
// # WHY ABSOLUTE AND RELATIVE PATHS TAKE DIFFERENT ROUTES
//
// A relative path is resolved by safefs, which already refuses a traversal —
// `../../etc/passwd` is E-SCAN-004 there. An absolute path never reaches
// safefs's resolver in a useful way, so it is checked with safefs.Rel, which
// answers "is this inside the root?" without resolving anything. Both routes
// end at the same refusal.
//
// The refusal is returned as E-MCP-001 rather than E-SCAN-004 because the two
// are different events to a reader: E-SCAN-004 is "your project has a symlink
// that points outside it, which is a fact about your project", and E-MCP-001 is
// "your agent asked for a file it was not given, which is a fact about the
// request". Reporting the second as the first would send someone looking at
// their repository.
func resolveInRoot(root *safefs.Root, requested string) (string, error) {
	req := strings.TrimSpace(requested)
	if req == "" {
		// An empty path means the root itself, which is the common case: an
		// agent checking the project it is already in.
		return root.Abs(), nil
	}

	if filepath.IsAbs(req) {
		abs := filepath.Clean(req)
		if _, ok := root.Rel(abs); !ok {
			return "", cerr.New(cerr.EMcp001, displayable(req))
		}
		return abs, nil
	}

	resolved, err := root.Resolve(req)
	if err != nil {
		// safefs refused it. Either it escapes the root or it does not exist;
		// both are E-MCP-001 from the client's point of view, because both mean
		// "you may not have this".
		return "", cerr.New(cerr.EMcp001, displayable(req))
	}
	return resolved, nil
}

// displayable renders a path for an error message without leaking the absolute
// prefix of the machine it ran on.
//
// # WHY THIS IS NOT PARANOIA
//
// The refusal message travels back through the protocol to a client that may
// log it, and from there into a ticket. `C:\Users\kate\work\...` in a shared
// log is a small privacy leak that the product's own privacy spine forbids
// elsewhere, and there is no reason for this message to be the exception. The
// last two segments are enough for a human to recognise what was asked for, and
// the ellipsis makes it obvious that something was elided rather than implying
// the path was relative.
func displayable(p string) string {
	// Both separators are folded to "/" and cleaned with the OS-independent
	// path package, not filepath. filepath.ToSlash only converts the separator
	// of the host it is compiled for, so on Linux a Windows-style path was
	// returned untouched and the prefix this function exists to drop survived.
	clean := path.Clean(strings.ReplaceAll(p, `\`, "/"))
	if len(clean) <= 1 {
		return clean
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	if len(parts) <= 2 {
		return clean
	}
	return "…/" + strings.Join(parts[len(parts)-2:], "/")
}
