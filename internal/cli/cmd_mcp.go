package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/mcp"
)

// runMCP is the `clearance mcp` family. Today it has one member, `serve`.
//
// # WHY THE CORPUS IS RESOLVED HERE RATHER THAN IN internal/mcp
//
// Because resolution reads the environment and probes the filesystem, and the
// MCP package is deliberately a pure server: it is handed everything it needs
// and resolves nothing. That is what makes it testable from a buffer with no
// environment at all, and it is the same division of labour the arch guard's
// purity comment describes — the L5 caller does the I/O.
//
// # WHY THIS IS A SUBCOMMAND RATHER THAN A FLAG
//
// `clearance mcp serve` rather than `clearance --mcp`. The interface contract
// fixes the shape,
// and the shape is right for a reason that is not cosmetic: a server has no
// verdict, no exit-on-blocker and no output file, so every flag `check` accepts
// would be a flag this command silently ignores.
func runMCP(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, mcpUsage)
		return cerr.ExitOK
	}

	switch args[0] {
	case "serve":
		return runMCPServe(args[1:], stdin, stdout, stderr)
	case "help", "--help", "-h":
		fmt.Fprint(stdout, mcpUsage)
		return cerr.ExitOK
	}

	fmt.Fprintf(stderr, "clearance: unknown mcp subcommand %q\n\n", args[0])
	fmt.Fprint(stderr, mcpUsage)
	return cerr.ExitConfig
}

// runMCPServe starts the server on stdin/stdout and runs until the stream ends.
//
// # WHY THE ROOT DEFAULTS TO THE WORKING DIRECTORY
//
// Because that is the scope the operator meant when they ran the command. The
// alternative — defaulting to the filesystem root — would make the capability
// declaration meaningless, and the alternative of requiring an explicit --root
// would make the common case (an agent checking the project it is already in)
// an error.
//
// # WHY stdout IS THE PROTOCOL AND stderr IS THE LOG
//
// Because a single stray byte on stdout corrupts the JSON-RPC stream and the
// client sees a parse error rather than the message. Every human-readable line
// this command produces goes to stderr, including the startup banner, and the
// banner is only printed when stderr is not the stream the client is reading —
// which, for a stdio server, is always.
func runMCPServe(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("clearance mcp serve")
	corpusFlag := fs.String("corpus", "", "")
	root := fs.String("root", ".", "")
	today := fs.String("today", "", "")
	quiet := fs.Bool("quiet", false, "")
	if code, ok := parseFlags(fs, args, stdout, stderr, mcpServeUsage); !ok {
		return code
	}

	corpusPath, tried := resolveCorpusDir(*corpusFlag)
	if corpusPath == "" {
		return fail(stderr, cerr.New(cerr.ECorpus001, strings.Join(tried, "; ")))
	}

	// The date is injected rather than read inside the server, so that the
	// evaluation is a pure function of its inputs (INV-6). An operator who
	// needs to reproduce a verdict from last month passes the date it was
	// produced on.
	day := strings.TrimSpace(*today)
	if day == "" {
		day = time.Now().UTC().Format("2006-01-02")
	}

	srv, err := mcp.New(mcp.Options{
		Root:       *root,
		CorpusDir:  corpusPath,
		Today:      day,
		Version:    Version,
		Commit:     Commit,
		Provenance: Provenance,
	})
	if err != nil {
		return fail(stderr, err)
	}

	if !*quiet {
		fmt.Fprintf(stderr, "clearance mcp serve — corpus v%s, root %s, protocol %s\n",
			srv.Corpus().Version, srv.Root(), mcp.ProtocolVersion())
		fmt.Fprintf(stderr, "  capability: fs.read, scoped to the root above\n")
	}

	if err := srv.Serve(stdin, stdout); err != nil {
		return fail(stderr, err)
	}
	return cerr.ExitOK
}
