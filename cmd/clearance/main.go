// Command clearance is the process entry point.
//
// It is deliberately three lines. Everything the program does lives in
// internal/cli, where it can be called from a test with a buffer instead
// of a terminal — because a CLI whose logic is only reachable by running the
// binary is a CLI whose exit codes are only tested by accident.
//
// Clearance — licence, model-weights and platform-terms clearance.
// By K1NGBRONXO.
package main

import (
	"os"

	"github.com/clearance-dev/clearance/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
