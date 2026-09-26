package run

import "os/exec"

// Run spawns whatever tool the caller names.
//
// The command name arrives in a variable, so no detector can tell what runs
// here. This is the case the spec's §3.1 calls out: a dynamically-constructed
// command cannot be attributed to a platform, and attributing it anyway would
// be a guess.
func Run(tool string, args ...string) error {
	return exec.Command(tool, args...).Run()
}
