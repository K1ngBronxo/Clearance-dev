package jobs

import "os/exec"

// Submit hands a job to a third-party service through its CLI.
//
// The spawn is what inherits the platform's terms; nothing in this file or its
// lockfile mentions the vendor. See upstream-stale-tos, whose submit.go is
// byte-identical apart from the binary name.
func Submit(job string) error {
	return exec.Command("freshtool", "submit", job).Run()
}
