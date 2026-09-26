package jobs

import "os/exec"

// Submit hands a job to a third-party service through its CLI.
func Submit(job string) error {
	return exec.Command("staletool", "submit", job).Run()
}
