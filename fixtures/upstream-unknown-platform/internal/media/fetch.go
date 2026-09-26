package media

import "os/exec"

// Fetch downloads a stream with a tool that is not in the corpus.
//
// `yt-dlp` is the archetypal case the spec's §1 opens with, and the corpus
// deliberately carries no entry for it. That is not an oversight: the entry
// would have to state terms, and nobody has curated and date-stamped them.
// Writing one from memory would put an unverified citation in front of a user
// who is making a shipping decision.
func Fetch(url, out string) error {
	return exec.Command("yt-dlp", "-o", out, url).Run()
}
