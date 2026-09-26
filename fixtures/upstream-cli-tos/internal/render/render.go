package render

import "os/exec"

// Transcode re-encodes a clip with the ffmpeg binary the host provides.
//
// FFmpeg is not vendored, not imported and not linked: the process is spawned
// by name and the operating system finds it. It appears in no lockfile and in
// no SBOM, which is why a code-licence scanner reports nothing at all here and
// this layer does.
func Transcode(in, out string) error {
	return exec.Command("ffmpeg", "-i", in, "-c:v", "libx264", out).Run()
}
