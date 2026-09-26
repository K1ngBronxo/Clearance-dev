package transcode

// This package deliberately contains no process spawn.
//
// The name below appears in prose, in a comment, and inside a string that is
// never executed. A detector that matched the bare token would report a
// dependency on ffmpeg for this package. A detector that matches the *call*
// reports nothing, and that difference is the whole reason §3.2 of the
// detection spec insists on parsing rather than grepping.
//
// For reference, the call this package does not make is:
//
//	exec.Command("ffmpeg", "-i", in, "-c:v", "libx264", out)
//
// The line above is the exact syntax the detector looks for, sitting in a
// comment where it must be invisible.

import "fmt"

// unavailable is the message a caller gets when ffmpeg is missing.
const unavailable = "ffmpeg is not installed; install it and retry"

// ErrUnavailable is returned when the transcoder cannot run.
var ErrUnavailable = fmt.Errorf("%s", unavailable)
