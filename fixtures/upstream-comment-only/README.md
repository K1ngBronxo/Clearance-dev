# mentions

A package that documents an integration it does not have.

## Requirements

You will need `ffmpeg` on your PATH. If you wanted to call it, you would write
`exec.Command("ffmpeg", "-i", in, "-c:v", "libx264", out)` — but this package
does not, and neither does anything it depends on.

We also evaluated `yt-dlp` and `npx firecrawl` and decided against both. Those
decisions are recorded here and nowhere else.
