// Package safefs is the filesystem security boundary (control C3, INV-4).
//
// INV-4: "The scanner may not read outside the project root. Symlinks are
// resolved and validated before any read. Path traversal is a hard error, not
// a warning."
//
// # WHY THIS IS A PACKAGE AND NOT A HELPER
//
// The scanner walks trees it does not trust: a vendored dependency is
// attacker-controlled input. If any code path could open an arbitrary file,
// Clearance would be a file-read primitive that an attacker could aim with a
// crafted repository — and it would be running inside the victim's CI, with the
// victim's credentials in the environment. Every read therefore goes through
// exactly one function, and the containment check happens *after* symlink
// resolution, because a check against the link is bypassable by the link.
//
// `os.Open`, `os.ReadFile` and `os.ReadDir` on project input are banned
// everywhere else in internal/ by the linter and by internal/arch_test.go.
package safefs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// Limits bounds every dimension of the walk. A limit is not a suggestion: each
// one has a corresponding degrade code so the user is told what was skipped.
type Limits struct {
	MaxFiles      int   // default 200_000
	MaxDepth      int   // default 24
	MaxFileSize   int64 // default 8 MiB — larger files are recorded, never parsed
	MaxTotalBytes int64 // default 512 MiB — a total read budget
}

// DefaultLimits are the values the plan specifies. They are also the zero-value
// fallback, so a caller that forgets to set them gets the safe defaults rather
// than an unbounded walk.
func DefaultLimits() Limits {
	return Limits{
		MaxFiles:      200_000,
		MaxDepth:      24,
		MaxFileSize:   8 << 20,
		MaxTotalBytes: 512 << 20,
	}
}

// withDefaults fills any zero field with the documented default. This is what
// makes an accidentally-zero Limits safe instead of infinite.
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFiles <= 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxFileSize <= 0 {
		l.MaxFileSize = d.MaxFileSize
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = d.MaxTotalBytes
	}
	return l
}

// Root is a project root that has been validated once, at construction.
//
// It carries the read budget counters, so a walk cannot exceed its allowance
// by looping. All counters are atomic because the walk is parallel; nothing
// else in the scanner is.
type Root struct {
	abs    string
	limits Limits

	filesSeen    atomic.Int64
	filesSkipped atomic.Int64
	bytesRead    atomic.Int64
	dirsVisited  atomic.Int64
	maxDepthSeen atomic.Int64
	truncated    atomic.Bool
}

// New validates a path and returns a Root. The path must exist and be a
// directory; it is made absolute and its symlinks are resolved *once*, so that
// every later containment check compares two canonical paths.
func New(path string, limits Limits) (*Root, error) {
	if path == "" {
		path = "."
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, cerr.Wrap(cerr.EScan001, err, path)
	}
	// Resolve the root itself. If the user points Clearance at a symlink to a
	// directory, that is legitimate; what is forbidden is a *child* symlink
	// escaping the root.
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, cerr.New(cerr.EScan001, path)
		}
		return nil, cerr.Wrap(cerr.EScan002, err, path)
	}
	st, err := os.Stat(resolved)
	if err != nil {
		if os.IsPermission(err) {
			return nil, cerr.Wrap(cerr.EScan002, err, path)
		}
		return nil, cerr.Wrap(cerr.EScan001, err, path)
	}
	if !st.IsDir() {
		return nil, cerr.New(cerr.EScan001, path)
	}
	// A readability probe up front. Better to fail once, clearly, than to
	// discover it 40,000 files in.
	f, err := os.Open(resolved)
	if err != nil {
		return nil, cerr.Wrap(cerr.EScan002, err, path)
	}
	_ = f.Close()

	return &Root{abs: filepath.Clean(resolved), limits: limits.withDefaults()}, nil
}

// Abs returns the canonical absolute root. It is used for display and for
// computing project-relative evidence paths; it is never joined with untrusted
// input outside Resolve.
func (r *Root) Abs() string { return r.abs }

// Limits returns the effective limits.
func (r *Root) Limits() Limits { return r.limits }

// Resolve turns a project-relative path into a canonical absolute path, and
// refuses anything that leaves the root.
//
// The order matters and is not negotiable:
//
//  1. join and clean (lexical)
//  2. resolve symlinks on the *existing prefix* (the real path)
//  3. containment check against the canonical root
//
// A missing file is not an escape; it is reported as such by the caller. Only
// an actual containment failure produces E-SCAN-004.
func (r *Root) Resolve(rel string) (string, error) {
	if rel == "" {
		return "", cerr.New(cerr.EScan001, rel)
	}
	// Reject absolute paths outright rather than silently re-rooting them: a
	// caller passing "/etc/passwd" has a bug, and silently turning it into
	// "<root>/etc/passwd" would hide that bug.
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "\\") {
		return "", cerr.New(cerr.EScan004, rel, rel)
	}
	if hasDriveLetter(rel) {
		return "", cerr.New(cerr.EScan004, rel, rel)
	}

	joined := filepath.Clean(filepath.Join(r.abs, filepath.FromSlash(rel)))

	resolved, err := resolveExisting(joined)
	if err != nil {
		return "", err
	}
	if err := r.checkContained(rel, resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// checkContained is the containment check. It uses filepath.Rel rather than a
// string prefix because Rel handles Windows case-insensitivity and volume
// names correctly, whereas a prefix check does not.
func (r *Root) checkContained(rel, resolved string) error {
	back, err := filepath.Rel(r.abs, resolved)
	if err != nil {
		return cerr.New(cerr.EScan004, rel, resolved)
	}
	if back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return cerr.New(cerr.EScan004, rel, resolved)
	}
	return nil
}

// resolveExisting resolves symlinks on the longest existing prefix of a path,
// leaving the non-existent tail untouched. This matters because a missing file
// still has to be containment-checked, and filepath.EvalSymlinks fails outright
// on a path that does not exist.
func resolveExisting(abs string) (string, error) {
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved), nil
	}
	dir := filepath.Dir(abs)
	base := filepath.Base(abs)
	// Walk up until we find something that exists. The loop is bounded by the
	// path length, and each iteration strictly shortens the path.
	for i := 0; i < 256; i++ {
		if dir == filepath.Dir(dir) {
			break
		}
		resolvedDir, err := filepath.EvalSymlinks(dir)
		if err == nil {
			return filepath.Clean(filepath.Join(resolvedDir, base)), nil
		}
		base = filepath.Join(filepath.Base(dir), base)
		dir = filepath.Dir(dir)
	}
	// Nothing on the path exists. Return the lexically cleaned path; the
	// containment check still applies to it, and the caller's Open will fail
	// with a not-exist error, which is the correct outcome.
	return filepath.Clean(abs), nil
}

// Open opens a project file read-only, with every bound applied.
//
// It is the ONLY sanctioned way to read project input. The size check happens
// before the open, so a 2 GB "LICENSE" file is refused without being read.
func (r *Root) Open(rel string) (io.ReadCloser, error) {
	abs, err := r.Resolve(rel)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(abs)
	if err != nil {
		if os.IsPermission(err) {
			return nil, cerr.Wrap(cerr.EScan007, err, rel)
		}
		return nil, cerr.Wrap(cerr.EScan007, err, rel)
	}
	if st.IsDir() {
		return nil, cerr.New(cerr.EScan007, rel)
	}
	if st.Size() > r.limits.MaxFileSize {
		return nil, cerr.New(cerr.EScan006, rel, HumanBytes(st.Size()))
	}
	if !r.spendBytes(st.Size()) {
		return nil, cerr.New(cerr.EScan006, rel, HumanBytes(st.Size()))
	}
	f, err := os.Open(abs)
	if err != nil {
		if os.IsPermission(err) {
			return nil, cerr.Wrap(cerr.EScan007, err, rel)
		}
		return nil, cerr.Wrap(cerr.EScan007, err, rel)
	}
	return f, nil
}

// ReadFile reads a whole project file, subject to the same bounds as Open plus
// an explicit cap so that a caller cannot ask for more than the file limit.
func (r *Root) ReadFile(rel string, max int64) ([]byte, error) {
	if max <= 0 || max > r.limits.MaxFileSize {
		max = r.limits.MaxFileSize
	}
	abs, err := r.Resolve(rel)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(abs)
	if err != nil {
		return nil, cerr.Wrap(cerr.EScan007, err, rel)
	}
	if st.IsDir() {
		return nil, cerr.New(cerr.EScan007, rel)
	}
	if st.Size() > max {
		return nil, cerr.New(cerr.EScan006, rel, HumanBytes(st.Size()))
	}
	if !r.spendBytes(st.Size()) {
		return nil, cerr.New(cerr.EScan006, rel, HumanBytes(st.Size()))
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		if os.IsPermission(err) {
			return nil, cerr.Wrap(cerr.EScan007, err, rel)
		}
		return nil, cerr.Wrap(cerr.EScan007, err, rel)
	}
	// The file may have grown between the stat and the read. Trust the smaller
	// of the two, and never hand back more than the caller asked for.
	if int64(len(b)) > max {
		b = b[:max]
	}
	return b, nil
}

// ReadAbsFile reads one file at an absolute path that lies outside any Root.
//
// # WHY THIS EXISTS, AND WHY IT IS NOT A HOLE IN INV-4
//
// INV-4 is "every read is root-scoped", and its purpose is that a scanned
// repository must never be able to make the tool open something else. This
// function is for the reads that are not part of a scan at all: the BYOK key
// file, which deliberately lives outside the project, in a per-user directory
// the user named.
//
// That read was happening anyway, through os.ReadFile in internal/cli. The
// effect was that the one function that opens files was no longer the one place
// that opens files, and `make lint` — which bans os.ReadFile outside this
// package precisely to keep INV-4 checkable by reading a grep — could not pass.
//
// So the rule is kept whole by keeping the exception inside it. The caller names
// an absolute path and this function applies the same size cap a root-scoped
// read does. What it cannot do is check containment, because there is no root to
// be contained in — which is why the one caller takes its path from a fixed
// per-user location and never from anything inside the scanned tree.
//
// # WHY exists IS RETURNED RATHER THAN FOLDED INTO THE ERROR
//
// Because "the file is not there" is the ordinary case for this caller: a key
// may come from the environment or from stdin instead, and an absent keys.yml is
// not a failure. Recovering that fact from the error chain would mean depending
// on how the wrap preserves fs.ErrNotExist, which is a subtle thing to depend on
// for the difference between "no key configured" and "your key file is
// unreadable". A separate bool says it outright.
//
// display is what an error message names. It is separate from abs because an
// absolute path in a message is what the privacy spine forbids (see
// TestNoAbsolutePathsInOutput), so the caller passes a short human name and the
// machine's directory prefix never reaches the output.
func ReadAbsFile(abs, display string, max int64) (data []byte, exists bool, err error) {
	if max <= 0 {
		max = DefaultLimits().MaxFileSize
	}
	st, statErr := os.Lstat(abs)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return nil, false, nil
		}
		return nil, false, cerr.Wrap(cerr.EScan007, statErr, display)
	}
	if st.IsDir() {
		return nil, true, cerr.New(cerr.EScan007, display)
	}
	if st.Size() > max {
		return nil, true, cerr.New(cerr.EScan006, display, HumanBytes(st.Size()))
	}
	b, readErr := os.ReadFile(abs)
	if readErr != nil {
		return nil, true, cerr.Wrap(cerr.EScan007, readErr, display)
	}
	// The file may have grown between the stat and the read. Never hand back
	// more than the caller asked for.
	if int64(len(b)) > max {
		b = b[:max]
	}
	return b, true, nil
}

// ReadFilePrefix reads at most n bytes. Used for licence fingerprinting, which
// reads the first 4 KiB and must never read a whole file to do it.
func (r *Root) ReadFilePrefix(rel string, n int64) ([]byte, error) {
	abs, err := r.Resolve(rel)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(abs)
	if err != nil {
		if os.IsPermission(err) {
			return nil, cerr.Wrap(cerr.EScan007, err, rel)
		}
		return nil, cerr.Wrap(cerr.EScan007, err, rel)
	}
	defer f.Close()
	if !r.spendBytes(n) {
		return nil, cerr.New(cerr.EScan006, rel, HumanBytes(n))
	}
	buf := make([]byte, n)
	read, err := io.ReadFull(f, buf)
	// errors.Is, not !=: a wrapped EOF is still an EOF, and treating one as a
	// real failure would turn a short read into a false E-SCAN-007.
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, cerr.Wrap(cerr.EScan007, err, rel)
	}
	return buf[:read], nil
}

// Stat returns metadata for a project path without following a final symlink.
func (r *Root) Stat(rel string) (fs.FileInfo, error) {
	abs, err := r.Resolve(rel)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(abs)
	if err != nil {
		if os.IsPermission(err) {
			return nil, cerr.Wrap(cerr.EScan007, err, rel)
		}
		return nil, cerr.Wrap(cerr.EScan007, err, rel)
	}
	return st, nil
}

// Rel converts an absolute path back to a project-relative, forward-slashed
// path for use in Evidence. It returns false if the path is outside the root,
// which can only happen if the caller obtained it by some other means.
func (r *Root) Rel(abs string) (string, bool) {
	back, err := filepath.Rel(r.abs, abs)
	if err != nil {
		return "", false
	}
	if back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(back), true
}

// ── budget accounting ────────────────────────────────────────────────────────

// spendBytes charges the read budget. It returns false when the budget is
// exhausted, which the caller reports as E-SCAN-006 for the file and sets the
// truncation flag for the run.
func (r *Root) spendBytes(n int64) bool {
	if n < 0 {
		return false
	}
	total := r.bytesRead.Add(n)
	if total > r.limits.MaxTotalBytes {
		r.truncated.Store(true)
		return false
	}
	return true
}

func (r *Root) chargeFile() bool {
	seen := r.filesSeen.Add(1)
	if int(seen) > r.limits.MaxFiles {
		r.truncated.Store(true)
		return false
	}
	return true
}

// Counters returns the walk statistics. It is read once, after the walk, by the
// scanner, which copies the numbers into graph.Stats.
func (r *Root) Counters() (filesSeen, filesSkipped int, bytesRead int64, dirsVisited, maxDepth int, truncated bool) {
	return int(r.filesSeen.Load()),
		int(r.filesSkipped.Load()),
		r.bytesRead.Load(),
		int(r.dirsVisited.Load()),
		int(r.maxDepthSeen.Load()),
		r.truncated.Load()
}

// ── helpers ──────────────────────────────────────────────────────────────────

// hasDriveLetter reports whether a relative path starts with a Windows volume
// designator ("C:"). Such a path is absolute on Windows even though
// filepath.IsAbs may disagree depending on the current directory.
func hasDriveLetter(p string) bool {
	if len(p) < 2 {
		return false
	}
	c := p[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return false
	}
	return p[1] == ':'
}

// HumanBytes renders a byte count the way the error taxonomy's messages show
// it: "2.1 GB", "512 KiB". Binary units, one decimal, never a float for a
// count of things (only for a size, where it is a display convenience).
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return itoa(n) + " B"
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n)
	for i, u := range units {
		v /= unit
		if v < unit || i == len(units)-1 {
			return trimFloat(v) + " " + u
		}
	}
	return itoa(n) + " B"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func trimFloat(v float64) string {
	// One decimal place, no trailing ".0" for whole numbers.
	whole := int64(v)
	frac := int64((v - float64(whole)) * 10)
	if frac == 0 {
		return itoa(whole)
	}
	return itoa(whole) + "." + itoa(frac)
}
