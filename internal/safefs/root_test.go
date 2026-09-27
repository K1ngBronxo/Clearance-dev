package safefs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheckContainedRejectsEscapes is the guard for INV-4, the filesystem
// boundary. It tests containment directly rather than through a real symlink,
// because a real symlink cannot be created in every environment — see the note
// in TestCheckContainedSharedPrefix for the trap that makes this test worth
// having anyway.
func TestCheckContainedRejectsEscapes(t *testing.T) {
	base := t.TempDir()
	r := &Root{abs: base}

	cases := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"the root itself", base, false},
		{"a child", filepath.Join(base, "a"), false},
		{"a nested child", filepath.Join(base, "a", "b"), false},
		{"the parent", filepath.Dir(base), true},
		{"a sibling", filepath.Join(filepath.Dir(base), "sibling"), true},
		{"a grandparent", filepath.Dir(filepath.Dir(base)), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.checkContained("rel", tc.target)
			if (err != nil) != tc.wantErr {
				t.Errorf("checkContained(%q) returned err=%v, wantErr=%v", tc.target, err, tc.wantErr)
			}
		})
	}
}

// TestCheckContainedSharedPrefix is the case a string-prefix check gets wrong.
//
// A root of "/tmp/001" and a sibling "/tmp/0010" share a textual prefix, so
// `strings.HasPrefix(target, root)` accepts the sibling and the boundary is
// breached. That is why the implementation uses filepath.Rel and compares the
// result against "..". This test exists to fail if anyone "simplifies" it back
// to a prefix comparison.
func TestCheckContainedSharedPrefix(t *testing.T) {
	base := t.TempDir()
	r := &Root{abs: base}

	sibling := base + "0"
	if err := r.checkContained("rel", sibling); err == nil {
		t.Fatalf("checkContained accepted %q for root %q: a shared textual prefix is not containment", sibling, base)
	}

	// And the positive control, so the test cannot pass by rejecting everything.
	if err := r.checkContained("rel", filepath.Join(base, "0")); err != nil {
		t.Errorf("checkContained rejected a real child: %v", err)
	}
}

// TestResolveRejectsAbsoluteAndDrives covers the first line of defence: input
// that is not a project-relative path is refused before any containment check.
func TestResolveRejectsAbsoluteAndDrives(t *testing.T) {
	base := t.TempDir()
	r, err := New(base, Limits{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := os.WriteFile(filepath.Join(base, "ok.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	bad := []string{
		"/etc/passwd",
		"../outside",
		"a/../../outside",
		`C:\Windows\System32\drivers\etc\hosts`,
	}
	for _, rel := range bad {
		if _, err := r.Resolve(rel); err == nil {
			t.Errorf("Resolve(%q) was accepted; every one of these leaves the root", rel)
		}
	}

	if _, err := r.Resolve("ok.txt"); err != nil {
		t.Errorf("Resolve(%q) failed for a legitimate path: %v", "ok.txt", err)
	}
}

// TestReadFileRefusesOversize proves the size bound is applied BEFORE the read,
// so a 2 GB "LICENSE" file is refused rather than loaded.
func TestReadFileRefusesOversize(t *testing.T) {
	base := t.TempDir()
	r, err := New(base, Limits{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	big := make([]byte, 4096)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(filepath.Join(base, "big.txt"), big, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := r.ReadFile("big.txt", 1024); err == nil {
		t.Error("ReadFile returned data for a file larger than the limit")
	}
	if _, err := r.ReadFile("big.txt", 8192); err != nil {
		t.Errorf("ReadFile failed within the limit: %v", err)
	}
}

// TestWalkIsDeterministic: the same tree must produce the same inventory in the
// same order, because everything downstream depends on it (INV-6).
func TestWalkIsDeterministic(t *testing.T) {
	base := t.TempDir()
	for _, n := range []string{"z.txt", "a.txt", "m/inner.txt", "m/b.txt"} {
		abs := filepath.Join(base, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	r, err := New(base, Limits{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first, _, err := r.Walk()
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	r2, err := New(base, Limits{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	second, _, err := r2.Walk()
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if len(first) != len(second) {
		t.Fatalf("walk lengths differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Rel != second[i].Rel {
			t.Errorf("entry %d: %q vs %q", i, first[i].Rel, second[i].Rel)
		}
	}
	for i := 1; i < len(first); i++ {
		if first[i-1].Rel > first[i].Rel {
			t.Errorf("entries are not sorted: %q before %q", first[i-1].Rel, first[i].Rel)
		}
	}
}

// TestNewRefusesAMissingRoot: pointing Clearance at a path that does not exist
// must fail clearly (E-SCAN-001) rather than producing an empty graph.
func TestNewRefusesAMissingRoot(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "does-not-exist"), Limits{}); err == nil {
		t.Error("New accepted a path that does not exist")
	}
}

// TestNewRefusesAFile: the root must be a directory.
func TestNewRefusesAFile(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(file, Limits{}); err == nil {
		t.Error("New accepted a regular file as a root")
	}
}

// TestRelAcceptsADifferentlySpelledInRootPath is the regression test for the
// host-canonicalisation bug that CI found on windows-latest and macos-latest
// while passing on ubuntu-latest.
//
// Rel compares its argument to the root as strings, and New canonicalises the
// root with EvalSymlinks. An absolute path a caller obtained from elsewhere is
// spelled the way its host spells it, which is not always the way the root is
// stored: macOS reports /var/folders/... for a root resolved to
// /private/var/folders/..., and Windows reports the 8.3 short form
// (C:\Users\RUNNER~1\...) for a root resolved to the long one. Rel then
// reported "outside" for a file that is demonstrably inside, which refuses a
// legitimate MCP request and makes configPathFor fall back to the raw absolute
// path — the machine-path leak that function exists to prevent.
//
// The CI failure was real but unreproducible on a machine whose temp path has
// no alternate spelling, so the case is built here out of a symlink, which
// every host has: `link` and `real` are the same directory under two names,
// which is exactly the relationship /var has to /private/var. Without the fix
// this fails everywhere, not only where the bug was first seen.
func TestRelAcceptsADifferentlySpelledInRootPath(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "license.txt"), []byte("MIT"), 0o644); err != nil {
		t.Fatal(err)
	}

	root, err := New(real, Limits{})
	if err != nil {
		t.Fatalf("New(%q): %v", real, err)
	}

	// The negative first, so it is asserted even where the symlink cannot be
	// made and the rest of this test is skipped.
	if _, ok := root.Rel(filepath.Join(base, "elsewhere", "license.txt")); ok {
		t.Error("Rel accepted a path outside the root")
	}

	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlinks on this machine (%v); the escape "+
			"assertion above still ran", err)
	}
	if _, statErr := os.Lstat(link); statErr != nil {
		t.Skipf("os.Symlink reported success but created nothing; "+
			"verified with Lstat: %v", statErr)
	}

	// The same file, under the other name. It is the same directory, so this
	// is inside the root however it is spelled.
	spelled := filepath.Join(link, "license.txt")
	rel, ok := root.Rel(spelled)
	if !ok {
		t.Errorf("Rel(%q) reported the file outside the root, but %q and %q "+
			"are the same directory.\nAn absolute path spelled the way its host "+
			"spells it is the ordinary case, not a hostile one.", spelled, link, real)
	} else if rel != "license.txt" {
		t.Errorf("Rel(%q) = %q, want \"license.txt\"", spelled, rel)
	}

	// A file that is not there yet is the other half of the same question, and
	// the first version of this fix answered it wrongly: it canonicalised the
	// argument with EvalSymlinks, which fails outright on a path that does not
	// exist, so every path to a file that had not been written yet was reported
	// as outside the root. Both callers ask about paths that may be missing.
	if rel, ok := root.Rel(filepath.Join(link, "not-written-yet.txt")); !ok {
		t.Error("Rel reported a path to a file that does not exist yet as " +
			"outside the root; it is the link that has to be resolved, not the file")
	} else if rel != "not-written-yet.txt" {
		t.Errorf("Rel(not-written-yet.txt) = %q, want \"not-written-yet.txt\"", rel)
	}

	// Canonicalising the argument must not turn a genuine escape into an
	// accept: reached through the same link, a path that leaves the root still
	// leaves it after resolution.
	outside := filepath.Join(base, "elsewhere", "secret.txt")
	if err := os.Mkdir(filepath.Dir(outside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rel, ok := root.Rel(filepath.Join(link, "..", "elsewhere", "secret.txt")); ok {
		t.Errorf("Rel reported %q for a path that leaves the root through a link", rel)
	}
}
