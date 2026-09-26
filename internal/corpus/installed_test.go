package corpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// These tests pin the routing decision in LoadInstalled, which is the fix for a
// defect that made the released binary unusable: `check` called Load (YAML
// source tree only), so a release — whose corpus/ holds a compiled *signed*
// bundle and no YAML — was handed a directory it could not parse and refused it
// with E-CORPUS-001 "corpus not found". The signature machinery in bundle.go was
// correct, tested, and never on the path a user's verdict travelled.
//
// A test that only asserted "LoadInstalled returns no error for a bundle" would
// have passed before the fix as well, because before the fix nothing reached
// this function. These tests assert *which loader ran*, which is the property
// that was actually broken.

// writeBundleFiles lays down a structurally valid payload and manifest so that
// the only thing which can fail is the signature check. The manifest carries
// signature_alg "ed25519", which means verifyFiles must reach the public-key
// branch — and in a test binary the embedded key is the all-zero sentinel, so
// that branch returns E-INT-005.
//
// That is exactly what makes E-INT-005 the proof we want: it is reachable only
// through the bundle loader, and unreachable through the YAML loader. Seeing it
// means the bundle path was taken.
func writeBundleFiles(t *testing.T, dir string, withManifest bool) {
	t.Helper()

	payload := []byte(`{"licences":[],"traps":[],"tos":[],"territories":[]}`)
	if err := os.WriteFile(filepath.Join(dir, BundleFile), payload, 0o600); err != nil {
		t.Fatalf("writing %s: %v", BundleFile, err)
	}
	if !withManifest {
		return
	}

	// The seven fields of bundle schema 1, in canonical order (see
	// manifestFields). The digest must match or the digest check fires first
	// and we would be testing that instead.
	manifest := `{"version":"2026.09.1","schema_version":1,` +
		`"built_at":"2026-09-25T00:00:00Z","signed_at":"2026-09-25T00:00:00Z",` +
		`"sha256":"` + Digest(payload) + `","entry_count":0,"signature_alg":"ed25519"}`
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), []byte(manifest), 0o600); err != nil {
		t.Fatalf("writing %s: %v", ManifestFile, err)
	}
}

// TestLoadInstalledTakesTheBundlePath is the regression test for the shipped
// binary's inability to read its own corpus.
func TestLoadInstalledTakesTheBundlePath(t *testing.T) {
	dir := t.TempDir()
	writeBundleFiles(t, dir, true)

	_, err := LoadInstalled(LoadOptions{Dir: dir})
	if err == nil {
		t.Fatal("LoadInstalled returned a corpus for an unverifiable bundle; " +
			"a bundle whose signature cannot be checked must never produce a verdict")
	}

	e, ok := cerr.As(err)
	if !ok {
		t.Fatalf("error is untyped (%v); every error must carry a code", err)
	}
	if e.Code() != cerr.EInt005 {
		t.Fatalf("got %s (%v), want %s.\n"+
			"E-INT-005 is reachable only through the bundle loader: it is returned when the "+
			"manifest declares an ed25519 signature and no public key is embedded. Any other "+
			"code means the bundle path was NOT taken and the YAML loader ran instead — which "+
			"is the defect this test exists to catch.", e.Code(), err, cerr.EInt005)
	}
}

// TestLoadInstalledDoesNotDowngradeAnIncompleteBundle is the fail-closed test.
//
// A payload without its manifest is a half-installed corpus — a copy that was
// interrupted, or a release archive that lost a file. Routing it to the YAML
// loader would mean it produced a verdict indistinguishable from a verified
// one, which is the single failure this product exists to refuse. So it must
// error, and it must error about the *bundle*, not fall through.
func TestLoadInstalledDoesNotDowngradeAnIncompleteBundle(t *testing.T) {
	dir := t.TempDir()
	writeBundleFiles(t, dir, false) // payload present, manifest absent

	_, err := LoadInstalled(LoadOptions{Dir: dir})
	if err == nil {
		t.Fatal("LoadInstalled silently accepted an incomplete bundle")
	}

	e, ok := cerr.As(err)
	if !ok {
		t.Fatalf("error is untyped (%v); every error must carry a code", err)
	}
	// readBundle names the file it could not read, so the message must mention
	// the manifest. That is what distinguishes "the bundle is broken" from the
	// YAML loader's "this directory holds no corpus".
	if e.Code() != cerr.ECorpus001 {
		t.Fatalf("got %s (%v), want %s naming %s", e.Code(), err, cerr.ECorpus001, ManifestFile)
	}
	if !strings.Contains(err.Error(), ManifestFile) {
		t.Fatalf("error %q does not name %s, so it came from the YAML loader rather than the "+
			"bundle loader — the incomplete bundle was downgraded instead of refused", err, ManifestFile)
	}
}

// TestLoadInstalledFallsBackToTheYAMLTree pins the contributor path. The YAML
// tree cannot carry a signature, so it must still load — and it must report
// itself as unsigned, because a corpus that is not verified must never look
// like one that is.
func TestLoadInstalledFallsBackToTheYAMLTree(t *testing.T) {
	// The repository's own corpus, which is a YAML source tree with no bundle
	// beside it. This is also what `make dogfood` and every fixture use.
	dir := filepath.Join("..", "..", "corpus")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("repository corpus not present at %s: %v", dir, err)
	}

	c, err := LoadInstalled(LoadOptions{Dir: dir, Today: "2026-09-25"})
	if err != nil {
		t.Fatalf("LoadInstalled refused the YAML source tree: %v", err)
	}
	if c.Signed {
		t.Fatal("the YAML source tree reported itself as signed; it cannot be, and claiming " +
			"otherwise would present an unverified corpus as a verified one")
	}
	if c.Version != "0.0.0-unsigned" {
		t.Fatalf("version = %q, want the unsigned sentinel", c.Version)
	}
	if len(c.entries) == 0 {
		t.Fatal("the YAML fallback loaded no licences")
	}
}
