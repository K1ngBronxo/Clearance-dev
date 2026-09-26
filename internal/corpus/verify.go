package corpus

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/safefs"
)

// INV-9: "Corpus bundles are Ed25519-signed. The public key is compiled into
// the binary. An unsigned or mis-signed bundle is rejected with E-CORPUS-002,
// and the previous corpus remains in force."
//
// This product is a supply-chain tool. A compromised corpus mirror could inject
// false obligations — the exact failure Clearance exists to prevent — so the
// corpus is tamper-evident by construction, and verification happens on *every*
// load rather than only on update. A local attacker who edits the on-disk
// corpus is caught by the same check.
//
// The private key never touches a build server. It lives offline, and only
// `corpus-build` (which is never shipped) can use it. A compromised CI runner
// therefore cannot forge a corpus.

// Manifest is the sidecar that describes a compiled bundle. Its field set is
// frozen at bundle schema 1 (see docs/adr/ADR-003).
//
// built_at and signed_at are both present and they are different facts:
// built_at is when the compiler wrote the payload, signed_at is when the
// offline key signed it. Those can be days apart, because the private key never
// touches a build server — and the gap is the only record of how long an
// unsigned bundle sat on a disk.
type Manifest struct {
	Version       string `json:"version"`
	SchemaVersion int    `json:"schema_version"`
	BuiltAt       string `json:"built_at"`
	SignedAt      string `json:"signed_at"`
	SHA256        string `json:"sha256"`
	EntryCount    int    `json:"entry_count"`
	SignatureAlg  string `json:"signature_alg"`
}

// BundleNames are the three files that make up a signed corpus.
const (
	BundleFile    = "corpus.json"
	ManifestFile  = "corpus.version.json"
	SignatureFile = "corpus.json.sig"
)

// devPublicKeyHex is the corpus public key embedded in this build. A release
// build replaces it via -ldflags, which is why it is a var and not a const.
//
// # IT MUST BE A LITERAL, AND THAT IS NOT A STYLE PREFERENCE
//
// The linker's `-X` flag sets a string variable only when that variable is
// uninitialised or initialised to a **constant string expression**. This was
// `strings.Repeat("0", ed25519.PublicKeySize*2)` — a function call — so every
// `-X ...devPublicKeyHex=...` was silently ignored: no error, no warning, exit 0.
//
// The consequence was not cosmetic. A release built with a real key would have
// shipped carrying the all-zero key, refused every signed corpus with E-INT-005,
// and reported itself as perfectly built. It is the same failure as the dead
// `-X main.version` stamps in the Makefile (LOGS.md D-020), in the one place
// where being wrong means the tool cannot read the data it exists to interpret.
//
// So the literal is written out in full, and TestCorpusPublicKeyIsStampable
// pins the property that makes it stampable — because the failure mode here is
// silence, and a silent failure needs a test rather than a comment.
//
// An all-zero key means "this build has no corpus key", which makes every
// verification fail with E-INT-005 rather than silently accepting an unsigned
// corpus. Failing closed is the only acceptable direction here.
//
// The literal is exactly ed25519.PublicKeySize*2 = 64 hex digits, written on two
// lines because 64 unbroken characters are unreadable. It must not be longer:
// PublicKey checks the decoded length before it checks for all-zeros, so a
// 128-digit placeholder would fail on length and leave the all-zero sentinel —
// the branch that actually expresses "no key configured" — unreachable.
var devPublicKeyHex = "0000000000000000000000000000000000000000000000000000000000000000"

// PublicKey returns the embedded corpus public key.
//
// It returns an error when the key is missing, because a binary that cannot
// verify a corpus must not pretend it did.
func PublicKey() (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(devPublicKeyHex))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, cerr.New(cerr.EInt005)
	}
	allZero := true
	for _, b := range raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, cerr.New(cerr.EInt005)
	}
	return ed25519.PublicKey(raw), nil
}

// Verify reads a bundle directory and checks the manifest against the payload
// and the signature against the manifest's canonical bytes.
//
// # ONE SCHEME, ONE IMPLEMENTATION
//
// This function used to carry its own verification: it parsed five of the
// manifest's seven fields, and it verified the signature over the SHA-256
// digest of the payload. LoadBundle verified the signature over
// CanonicalManifest(m) instead — the rule ADR-003 documents. Two schemes over
// one bundle means a bundle signed for one path is rejected by the other, so
// `clearance corpus verify` could report OK on a bundle that `clearance check`
// then refused to load, and the user would have no way to tell which answer
// was the real one.
//
// It now delegates to verifyFiles, which is the single verifier. The order is
// therefore fixed in one place and not negotiable:
//
//  1. The manifest parses, with exactly the seven documented fields in
//     canonical order.
//  2. DIGEST: sha256(corpus.json) equals manifest.sha256.
//  3. SIGNATURE: the signature over the manifest's canonical bytes verifies
//     against the embedded key.
//  4. SCHEMA: manifest.schema_version is supported, checked last so a stale
//     binary says "upgrade Clearance" rather than reporting a signature error
//     on a bundle that is in fact perfectly signed.
//
// An unsigned bundle is refused here, as it is at load time: this build has no
// AllowUnsigned escape hatch on the verify path, because the command a user
// runs to check whether a corpus is authentic must not be the command that
// accepts one that is not.
func Verify(root *safefs.Root, pub ed25519.PublicKey) (*Manifest, error) {
	payload, err := root.ReadFile(BundleFile, MaxCorpusBytes)
	if err != nil {
		return nil, cerr.New(cerr.ECorpus001, BundleFile)
	}
	manifest, err := root.ReadFile(ManifestFile, 1<<20)
	if err != nil {
		return nil, cerr.New(cerr.ECorpus001, ManifestFile)
	}
	// The signature file is optional at read time: an unsigned bundle has none,
	// and verifyFiles is what decides whether that is acceptable.
	sig, _ := root.ReadFile(SignatureFile, 1<<20)

	return verifyFiles(&bundleFiles{payload: payload, manifest: manifest, sig: sig},
		pub, BundleOptions{})
}

// Digest returns the hex SHA-256 of a payload, for the manifest.
func Digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func decodeSignature(raw []byte) ([]byte, error) {
	s := strings.TrimSpace(string(raw))
	// Accept base64 in either alphabet, because a signature file that travelled
	// through a system that rewrote `+/` to `-_` is still a valid signature and
	// refusing it would send a user hunting for a problem that does not exist.
	if sig, err := base64.StdEncoding.DecodeString(s); err == nil && len(sig) == ed25519.SignatureSize {
		return sig, nil
	}
	if sig, err := base64.URLEncoding.DecodeString(s); err == nil && len(sig) == ed25519.SignatureSize {
		return sig, nil
	}
	// Also accept hex, which is what a hand-written test fixture tends to use.
	if sig, err := hex.DecodeString(s); err == nil && len(sig) == ed25519.SignatureSize {
		return sig, nil
	}
	return nil, cerr.New(cerr.ECorpus002)
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
