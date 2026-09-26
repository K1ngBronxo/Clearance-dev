package corpus

import (
	"crypto/ed25519"
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/cite"
	"github.com/clearance-dev/clearance/internal/expr"
	"github.com/clearance-dev/clearance/internal/safefs"
	"github.com/clearance-dev/clearance/internal/safejson"
	"github.com/clearance-dev/clearance/internal/safeyaml"
)

// This file is the compiled-bundle half of the corpus (ADR-003). It turns the
// validated YAML source tree into a signed, three-file release artefact, and
// reads that artefact back into a *Corpus.
//
//	corpus.json          the payload: every licence, trap, ToS and territory
//	corpus.version.json  the manifest (seven fields, frozen at schema 1)
//	corpus.json.sig      the Ed25519 detached signature
//
// ── WHY corpus.json CARRIES NO TIMESTAMPS ────────────────────────────────────
//
// The payload must be *byte-identical for identical YAML input* (INV-6: a
// reproducible build must be comparable against an independent rebuild). If
// built_at lived inside corpus.json, its digest would change on every build and
// no two builds could ever be compared. So every piece of build metadata lives
// in the manifest — a *separate* file — and the payload is pure data. That
// separation is the whole reason the manifest exists; it is not tidiness.
//
// ── WHY THE SIGNATURE IS OVER THE MANIFEST, NOT THE BUNDLE ───────────────────
//
// The signature covers the manifest's canonical bytes. The manifest carries the
// SHA-256 of the payload, so signing the manifest transitively covers the
// payload while keeping the payload itself free of metadata. Signing the
// payload's own bytes would force the payload to carry a digest of itself, or
// would require signing whatever formatting happened to be on disk.
//
// CANONICALISATION RULE (normative). The canonical form of the manifest is
// `json.Marshal` of the Manifest struct with its fields in declaration order and
// **no trailing newline**:
//
//	{"version":..,"schema_version":..,"built_at":..,"signed_at":..,"sha256":..,"entry_count":..,"signature_alg":..}
//
// CanonicalManifest reproduces those bytes exactly, including encoding/json's
// default HTML escaping of <, > and &. A signature scheme without a documented
// canonicalisation rule is a scheme that breaks the first time somebody
// reformats a file; this rule is what lets a verifier recompute the exact bytes
// the signer signed from the parsed fields alone.

// BundleOptions tunes bundle verification. The zero value is the strict,
// production behaviour.
type BundleOptions struct {
	// AllowUnsigned permits a bundle whose manifest declares
	// signature_alg:"none". It exists so a developer can exercise the loader
	// against an unsigned local build. It MUST NOT be reachable by accident in
	// production: the zero value refuses an unsigned bundle, and nothing in the
	// runtime path sets this field.
	AllowUnsigned bool
}

// bundlePayload is the decoded shape of corpus.json. It is decoded through
// safejson (bounded) and then safeyaml.Decode, so every predicate is rebuilt
// through expr.FromValue and re-validated on the way in — a bundle cannot smuggle
// in a predicate the YAML loader would have refused.
type bundlePayload struct {
	Licences    []*Entry          `json:"licences"`
	Traps       []*Trap           `json:"traps"`
	ToS         []*ToSEntry       `json:"tos"`
	Territories []*TerritoryEntry `json:"territories"`
}

// bundleFiles is the raw content of the three files.
type bundleFiles struct {
	payload  []byte
	manifest []byte
	sig      []byte // nil when the signature file is absent (an unsigned bundle)
}

// manifestFields is the frozen field set of bundle schema 1, in canonical order.
var manifestFields = []string{
	"version", "schema_version", "built_at", "signed_at", "sha256", "entry_count", "signature_alg",
}

// ── writing the bundle (the compiler side) ───────────────────────────────────

// MarshalPayload serialises a loaded corpus to the canonical corpus.json bytes.
//
// It is hand-written rather than `json.Marshal` for two reasons: (1) the corpus
// package may not import encoding/json (depguard rule 3b — untrusted JSON is
// read only through safejson, and this package is on that list), and (2) the
// output must be deterministic, so every map is walked through a sorted
// accessor and the predicate is emitted in the one shape expr.FromValue reads.
//
// The `when` of a predicate is written in canonical predicate form: `op` is the
// boolean operator for and/or/not/lit, and the comparison operator for a
// comparison. The domain Expr type's own JSON tags cannot be used here — they
// emit `op:"cmp"` plus a separate `cmp_op`, a shape the loader cannot read back.
func MarshalPayload(c *Corpus) []byte {
	buf := make([]byte, 0, 1<<16)
	if c == nil {
		return append(buf, `{"licences":[],"traps":[],"tos":[],"territories":[]}`...)
	}
	buf = append(buf, `{"licences":[`...)
	for i, e := range c.entries {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = appendEntry(buf, e)
	}
	buf = append(buf, `],"traps":[`...)
	for i, t := range c.globalTraps {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = appendTrap(buf, t)
	}
	buf = append(buf, `],"tos":[`...)
	for i, slug := range c.SortedToSPlatforms() {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = appendToS(buf, c.tos[slug])
	}
	buf = append(buf, `],"territories":[`...)
	for i, code := range c.SortedTerritoryCodes() {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = appendTerritory(buf, c.territories[code])
	}
	buf = append(buf, `]}`...)
	return buf
}

func appendEntry(b []byte, e *Entry) []byte {
	b = append(b, `{"id":`...)
	b = appendJSONString(b, e.ID, false)
	b = append(b, `,"spdx_id":`...)
	b = appendJSONString(b, e.SPDXID, false)
	b = append(b, `,"name":`...)
	b = appendJSONString(b, e.Name, false)
	b = append(b, `,"family":`...)
	b = appendJSONString(b, e.Family, false)
	b = append(b, `,"osi_approved":`...)
	b = appendBool(b, e.OSIApproved)
	b = append(b, `,"fsf_libre":`...)
	b = appendBool(b, e.FSFLibre)
	b = append(b, `,"permissiveness":`...)
	b = strconv.AppendInt(b, int64(e.Permissiveness), 10)
	b = append(b, `,"obligations":[`...)
	for i := range e.Obligations {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendObligation(b, &e.Obligations[i])
	}
	b = append(b, `],"traps":[`...)
	for i := range e.Traps {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendTrap(b, &e.Traps[i])
	}
	b = append(b, `],"citation":`...)
	b = appendRef(b, e.Citation)
	b = append(b, `,"confidence":`...)
	b = appendJSONString(b, e.Confidence, false)
	b = append(b, `,"last_verified":`...)
	b = appendJSONString(b, e.LastVerified, false)
	if e.Correction != nil {
		b = append(b, `,"correction":`...)
		b = appendCorrection(b, e.Correction)
	}
	return append(b, '}')
}

func appendObligation(b []byte, o *Obligation) []byte {
	b = append(b, `{"id":`...)
	b = appendJSONString(b, o.ID, false)
	b = append(b, `,"kind":`...)
	b = appendJSONString(b, o.Kind, false)
	b = append(b, `,"severity":`...)
	b = appendJSONString(b, o.Severity, false)
	b = append(b, `,"when":`...)
	b = appendPredicate(b, o.When)
	b = append(b, `,"message":`...)
	b = appendJSONString(b, o.Message, false)
	b = append(b, `,"citation":`...)
	b = appendRef(b, o.Citation)
	b = append(b, `,"confidence":`...)
	b = appendJSONString(b, o.Confidence, false)
	if o.Fix != nil {
		b = append(b, `,"fix":`...)
		b = appendFix(b, o.Fix)
	}
	return append(b, '}')
}

func appendTrap(b []byte, t *Trap) []byte {
	b = append(b, `{"id":`...)
	b = appendJSONString(b, t.ID, false)
	b = append(b, `,"title":`...)
	b = appendJSONString(b, t.Title, false)
	b = append(b, `,"summary":`...)
	b = appendJSONString(b, t.Summary, false)
	b = append(b, `,"severity":`...)
	b = appendJSONString(b, t.Severity, false)
	b = append(b, `,"when":`...)
	b = appendPredicate(b, t.When)
	b = append(b, `,"citation":`...)
	b = appendRef(b, t.Citation)
	b = append(b, `,"confidence":`...)
	b = appendJSONString(b, t.Confidence, false)
	// The scope is written even when it is the default, because a bundle is the
	// published artifact and a reader must not have to know the default to know
	// what the trap means. It sits here, after confidence, so the byte layout is
	// a function of the field list rather than of which traps happen to be
	// graph-scoped (INV-6).
	b = append(b, `,"scope":`...)
	b = appendJSONString(b, t.ScopeOf(), false)
	if t.Fix != nil {
		b = append(b, `,"fix":`...)
		b = appendFix(b, t.Fix)
	}
	if t.Global {
		b = append(b, `,"global":true`...)
	}
	return append(b, '}')
}

func appendFix(b []byte, f *Fix) []byte {
	b = append(b, `{"action":`...)
	b = appendJSONString(b, f.Action, false)
	b = append(b, `,"suggestion":`...)
	b = appendJSONString(b, f.Suggestion, false)
	if f.Alternative != "" {
		b = append(b, `,"alternative":`...)
		b = appendJSONString(b, f.Alternative, false)
	}
	b = append(b, `,"confidence":`...)
	b = appendJSONString(b, f.Confidence, false)
	return append(b, '}')
}

func appendCorrection(b []byte, c *Correction) []byte {
	b = append(b, `{"reason":`...)
	b = appendJSONString(b, c.Reason, false)
	b = append(b, `,"evidence":`...)
	b = appendJSONString(b, c.Evidence, false)
	b = append(b, `,"from":`...)
	b = appendJSONString(b, c.From, false)
	b = append(b, `,"to":`...)
	b = appendJSONString(b, c.To, false)
	b = append(b, `,"corrected_at":`...)
	b = appendJSONString(b, c.CorrectedAt, false)
	b = append(b, `,"corrected_by":`...)
	b = appendJSONString(b, c.CorrectedBy, false)
	return append(b, '}')
}

func appendRef(b []byte, r cite.Ref) []byte {
	b = append(b, `{"url":`...)
	b = appendJSONString(b, r.URL, false)
	b = append(b, `,"section":`...)
	b = appendJSONString(b, r.Section, false)
	if r.Excerpt != "" {
		b = append(b, `,"excerpt":`...)
		b = appendJSONString(b, r.Excerpt, false)
	}
	// excerpt_kind is written beside the excerpt it qualifies — and it is written
	// at all, which it was not until 25 Sep 2026.
	//
	// The field was validated at build time (cite.Ref.Validate, E-CORPUS-004,
	// validation rule 13) and then dropped here, because this encoder is written
	// by hand while the decoder is reflection-driven, so the encoder can fall
	// behind the struct with nothing to notice. The consequence was not a build
	// failure but a shipped corpus with no kinds in it: every excerpt reached the
	// renderer with an empty ExcerptKind, and a renderer permitted to quote only a
	// verbatim excerpt correctly quoted nothing. The tool's headline claim is
	// "every finding quotes the exact clause"; the bundle made it present every
	// genuine quotation as "Clearance's reading:".
	//
	// TestPayloadRoundTripKeepsEveryCitationField covers this by reflection, so
	// the next field added to cite.Ref fails the suite instead of shipping.
	//
	// It sits after excerpt and before retrieved_at so the byte layout follows
	// the struct's field order (INV-6).
	if r.ExcerptKind != "" {
		b = append(b, `,"excerpt_kind":`...)
		b = appendJSONString(b, string(r.ExcerptKind), false)
	}
	if r.RetrievedAt != "" {
		b = append(b, `,"retrieved_at":`...)
		b = appendJSONString(b, r.RetrievedAt, false)
	}
	return append(b, '}')
}

func appendToS(b []byte, t *ToSEntry) []byte {
	if t == nil {
		return append(b, `{}`...)
	}
	b = append(b, `{"platform":`...)
	b = appendJSONString(b, t.Platform, false)
	b = append(b, `,"display_name":`...)
	b = appendJSONString(b, t.DisplayName, false)
	b = append(b, `,"summary":`...)
	b = appendJSONString(b, t.Summary, false)
	b = append(b, `,"restrictive_clauses":[`...)
	for i := range t.RestrictiveClauses {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendClause(b, &t.RestrictiveClauses[i])
	}
	b = append(b, `],"last_verified":`...)
	b = appendJSONString(b, t.LastVerified, false)
	b = append(b, `,"staleness_days":`...)
	b = strconv.AppendInt(b, int64(t.StalenessDays), 10)
	return append(b, '}')
}

func appendClause(b []byte, c *Clause) []byte {
	b = append(b, `{"id":`...)
	b = appendJSONString(b, c.ID, false)
	b = append(b, `,"text_summary":`...)
	b = appendJSONString(b, c.TextSummary, false)
	b = append(b, `,"severity":`...)
	b = appendJSONString(b, c.Severity, false)
	b = append(b, `,"citation":`...)
	b = appendRef(b, c.Citation)
	b = append(b, `,"confidence":`...)
	b = appendJSONString(b, c.Confidence, false)
	return append(b, '}')
}

func appendTerritory(b []byte, t *TerritoryEntry) []byte {
	if t == nil {
		return append(b, `{}`...)
	}
	b = append(b, `{"code":`...)
	b = appendJSONString(b, t.Code, false)
	b = append(b, `,"name":`...)
	b = appendJSONString(b, t.Name, false)
	b = append(b, `,"notes":`...)
	b = appendJSONString(b, t.Notes, false)
	b = append(b, `,"gates":[`...)
	for i := range t.Gates {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendGate(b, &t.Gates[i])
	}
	return append(b, `]}`...)
}

func appendGate(b []byte, g *Gate) []byte {
	b = append(b, `{"id":`...)
	b = appendJSONString(b, g.ID, false)
	b = append(b, `,"summary":`...)
	b = appendJSONString(b, g.Summary, false)
	b = append(b, `,"severity":`...)
	b = appendJSONString(b, g.Severity, false)
	b = append(b, `,"citation":`...)
	b = appendRef(b, g.Citation)
	b = append(b, `,"confidence":`...)
	b = appendJSONString(b, g.Confidence, false)
	return append(b, '}')
}

// appendPredicate writes a predicate in the canonical shape expr.FromValue
// reads back. A nil predicate means "always", written as the literal true.
func appendPredicate(b []byte, e *expr.Expr) []byte {
	if e == nil {
		return append(b, `{"op":"lit","value":true}`...)
	}
	switch e.Kind {
	case expr.KindAnd, expr.KindOr:
		b = append(b, `{"op":`...)
		b = appendJSONString(b, string(e.Kind), false)
		b = append(b, `,"l":`...)
		b = appendPredicate(b, e.L)
		b = append(b, `,"r":`...)
		b = appendPredicate(b, e.R)
		return append(b, '}')
	case expr.KindNot:
		b = append(b, `{"op":"not","x":`...)
		b = appendPredicate(b, e.X)
		return append(b, '}')
	case expr.KindLit:
		v := true
		if e.Lit != nil {
			v = *e.Lit
		}
		b = append(b, `{"op":"lit","value":`...)
		b = appendBool(b, v)
		return append(b, '}')
	case expr.KindCmp:
		b = append(b, `{"op":`...)
		b = appendJSONString(b, string(e.Cmp), false)
		b = append(b, `,"field":`...)
		b = appendJSONString(b, e.Field, false)
		b = append(b, `,"value":`...)
		b = appendValue(b, e.Value)
		return append(b, '}')
	}
	// An unknown kind cannot arise from a validated corpus; emit "always" so
	// the output stays valid JSON rather than silently truncating.
	return append(b, `{"op":"lit","value":true}`...)
}

// appendValue writes a predicate literal. Predicate values are constrained by
// expr.typeCheck at load time to bool, int, string or a list of strings, so the
// default arm is unreachable for a validated corpus.
func appendValue(b []byte, v any) []byte {
	switch t := v.(type) {
	case nil:
		return append(b, `null`...)
	case bool:
		return appendBool(b, t)
	case int:
		return strconv.AppendInt(b, int64(t), 10)
	case int64:
		return strconv.AppendInt(b, t, 10)
	case float64:
		return strconv.AppendFloat(b, t, 'g', -1, 64)
	case string:
		return appendJSONString(b, t, false)
	case []any:
		b = append(b, '[')
		for i, item := range t {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendValue(b, item)
		}
		return append(b, ']')
	case []string:
		b = append(b, '[')
		for i, item := range t {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendJSONString(b, item, false)
		}
		return append(b, ']')
	}
	return append(b, `null`...)
}

func appendBool(b []byte, v bool) []byte {
	if v {
		return append(b, `true`...)
	}
	return append(b, `false`...)
}

// CanonicalManifest returns the canonical bytes of a manifest: exactly what
// `json.Marshal(Manifest)` produces, fields in declaration order, no trailing
// newline. See the canonicalisation rule at the top of this file.
//
// It is exported because corpus-build must write exactly these bytes (so the
// signed artefact and the verifier cannot drift), and because a test asserts it
// equals json.Marshal byte for byte.
func CanonicalManifest(m *Manifest) []byte {
	if m == nil {
		return nil
	}
	b := make([]byte, 0, 256)
	b = append(b, `{"version":`...)
	b = appendJSONString(b, m.Version, true)
	b = append(b, `,"schema_version":`...)
	b = strconv.AppendInt(b, int64(m.SchemaVersion), 10)
	b = append(b, `,"built_at":`...)
	b = appendJSONString(b, m.BuiltAt, true)
	b = append(b, `,"signed_at":`...)
	b = appendJSONString(b, m.SignedAt, true)
	b = append(b, `,"sha256":`...)
	b = appendJSONString(b, m.SHA256, true)
	b = append(b, `,"entry_count":`...)
	b = strconv.AppendInt(b, int64(m.EntryCount), 10)
	b = append(b, `,"signature_alg":`...)
	b = appendJSONString(b, m.SignatureAlg, true)
	return append(b, '}')
}

// SignManifest signs the manifest's canonical bytes and returns the signature
// file content (base64, newline-terminated).
//
// This is the one place a corpus is signed. It lives here, beside the verifier,
// so signing and verification cannot drift apart. It signs the manifest bytes
// directly — Ed25519 hashes internally, so pre-hashing would be redundant — and
// it is used only by corpus-build, which is never shipped.
func SignManifest(priv ed25519.PrivateKey, m *Manifest) string {
	sig := ed25519.Sign(priv, CanonicalManifest(m))
	return base64.StdEncoding.EncodeToString(sig) + "\n"
}

// ── verification ─────────────────────────────────────────────────────────────

// VerifyBundle verifies the bundle in dir and returns its manifest.
//
// The verification order is normative and each step's position is load-bearing:
//
//  1. The manifest parses, and its field set is exactly the seven documented
//     fields in canonical order.
//  2. DIGEST: sha256(corpus.json) equals manifest.sha256, else E-CORPUS-002.
//     Checked first because it is cheap and it establishes the payload is
//     intact before we spend anything on it.
//  3. SIGNATURE: the signature over the manifest's canonical bytes verifies
//     against the embedded public key, else E-CORPUS-002; a well-formed
//     signature that does not verify means an unknown key, E-CORPUS-009.
//     Checked second because it is expensive and only meaningful on a payload
//     that already matches the signed digest.
//  4. SCHEMA: manifest.schema_version is supported, else E-CORPUS-003. Checked
//     LAST so that a user running a stale binary gets a clear "upgrade
//     Clearance" message rather than a confusing signature error from a bundle
//     that is, in fact, perfectly signed.
func VerifyBundle(dir string) (*Manifest, error) {
	pub, _ := PublicKey() // nil when no key is embedded; handled below
	return verifyBundle(dir, pub, BundleOptions{})
}

func verifyBundle(dir string, pub ed25519.PublicKey, opts BundleOptions) (*Manifest, error) {
	f, err := readBundle(dir)
	if err != nil {
		return nil, err
	}
	return verifyFiles(f, pub, opts)
}

func verifyFiles(f *bundleFiles, pub ed25519.PublicKey, opts BundleOptions) (*Manifest, error) {
	// 1. Manifest parses, with exactly the seven fields in canonical order.
	m, err := parseManifest(f.manifest)
	if err != nil {
		return nil, err
	}

	// 2. Digest.
	if !strings.EqualFold(Digest(f.payload), m.SHA256) {
		return nil, cerr.New(cerr.ECorpus002).WithDetail("check", "digest")
	}

	// 3. Signature over the manifest's canonical bytes.
	switch m.SignatureAlg {
	case "none":
		if !opts.AllowUnsigned {
			return nil, cerr.New(cerr.ECorpus002).WithDetail("check", "unsigned")
		}
	case "ed25519":
		if pub == nil {
			// No public key embedded: we cannot verify, so we must not pretend.
			return nil, cerr.New(cerr.EInt005)
		}
		if len(f.sig) == 0 {
			return nil, cerr.New(cerr.ECorpus002).WithDetail("check", "signature")
		}
		sig, err := decodeSignature(f.sig)
		if err != nil {
			return nil, cerr.New(cerr.ECorpus002).WithDetail("check", "signature")
		}
		if !ed25519.Verify(pub, CanonicalManifest(m), sig) {
			// A well-formed signature that does not verify under our key is the
			// signature of some other key: a mirror served something unofficial.
			return nil, cerr.New(cerr.ECorpus009)
		}
	default:
		return nil, cerr.New(cerr.ECorpus002).WithDetail("check", "algorithm")
	}

	// 4. Schema compatibility, checked last (see the doc comment).
	if m.SchemaVersion < 1 || m.SchemaVersion > SchemaVersion {
		return nil, cerr.New(cerr.ECorpus003, itoa(int64(m.SchemaVersion)), itoa(int64(SchemaVersion)))
	}
	return m, nil
}

// parseManifest decodes corpus.version.json, enforcing the frozen field set.
func parseManifest(raw []byte) (*Manifest, error) {
	v, err := safejson.Decode(raw, safejson.Limits{MaxBytes: 1 << 20})
	if err != nil {
		return nil, cerr.New(cerr.ECorpus002).WithDetail("check", "manifest")
	}
	obj, ok := v.(safejson.Object)
	if !ok {
		return nil, cerr.New(cerr.ECorpus002).WithDetail("check", "manifest")
	}
	// The field set is exactly the seven, in canonical order. A missing or extra
	// field — or a reordered one — is a manifest this binary does not
	// understand, and a manifest it does not understand is not one it signs.
	if len(obj.Keys) != len(manifestFields) {
		return nil, cerr.New(cerr.ECorpus002).WithDetail("check", "manifest-fields")
	}
	for i, want := range manifestFields {
		if obj.Keys[i] != want {
			return nil, cerr.New(cerr.ECorpus002).WithDetail("check", "manifest-fields")
		}
	}
	sv, okSV := obj.Int("schema_version")
	ec, okEC := obj.Int("entry_count")
	m := &Manifest{
		Version:       obj.String("version"),
		SchemaVersion: int(sv),
		BuiltAt:       obj.String("built_at"),
		SignedAt:      obj.String("signed_at"),
		SHA256:        obj.String("sha256"),
		EntryCount:    int(ec),
		SignatureAlg:  obj.String("signature_alg"),
	}
	if !okSV || !okEC || m.Version == "" || m.SHA256 == "" || m.SignatureAlg == "" {
		return nil, cerr.New(cerr.ECorpus002).WithDetail("check", "manifest")
	}
	return m, nil
}

// ParseManifest parses a manifest sidecar's bytes, enforcing the frozen field
// set and its canonical order.
//
// It is exported for corpus-build, which must read a manifest back before it
// signs one. It exists so the compiler reads manifests through the same parser
// the verifier uses: a signing tool with its own reader would be a second
// implementation of the manifest format, and the two would drift — which is
// precisely the defect the `Verify` doc comment describes, one file over.
func ParseManifest(raw []byte) (*Manifest, error) {
	return parseManifest(raw)
}

// readBundle reads the three files through safefs, which resolves symlinks and
// keeps the read inside the bundle directory.
func readBundle(dir string) (*bundleFiles, error) {
	root, err := safefs.New(dir, safefs.Limits{
		MaxFiles:      16,
		MaxDepth:      4,
		MaxFileSize:   MaxCorpusBytes,
		MaxTotalBytes: MaxCorpusBytes + (2 << 20),
	})
	if err != nil {
		return nil, cerr.New(cerr.ECorpus001, dir)
	}
	payload, err := root.ReadFile(BundleFile, MaxCorpusBytes)
	if err != nil {
		return nil, cerr.New(cerr.ECorpus001, BundleFile)
	}
	manifest, err := root.ReadFile(ManifestFile, 1<<20)
	if err != nil {
		return nil, cerr.New(cerr.ECorpus001, ManifestFile)
	}
	// The signature file is optional here: an unsigned bundle has none, and
	// verifyFiles decides whether that is acceptable.
	sig, _ := root.ReadFile(SignatureFile, 1<<20)
	return &bundleFiles{payload: payload, manifest: manifest, sig: sig}, nil
}

// ── loading ──────────────────────────────────────────────────────────────────

// LoadBundle verifies the bundle in dir and parses corpus.json into a *Corpus.
// It is a drop-in alternative to Load: the returned corpus carries the same
// indexes (bySPDX, tos, territories, Citations), so every lookup behaves
// identically.
//
// It refuses an unsigned bundle (the production behaviour). A developer who
// needs to exercise the loader against a local unsigned build must opt in
// explicitly via LoadBundleWith.
func LoadBundle(dir string) (*Corpus, error) {
	return LoadBundleWith(dir, BundleOptions{})
}

// LoadBundleWith is LoadBundle with explicit options. See BundleOptions.
func LoadBundleWith(dir string, opts BundleOptions) (*Corpus, error) {
	pub, _ := PublicKey()
	return loadBundle(dir, pub, opts)
}

func loadBundle(dir string, pub ed25519.PublicKey, opts BundleOptions) (*Corpus, error) {
	f, err := readBundle(dir)
	if err != nil {
		return nil, err
	}
	m, err := verifyFiles(f, pub, opts)
	if err != nil {
		return nil, err
	}
	c, err := ParsePayload(f.payload)
	if err != nil {
		return nil, err
	}
	c.Version = m.Version
	c.SchemaVersion = m.SchemaVersion
	c.BuiltAt = m.BuiltAt
	c.Signed = m.SignatureAlg == "ed25519"
	return c, nil
}

// ParsePayload parses corpus.json bytes into a *Corpus WITHOUT verifying any
// signature.
//
// It exists for exactly one caller: corpus-build's --previous flag, which
// compares this corpus against the previous one to enforce INV-8 across
// versions. The previous corpus is the maintainer's own input on their own
// machine, so there is no trust boundary to cross. It is NOT a runtime entry
// point; the runtime uses LoadBundle, which verifies first.
func ParsePayload(data []byte) (*Corpus, error) {
	v, err := safejson.Decode(data, safejson.Limits{
		MaxBytes: MaxCorpusBytes,
		MaxDepth: 64,
		MaxKeys:  1 << 20,
	})
	if err != nil {
		return nil, cerr.New(cerr.ECorpus004, BundleFile)
	}
	node, err := nodeFromValue(v)
	if err != nil {
		return nil, err
	}
	var bp bundlePayload
	if err := safeyaml.Decode(node, &bp); err != nil {
		return nil, cerr.New(cerr.ECorpus004, BundleFile)
	}
	return corpusFromPayload(&bp)
}

// corpusFromPayload rebuilds the Corpus indexes exactly as Load does, so the
// bundle is a drop-in for the YAML tree.
func corpusFromPayload(bp *bundlePayload) (*Corpus, error) {
	c := &Corpus{
		SchemaVersion: SchemaVersion,
		bySPDX:        map[string]*Entry{},
		tos:           map[string]*ToSEntry{},
		territories:   map[string]*TerritoryEntry{},
		Citations:     cite.NewIndex(),
	}
	for _, e := range bp.Licences {
		for i := range e.Obligations {
			e.Obligations[i].EntryID = e.ID
		}
		for i := range e.Traps {
			e.Traps[i].EntryID = e.ID
			e.Traps[i].Global = false
		}
		key := strings.ToUpper(e.SPDXID)
		c.bySPDX[key] = e
		c.bySPDX[e.SPDXID] = e
		c.entries = append(c.entries, e)

		registerCitation(c, e.Citation, e.ID)
		for _, ob := range e.Obligations {
			registerCitation(c, ob.Citation, e.ID)
		}
		for _, t := range e.Traps {
			registerCitation(c, t.Citation, e.ID)
		}
	}
	for _, t := range bp.Traps {
		t.Global = true
		c.globalTraps = append(c.globalTraps, t)
		registerCitation(c, t.Citation, t.ID)
	}
	sort.SliceStable(c.globalTraps, func(i, j int) bool { return c.globalTraps[i].ID < c.globalTraps[j].ID })
	for _, t := range bp.ToS {
		slug := strings.ToLower(strings.TrimSpace(t.Platform))
		c.tos[slug] = t
		for _, cl := range t.RestrictiveClauses {
			registerCitation(c, cl.Citation, t.Platform)
		}
	}
	for _, t := range bp.Territories {
		code := strings.ToUpper(strings.TrimSpace(t.Code))
		c.territories[code] = t
		for _, g := range t.Gates {
			registerCitation(c, g.Citation, t.Code)
		}
	}
	return c, nil
}

// ── the safejson -> safeyaml bridge ──────────────────────────────────────────

// nodeFromValue turns a decoded JSON value into a safeyaml.Node, so that the
// bundle is decoded by the *same* reflection decoder the YAML loader uses. That
// keeps the two paths' semantics identical (unknown-key rejection, the
// expr.UnmarshalYAML predicate hook) instead of maintaining a second decoder.
func nodeFromValue(v safejson.Value) (*safeyaml.Node, error) {
	switch t := v.(type) {
	case nil:
		return &safeyaml.Node{Kind: safeyaml.ScalarNode, Value: nil}, nil
	case bool:
		return &safeyaml.Node{Kind: safeyaml.ScalarNode, Value: t}, nil
	case string:
		return &safeyaml.Node{Kind: safeyaml.ScalarNode, Value: t}, nil
	case int64:
		return &safeyaml.Node{Kind: safeyaml.ScalarNode, Value: t}, nil
	case float64:
		return &safeyaml.Node{Kind: safeyaml.ScalarNode, Value: t}, nil
	case []safejson.Value:
		n := &safeyaml.Node{Kind: safeyaml.SequenceNode}
		for _, item := range t {
			child, err := nodeFromValue(item)
			if err != nil {
				return nil, err
			}
			n.Items = append(n.Items, child)
		}
		return n, nil
	case safejson.Object:
		n := &safeyaml.Node{Kind: safeyaml.MappingNode}
		for i, k := range t.Keys {
			child, err := nodeFromValue(t.Values[i])
			if err != nil {
				return nil, err
			}
			n.Keys = append(n.Keys, k)
			n.Values = append(n.Values, child)
		}
		return n, nil
	}
	return nil, cerr.New(cerr.ECorpus004, BundleFile)
}

// ── JSON string escaping ─────────────────────────────────────────────────────

const hexDigits = "0123456789abcdef"

// appendJSONString appends s as a JSON string literal.
//
// With escapeHTML set it reproduces encoding/json's default escaping exactly,
// including <, > and & — which is what makes CanonicalManifest byte-identical to
// json.Marshal. With escapeHTML clear it leaves <, > and & literal, which keeps
// the human-inspectable payload readable. U+2028/U+2029 and invalid UTF-8 are
// escaped in both modes, matching encoding/json.
func appendJSONString(dst []byte, s string, escapeHTML bool) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); {
		b := s[i]
		if b < utf8.RuneSelf {
			safe := b >= 0x20 && b != '"' && b != '\\'
			if escapeHTML && (b == '<' || b == '>' || b == '&') {
				safe = false
			}
			if safe {
				i++
				continue
			}
			if start < i {
				dst = append(dst, s[start:i]...)
			}
			switch b {
			case '\\', '"':
				dst = append(dst, '\\', b)
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[b>>4], hexDigits[b&0xF])
			}
			i++
			start = i
			continue
		}
		c, size := utf8.DecodeRuneInString(s[i:])
		if c == utf8.RuneError && size == 1 {
			if start < i {
				dst = append(dst, s[start:i]...)
			}
			dst = append(dst, `\ufffd`...)
			i += size
			start = i
			continue
		}
		if c == '\u2028' || c == '\u2029' {
			if start < i {
				dst = append(dst, s[start:i]...)
			}
			dst = append(dst, `\u202`...)
			dst = append(dst, hexDigits[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		dst = append(dst, s[start:]...)
	}
	return append(dst, '"')
}
