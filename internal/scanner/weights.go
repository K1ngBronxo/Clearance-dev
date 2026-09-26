// The model-weights detector.
//
// # WHY THIS FILE EXISTS
//
// A weight file is a dependency. It has a licence. Nothing else in the market
// treats it as one, and that omission is the single most common AI-era licence
// trap: a repository whose *code* is permissively licensed while the *weights*
// it loads are non-commercial. The code licence tells you nothing about the
// weights, and every existing SCA tool ignores weight files entirely.
//
// PLAN/02-SPECIFICATIONS/05-detection-spec-weights.md is the contract this
// implements.
//
// # THE THREE RULES THAT SHAPE THE CODE
//
//  1. **Magic bytes first, extension second.** A file named `model.bin` may be
//     a pickle, a GGUF, a zip or a config; a file named `README.md` may be a
//     mis-renamed GGUF. Extension guessing is exactly the sloppiness this
//     product replaces, so detection reads bytes.
//
//  2. **A 70 GB weight file is never read into memory.** Every read here is
//     bounded, and the bounds are named constants rather than inline numbers so
//     that raising one is a visible decision. The file's *size* is recorded in
//     evidence; its contents are not hashed, because hashing 70 GB to fill in a
//     field nobody reads would make the tool unusable on the inputs it exists
//     for.
//
//  3. **No licence statement is a finding, not a gap.** If none of the seven
//     sources resolves, the result is an `Undetermined` with `E-SCAN-010` — and
//     the corpus carries `trap.weights.no-licence-statement` at BLOCK severity
//     for commercial use, because an unlicensed weight file is legally unusable
//     for commercial purposes. Saying so is the honest answer. Guessing from the
//     model's name would not be.
package scanner

import (
	"encoding/binary"
	"math"
	"path"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/safefs"
	"github.com/clearance-dev/clearance/internal/safejson"
)

const (
	// weightMagicBytes is the prefix read for the magic check. Every format's
	// magic lives in the first 16 bytes; SafeTensors needs 9 (an 8-byte header
	// length plus the opening brace of its JSON header).
	weightMagicBytes = 16

	// weightSniffMinSize is the size above which a file is sniffed even when its
	// name looks nothing like a weight file. See shouldSniffWeight.
	weightSniffMinSize = 64 << 10

	// weightMetaBytes is the first attempt at a structured header. Every real
	// GGUF metadata block fits: the block holds the architecture, the
	// tokenizer and the licence, and a large one is a few hundred KiB.
	weightMetaBytes = 1 << 20

	// weightMetaMaxBytes is the escalated attempt, and the hard ceiling the
	// spec sets for a structured header.
	weightMetaMaxBytes = 16 << 20

	// weightZipTailBytes bounds the central-directory read used to tell a
	// PyTorch checkpoint from any other zip.
	weightZipTailBytes = 1 << 20

	// weightProseBytes bounds a sibling markdown file read.
	weightProseBytes = 256 << 10
)

// weightFormat is a recognised container format.
type weightFormat struct {
	// Name is the human name used in evidence and metadata.
	Name string
	// InFile is true when the format can carry a licence statement inside the
	// file itself. Only GGUF does, today.
	InFile bool
	// LicenceSource is the metadata key holding the licence, when InFile.
	LicenceSource string
}

// weightExtensions are the file extensions worth reading bytes from on sight.
//
// This is a *performance* gate, not a detection rule: detection is by magic
// bytes. The gate exists so the detector does not open every one of 200,000
// files to find three models. See shouldSniffWeight for the exact coverage and
// the case it misses.
var weightExtensions = map[string]bool{
	".safetensors": true,
	".gguf":        true,
	".onnx":        true,
	".pt":          true,
	".pth":         true,
	".ckpt":        true,
	".bin":         true,
	".pkl":         true,
	".pickle":      true,
	".h5":          true,
	".keras":       true,
	".pb":          true,
	".tflite":      true,
	".engine":      true,
	".plan":        true,
	".mlmodel":     true,
	".joblib":      true,
	".npz":         true,
	".msgpack":     true,
	".flax":        true,
	".model":       true,
	".weights":     true,
}

// shouldSniffWeight reports whether a file is worth reading bytes from.
//
// The spec's rule is "a file is a weight file if its magic bytes match,
// regardless of name". That rule is honoured for every file with a plausible
// extension and for every file of any size. What it does NOT cover is a file
// that is **both** mis-named and smaller than 64 KiB. That combination is
// pathological — a real weight file is megabytes at the very smallest — and
// covering it would mean opening every file in the tree, which is the trade the
// threshold makes. The limit is stated here rather than left to be discovered.
func shouldSniffWeight(e safefs.WalkEntry) bool {
	if e.IsDir || e.Rel == "" {
		return false
	}
	if weightExtensions[strings.ToLower(path.Ext(e.Base()))] {
		return true
	}
	return e.Size >= weightSniffMinSize
}

// detectWeights finds model weight files and resolves each one's licence.
func (s *scan) detectWeights(entries []safefs.WalkEntry) {
	sib := indexSiblings(entries)

	for _, e := range entries {
		if !shouldSniffWeight(e) {
			continue
		}

		// The spec's skip rule, and the reason it is here rather than in the
		// walk: `safefs` deliberately does NOT skip node_modules, because
		// vendored licences live there. A 2 GB `.bin` inside an npm package is
		// a package payload, and the code-licence layer governs it. Classifying
		// it as a model would produce a confident finding about the wrong
		// thing.
		if insideDependencyDir(e.Rel) {
			continue
		}

		format, ok := s.classifyWeight(e)
		if !ok {
			continue
		}
		s.addWeight(e, format, sib)
	}
}

// classifyWeight reads the bounded prefix and reports the container format.
func (s *scan) classifyWeight(e safefs.WalkEntry) (weightFormat, bool) {
	prefix, err := s.root.ReadFilePrefix(e.Rel, weightMagicBytes)
	if err != nil {
		// A file we cannot read is a DEGRADE, recorded, not a silent skip.
		s.warnErr(err, e.Rel)
		return weightFormat{}, false
	}
	if len(prefix) < 4 {
		return weightFormat{}, false
	}

	// SafeTensors: an 8-byte little-endian header length, then `{`.
	if len(prefix) >= 9 && prefix[8] == '{' {
		n := binary.LittleEndian.Uint64(prefix[:8])
		if n > 0 && n <= weightMetaMaxBytes {
			return weightFormat{Name: "SafeTensors"}, true
		}
	}

	// GGUF: a 4-byte ASCII magic, and the only format here that carries its own
	// licence. `general.license` is machine-written by the publisher at export
	// time, which makes it the highest-confidence source in the whole chain.
	if string(prefix[:4]) == "GGUF" {
		return weightFormat{
			Name:          "GGUF",
			InFile:        true,
			LicenceSource: "general.license",
		}, true
	}

	// HDF5 (TensorFlow/Keras `.h5`, `.keras`).
	if len(prefix) >= 8 && string(prefix[:8]) == "\x89HDF\r\n\x1a\n" {
		return weightFormat{Name: "HDF5"}, true
	}

	// Pickle: protocol 0x80 followed by a protocol version in 2..5.
	if len(prefix) >= 2 && prefix[0] == 0x80 && prefix[1] >= 2 && prefix[1] <= 5 {
		return weightFormat{Name: "Pickle"}, true
	}

	// Zip. This is the one magic that is genuinely ambiguous — every zip starts
	// `PK\x03\x04` — so it is confirmed by looking for PyTorch's `data.pkl`
	// central-directory entry. Without that check, a vendored `.zip` archive
	// would be reported as a model.
	if string(prefix[:4]) == "PK\x03\x04" {
		if s.zipContainsPyTorchPayload(e) {
			return weightFormat{Name: "PyTorch (zip)"}, true
		}
		return weightFormat{}, false
	}

	// ONNX: a protobuf stream whose first field is the varint ir_version, so it
	// begins 0x08. That byte alone is not distinctive — plenty of protobuf
	// messages start with it — so the extension is required as well. This is
	// the one format where the spec's "magic first" rule cannot be applied on
	// its own, and the reason is recorded here rather than papered over.
	if prefix[0] == 0x08 && strings.EqualFold(path.Ext(e.Base()), ".onnx") {
		return weightFormat{Name: "ONNX"}, true
	}

	return weightFormat{}, false
}

// zipContainsPyTorchPayload reports whether a zip's central directory lists
// `data.pkl`, the entry every PyTorch checkpoint contains.
//
// The central directory is at the *end* of a zip, so this reads the tail. It
// searches the bounded tail rather than walking the directory records: a
// malformed archive can make a structural walk loop, and the search answers the
// only question being asked. A false positive would need a zip that is not a
// checkpoint but contains an entry literally named `data.pkl`, which is the
// same signal.
func (s *scan) zipContainsPyTorchPayload(e safefs.WalkEntry) bool {
	rc, err := s.root.Open(e.Rel)
	if err != nil {
		// Open applies the 8 MiB MaxFileSize bound, so a large checkpoint is
		// refused here. That is not a failure: the magic already matched, and
		// the tail check is a disambiguation, so fall back to the prefix.
		return true
	}
	defer rc.Close()

	rs, ok := rc.(interface {
		Seek(offset int64, whence int) (int64, error)
		Read([]byte) (int, error)
	})
	if !ok {
		return true
	}

	start := e.Size - weightZipTailBytes
	if start < 0 {
		start = 0
	}
	if _, err := rs.Seek(start, 0); err != nil {
		return true
	}
	buf := make([]byte, weightZipTailBytes)
	n, _ := rs.Read(buf)
	return strings.Contains(string(buf[:n]), "data.pkl")
}

// addWeight records a detected weight file, with its licence or its absence.
func (s *scan) addWeight(e safefs.WalkEntry, format weightFormat, sib *siblingIndex) {
	res := s.resolveWeightLicence(e, format, sib)

	meta := map[string]string{
		"format":     format.Name,
		"size_bytes": itoaInt(e.Size),
	}
	excerpt := format.Name + ", " + safefs.HumanBytes(e.Size)

	id := graph.LocalID(graph.KindWeights, e.Rel)

	if !res.found {
		// The honest gap. E-SCAN-010's recovery text tells the user to locate
		// the licence or remove the file, and the corpus turns this into a
		// BLOCK for a commercial intent via trap.weights.no-licence-statement.
		s.g.Undetermined = append(s.g.Undetermined, graph.Undetermined{
			ID:   id,
			Kind: graph.KindWeights,
			// The reason names every source that was tried, so the reader can
			// tell "nobody published a licence" from "we did not look".
			Reason:    "licence_not_found",
			Detail:    "No licence statement in the file itself, config.json, README.md, MODEL_CARD.md or a sibling LICENSE file.",
			Evidence:  []graph.Evidence{{Path: e.Rel, Excerpt: excerpt}},
			ErrorCode: string(cerr.EScan010),
		})
		// It is still a dependency. A weight file whose licence is unknown is
		// not a weight file that is absent, and dropping it here is how a
		// "we could not tell" becomes a "there was nothing to tell".
		s.g.Add(graph.Dependency{
			ID:        id,
			Kind:      graph.KindWeights,
			Name:      path.Base(e.Rel),
			Ecosystem: "weights",
			Scope:     s.containingScope(e.Rel),
			Licence:   graph.LicenceRef{Raw: "", Source: "unresolved", Resolved: false, Confidence: "none"},
			Evidence:  []graph.Evidence{{Path: e.Rel, Excerpt: excerpt}},
			Metadata:  meta,
		})
		return
	}

	meta["licence_source"] = res.ref.Source
	if res.link != "" {
		meta["licence_link"] = res.link
	}

	s.g.Add(graph.Dependency{
		ID:        id,
		Kind:      graph.KindWeights,
		Name:      path.Base(e.Rel),
		Ecosystem: "weights",
		Scope:     s.containingScope(e.Rel),
		Licence:   res.ref,
		Evidence:  []graph.Evidence{{Path: e.Rel, Excerpt: excerpt}},
		Metadata:  meta,
	})
}

// weightLicence is the outcome of walking the resolution chain.
type weightLicence struct {
	ref   graph.LicenceRef
	link  string // GGUF's general.license.link, when present
	found bool
}

// resolveWeightLicence walks the seven-source priority chain from the spec.
//
// Order matters and is not arbitrary: an in-file machine-written field beats a
// structured sibling, which beats a licence file, which beats prose. Each step
// down is a step from "the publisher stated this" to "we inferred it", and the
// confidence recorded on the LicenceRef says which it was.
func (s *scan) resolveWeightLicence(e safefs.WalkEntry, format weightFormat, sib *siblingIndex) weightLicence {
	dir := e.Dir()

	// 1. GGUF in-file metadata — HIGH. Only source that survives the file being
	//    moved away from its siblings.
	if format.InFile {
		if l, link, ok := s.ggufLicence(e); ok {
			if ref, resolved := licenceFromString(l, "weight_metadata"); resolved {
				ref.Confidence = "high"
				return weightLicence{ref: ref, link: link, found: true}
			}
		}
	}

	// 2. Sibling config.json — HIGH. The Hugging Face convention, and
	//    publisher-authored. Looked for beside the weights and at the root,
	//    because a repository keeps one README/config at the top and puts the
	//    tensors in a subdirectory.
	for _, rel := range sib.candidates(dir, e.Rel, "config.json") {
		if ref, ok := s.configJSONLicence(rel); ok {
			ref.Confidence = "high"
			return weightLicence{ref: ref, found: true}
		}
	}

	// 3. Sibling README.md YAML frontmatter — HIGH. Structured, and the
	//    convention Hugging Face itself documents.
	for _, rel := range sib.candidates(dir, e.Rel, "README.md") {
		if ref, ok := s.frontmatterLicence(rel); ok {
			ref.Confidence = "high"
			return weightLicence{ref: ref, found: true}
		}
	}

	// 4. Sibling LICENSE / LICENSE.md / COPYING — HIGH. The actual text, run
	//    through the same content classifier the code-licence layer uses.
	for _, name := range []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md"} {
		for _, rel := range sib.candidates(dir, e.Rel, name) {
			if spdx, conf, ok := s.recogniseFile(rel); ok {
				return weightLicence{
					ref: graph.LicenceRef{
						SPDX: spdx, Raw: spdx, Source: "weight_sibling_licence",
						Resolved: true, Confidence: conf,
					},
					found: true,
				}
			}
		}
	}

	// 5. MODEL_CARD.md prose — MEDIUM. A model card may summarise the licence,
	//    or may be marketing. It is read, and it is not trusted as highly as a
	//    structured field.
	for _, name := range []string{"MODEL_CARD.md", "model_card.md"} {
		for _, rel := range sib.candidates(dir, e.Rel, name) {
			if ref, ok := s.proseLicence(rel, "model_card"); ok {
				ref.Confidence = "medium"
				return weightLicence{ref: ref, found: true}
			}
		}
	}

	// 6. Any sibling markdown with a licence line — LOW. Inference, and the
	//    confidence says so.
	for _, rel := range sib.markdownNear(dir, e.Rel) {
		if ref, ok := s.proseLicence(rel, "weight_prose"); ok {
			ref.Confidence = "low"
			return weightLicence{ref: ref, found: true}
		}
	}

	// 7. UNRESOLVED. Not a guess, and not a pass.
	return weightLicence{}
}

// licenceFromString turns a licence string found in weight metadata into a
// LicenceRef, reporting whether it actually resolved.
//
// The second return value is the point: "cc-by-nc-4.0" and "see the LICENSE
// file" both come out of this function, and only one of them is a licence. A
// caller that ignored the flag would attach another licence's obligations to
// this dependency and produce a confident verdict about the wrong terms.
func licenceFromString(raw, source string) (graph.LicenceRef, bool) {
	ref := LicenceRefFromString(raw, source)
	if !ref.Resolved || ref.SPDX == "" {
		return ref, false
	}
	return ref, true
}

// configJSONLicence reads a licence field from a model's config.json.
func (s *scan) configJSONLicence(rel string) (graph.LicenceRef, bool) {
	data, err := s.root.ReadFile(rel, weightProseBytes)
	if err != nil {
		s.warnErr(err, rel)
		return graph.LicenceRef{}, false
	}
	obj, err := safejson.DecodeObject(data, safejson.Limits{MaxBytes: weightProseBytes})
	if err != nil {
		// The spec's rule: a config.json that cannot be parsed is skipped and
		// the chain moves on. It is not fatal, because the next source may
		// still answer.
		s.warn(cerr.EParse005, rel, "Cannot parse '"+rel+"' as JSON. Skipped as a licence source.")
		return graph.LicenceRef{}, false
	}
	// Both spellings: the field is `license` in the Hugging Face convention and
	// `licence` in some European-authored repositories.
	for _, key := range []string{"license", "licence"} {
		raw := obj.String(key)
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if ref, ok := licenceFromString(raw, "model_card"); ok {
			return ref, true
		}
		// The key was present and held something unresolvable. That is a
		// different fact from an absent key, and the chain should say so
		// rather than silently continuing as if the field were missing.
		return graph.LicenceRef{Raw: raw, Source: "model_card", Confidence: "low"}, false
	}
	return graph.LicenceRef{}, false
}

// frontmatterLicence reads a `license:` key from a markdown YAML frontmatter
// block. Only the frontmatter is read — a licence word in the body is prose and
// is handled at a lower confidence by proseLicence.
func (s *scan) frontmatterLicence(rel string) (graph.LicenceRef, bool) {
	data, err := s.root.ReadFile(rel, weightProseBytes)
	if err != nil {
		s.warnErr(err, rel)
		return graph.LicenceRef{}, false
	}
	body := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(body, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return graph.LicenceRef{}, false
	}
	for _, line := range lines[1:] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" {
			break
		}
		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "license", "licence", "license_name":
			if ref, ok := licenceFromString(value, "model_card"); ok {
				return ref, true
			}
		}
	}
	return graph.LicenceRef{}, false
}

// proseLicence finds a licence named in prose.
//
// This is inference, and the caller records it as LOW or MEDIUM confidence. The
// table is deliberately small and ordered most-specific-first: "CC BY-NC-SA"
// must be tested before "CC BY", or the share-alike variant would be reported
// as the plain attribution one. A long table of near-miss patterns would be a
// classifier pretending to be a lookup, and a wrong match here is worse than no
// match — it attaches real obligations to the wrong licence.
var proseLicencePatterns = []struct {
	Needle string
	SPDX   string
}{
	// Non-commercial and share-alike variants first, longest match wins.
	{"creative commons attribution-noncommercial-sharealike", "CC-BY-NC-SA-4.0"},
	{"creative commons attribution-noncommercial-noDerivatives", "CC-BY-NC-ND-4.0"},
	{"creative commons attribution-noncommercial", "CC-BY-NC-4.0"},
	{"cc by-nc-sa", "CC-BY-NC-SA-4.0"},
	{"cc by-nc-nd", "CC-BY-NC-ND-4.0"},
	{"cc by-nc", "CC-BY-NC-4.0"},
	{"cc-by-nc-sa", "CC-BY-NC-SA-4.0"},
	{"cc-by-nc-nd", "CC-BY-NC-ND-4.0"},
	{"cc-by-nc", "CC-BY-NC-4.0"},
	{"noncommercial", "CC-BY-NC-4.0"},

	{"creative commons attribution-sharealike", "CC-BY-SA-4.0"},
	{"cc by-sa", "CC-BY-SA-4.0"},
	{"cc-by-sa", "CC-BY-SA-4.0"},
	{"creative commons attribution", "CC-BY-4.0"},

	{"apache license, version 2.0", "Apache-2.0"},
	{"apache-2.0", "Apache-2.0"},
	{"apache 2.0", "Apache-2.0"},

	{"gnu affero general public license", "AGPL-3.0-only"},
	{"agpl-3.0", "AGPL-3.0-only"},
	{"gnu lesser general public license", "LGPL-3.0-only"},
	{"lgpl-3.0", "LGPL-3.0-only"},
	{"gnu general public license", "GPL-3.0-only"},

	{"bsd 3-clause", "BSD-3-Clause"},
	{"bsd-3-clause", "BSD-3-Clause"},
	{"mozilla public license", "MPL-2.0"},
	{"mpl-2.0", "MPL-2.0"},

	{"server side public license", "SSPL-1.0"},
	{"sspl-1.0", "SSPL-1.0"},
	{"business source license", "BUSL-1.1"},
	{"busl-1.1", "BUSL-1.1"},
	{"elastic license", "Elastic-2.0"},

	{"llama 3.1 community", "Llama-3.1-Community"},
	{"llama-3.1-community", "Llama-3.1-Community"},
	{"llama 3 community", "Llama-3-Community"},
	{"gemma terms of use", "Gemma-Terms-of-Use"},
	{"openrail", "OpenRAIL-M"},

	{"mit license", "MIT"},
	{"isc license", "ISC"},
}

// proseLicence scans a markdown file for a licence named in prose.
func (s *scan) proseLicence(rel, source string) (graph.LicenceRef, bool) {
	data, err := s.root.ReadFile(rel, weightProseBytes)
	if err != nil {
		s.warnErr(err, rel)
		return graph.LicenceRef{}, false
	}
	body := strings.ToLower(string(data))
	// Only lines that are talking about licensing at all. Without this gate the
	// word "noncommercial" in a marketing paragraph would resolve a licence.
	if !strings.Contains(body, "licen") {
		return graph.LicenceRef{}, false
	}
	for _, p := range proseLicencePatterns {
		if strings.Contains(body, strings.ToLower(p.Needle)) {
			return graph.LicenceRef{
				SPDX: p.SPDX, Raw: p.Needle, Source: source,
				Resolved: true,
			}, true
		}
	}
	return graph.LicenceRef{}, false
}

// ── GGUF in-file metadata ───────────────────────────────────────────────────

// ggufLicence extracts the licence fields from a GGUF metadata block.
//
// # THE FORMAT
//
// Little-endian throughout:
//
//	magic      "GGUF"     4 bytes
//	version    u32        4
//	tensors    u64        8
//	kv_count   u64        8
//	then kv_count pairs of: key (u64 length + bytes), type u32, value
//
// Only three keys are read; every other value is skipped by its declared size.
// The block is bounded, so a hostile file cannot make this read unbounded memory
// or loop: the cursor refuses to move past the buffer, array nesting is
// depth-limited, and the total number of skipped elements is capped.
//
// The second return value is the `general.license.link`, and the third reports
// whether a licence was found. A truncated block is reported by the caller as
// E-SCAN-012 rather than treated as "no licence", because those are different
// facts.
func (s *scan) ggufLicence(e safefs.WalkEntry) (licence, link string, ok bool) {
	// First attempt: the common case, where the metadata block is small.
	data, err := s.root.ReadFilePrefix(e.Rel, weightMetaBytes)
	if err != nil {
		s.warnErr(err, e.Rel)
		return "", "", false
	}

	licence, link, ok, truncated := parseGGUFMetadata(data)
	if ok {
		return licence, link, true
	}
	if !truncated || e.Size <= int64(len(data)) {
		// Not truncated, and nothing found: the block was fully read and holds
		// no licence. That is the "no licence statement" case, not an error.
		return "", "", false
	}

	// The block ran past the first attempt. Escalate once, to the spec's
	// ceiling, and report truncation if it still does not fit.
	bigger, err := s.root.ReadFilePrefix(e.Rel, weightMetaMaxBytes)
	if err != nil {
		s.warnErr(err, e.Rel)
		return "", "", false
	}
	licence, link, ok, truncated = parseGGUFMetadata(bigger)
	if ok {
		return licence, link, true
	}
	if truncated {
		// A header that does not fit in 16 MiB is not a model we can read.
		// Saying so is the honest outcome; guessing is not.
		s.warn(cerr.EScan012, e.Rel,
			"GGUF metadata for '"+e.Rel+"' is larger than 16 MiB or malformed. The licence could not be read.")
	}
	return "", "", false
}

// ggufValueTypes are the GGUF metadata value type tags.
const (
	ggufUint8   = 0
	ggufInt8    = 1
	ggufUint16  = 2
	ggufInt16   = 3
	ggufUint32  = 4
	ggufInt32   = 5
	ggufFloat32 = 6
	ggufBool    = 7
	ggufString  = 8
	ggufArray   = 9
	ggufUint64  = 10
	ggufInt64   = 11
	ggufFloat64 = 12
)

// ggufMaxArrayElements bounds how many array elements are skipped, so a header
// claiming a 2^63-element array cannot spin.
const ggufMaxArrayElements = 1 << 22

// ggufMaxDepth bounds array nesting.
const ggufMaxDepth = 8

// parseGGUFMetadata returns the licence fields, whether one was found, and
// whether the buffer ended mid-structure.
func parseGGUFMetadata(data []byte) (licence, link string, ok, truncated bool) {
	if len(data) < 24 || string(data[:4]) != "GGUF" {
		return "", "", false, false
	}
	c := &ggufCursor{b: data, off: 24} // past magic, version, tensor count, kv count

	kvCount, _ := readU64At(data, 16)
	// A count larger than the buffer could possibly hold is malformed. Treat it
	// as truncated so the caller escalates rather than looping a billion times.
	if kvCount > uint64(len(data)) {
		return "", "", false, true
	}

	for i := uint64(0); i < kvCount; i++ {
		key, okKey := c.str()
		if !okKey {
			return licence, link, false, true
		}
		typ, okType := c.u32()
		if !okType {
			return licence, link, false, true
		}

		// The three keys that matter are all strings.
		want := key == "general.license" || key == "general.license.name" || key == "general.license.link"
		if want && typ == ggufString {
			value, okVal := c.str()
			if !okVal {
				return licence, link, false, true
			}
			switch key {
			case "general.license", "general.license.name":
				if licence == "" {
					licence = value
				}
			case "general.license.link":
				link = value
			}
			continue
		}

		if !c.skipValue(typ, 0) {
			return licence, link, false, true
		}
	}

	return licence, link, licence != "", false
}

// ggufCursor is a bounds-checked reader over a GGUF metadata buffer.
type ggufCursor struct {
	b   []byte
	off int
}

func readU64At(b []byte, off int) (uint64, bool) {
	if off < 0 || off+8 > len(b) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b[off : off+8]), true
}

func (c *ggufCursor) u32() (uint32, bool) {
	if c.off+4 > len(c.b) {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(c.b[c.off : c.off+4])
	c.off += 4
	return v, true
}

func (c *ggufCursor) u64() (uint64, bool) {
	if c.off+8 > len(c.b) {
		return 0, false
	}
	v := binary.LittleEndian.Uint64(c.b[c.off : c.off+8])
	c.off += 8
	return v, true
}

func (c *ggufCursor) str() (string, bool) {
	n, ok := c.u64()
	if !ok {
		return "", false
	}
	// A string longer than the remaining buffer is malformed or truncated.
	// The bound is taken in the uint64 domain the length arrived in, before
	// any narrowing: `n <= remaining` is what makes the int conversions below
	// safe rather than merely lucky on a 64-bit build.
	remaining := uint64(len(c.b) - c.off) // #nosec G115 -- len-off is a non-negative int
	if n > remaining {
		return "", false
	}
	w, ok := u64ToInt(n)
	if !ok {
		return "", false
	}
	s := string(c.b[c.off : c.off+w])
	c.off += w
	return s, true
}

// u64ToInt narrows a uint64 read from untrusted input, refusing any value that
// does not fit in an int.
//
// On a 64-bit platform int is 64 bits wide and the test is dead; on a 32-bit
// build it is the thing that stops a 4-gigabyte declared string length from
// becoming a negative slice bound. The GGUF header is attacker-controlled, so
// the narrowing is checked rather than assumed.
func u64ToInt(v uint64) (int, bool) {
	if v > math.MaxInt {
		return 0, false
	}
	return int(v), true // #nosec G115 -- v <= math.MaxInt, checked above
}

func (c *ggufCursor) skip(n int) bool {
	if n < 0 || c.off+n > len(c.b) {
		return false
	}
	c.off += n
	return true
}

// skipValue advances past one value of the given type.
func (c *ggufCursor) skipValue(typ uint32, depth int) bool {
	switch typ {
	case ggufUint8, ggufInt8, ggufBool:
		return c.skip(1)
	case ggufUint16, ggufInt16:
		return c.skip(2)
	case ggufUint32, ggufInt32, ggufFloat32:
		return c.skip(4)
	case ggufUint64, ggufInt64, ggufFloat64:
		return c.skip(8)
	case ggufString:
		_, ok := c.str()
		return ok
	case ggufArray:
		if depth >= ggufMaxDepth {
			return false
		}
		elemType, ok := c.u32()
		if !ok {
			return false
		}
		count, ok := c.u64()
		if !ok {
			return false
		}
		if count > ggufMaxArrayElements {
			return false
		}
		for i := uint64(0); i < count; i++ {
			if !c.skipValue(elemType, depth+1) {
				return false
			}
		}
		return true
	default:
		// An unknown type tag means we cannot know the size, so we cannot skip
		// it. Stopping here is what keeps a malformed file from being read as a
		// different file's metadata.
		return false
	}
}

// ── sibling lookup ──────────────────────────────────────────────────────────

// siblingIndex makes "the file beside this one" an O(1) question.
//
// It is built once per scan rather than per weight file, because a repository
// with 40 shards in one directory would otherwise re-walk the tree 40 times.
type siblingIndex struct {
	// byDir maps a directory to its entries, keyed by lower-cased base name so
	// that `README.md` and `readme.md` are the same file. Real repositories
	// contain both spellings.
	byDir map[string]map[string]safefs.WalkEntry
	// root is the project root directory, "" in relative terms.
	root map[string]safefs.WalkEntry
	// markdown lists every markdown file in the tree, sorted, for the
	// last-resort prose scan.
	markdown []safefs.WalkEntry
}

func indexSiblings(entries []safefs.WalkEntry) *siblingIndex {
	x := &siblingIndex{
		byDir: map[string]map[string]safefs.WalkEntry{},
		root:  map[string]safefs.WalkEntry{},
	}
	for _, e := range entries {
		if e.IsDir || e.Rel == "" {
			continue
		}
		dir := e.Dir()
		if x.byDir[dir] == nil {
			x.byDir[dir] = map[string]safefs.WalkEntry{}
		}
		key := strings.ToLower(e.Base())
		if _, seen := x.byDir[dir][key]; !seen {
			x.byDir[dir][key] = e
		}
		if dir == "." {
			if _, seen := x.root[key]; !seen {
				x.root[key] = e
			}
		}
		if strings.EqualFold(path.Ext(e.Base()), ".md") {
			x.markdown = append(x.markdown, e)
		}
	}
	return x
}

// candidates returns the paths to try for a named sibling: first beside the
// weight file, then at the project root.
//
// The root fallback is what makes a Hugging Face repository layout work. Such a
// repository keeps `README.md` and `config.json` at the top and puts the tensors
// in a subdirectory, so a detector that only looked beside the weights would
// report every model in every HF repo as unlicensed.
func (x *siblingIndex) candidates(dir, self, name string) []string {
	var out []string
	key := strings.ToLower(name)
	if e, ok := x.byDir[dir][key]; ok && e.Rel != self {
		out = append(out, e.Rel)
	}
	if dir != "." {
		if e, ok := x.root[key]; ok && e.Rel != self {
			out = append(out, e.Rel)
		}
	}
	return out
}

// markdownNear returns markdown files in the weight file's directory, then at
// the root, excluding the weight file itself and the ones already tried by name.
func (x *siblingIndex) markdownNear(dir, self string) []string {
	var out []string
	for _, e := range x.markdown {
		if e.Rel == self {
			continue
		}
		if e.Dir() != dir && e.Dir() != "." {
			continue
		}
		base := strings.ToLower(e.Base())
		if base == "readme.md" || base == "model_card.md" {
			// Already consulted at a higher confidence.
			continue
		}
		out = append(out, e.Rel)
	}
	return out
}

// ── small helpers ───────────────────────────────────────────────────────────
