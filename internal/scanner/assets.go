// The brand-asset detector.
//
// # WHY THIS FILE EXISTS
//
// A permissively licensed project can still reserve its name, its logo and its
// icon. Apache-2.0 §6 says in terms that the licence grants no trademark rights
// — "This License does not grant permission to use the trade names, trademarks,
// service marks, or product names of the Licensor" — and many projects restate
// it in a TRADEMARK file. So a fork that keeps the name has a trademark problem
// even though the copyright licence permits the fork, and no licence scanner
// mentions it.
//
// # WHAT THIS FILE DELIBERATELY DOES NOT DO
//
// **It does not read images.** §5 is explicit: "No OCR, no image analysis." The
// detector reads *text files* that reserve brand rights and *filenames* that
// indicate brand assets. Recognising a logo inside a PNG would be unreliable,
// and an unreliable detector that cries "trademark" is worse than one that
// stays quiet.
//
// **It does not decide anything.** The node it emits says "this vendored
// dependency carries a brand signal, here is the file that carries it". Whether
// that matters is the corpus's judgement: corpus/traps/excluded-brand-assets.yml
// fires only when the dependency is an asset AND the project distributes. A
// private internal use emits the node and produces no finding, which is the
// conditional-obligation model working exactly as the spec's §4 note describes.
//
// **It only looks inside vendored dependencies.** A logo in the project's own
// source is the project's own asset; §6's failure table says "no finding — it
// is your asset", and a detector that flagged it would tell every project it
// had infringed itself.
package scanner

import (
	"path"
	"sort"
	"strings"

	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/safefs"
)

// assetFileBytes bounds a TRADEMARK / NOTICE / LICENSE read. The largest real
// licence file is well under 64 KiB; this is generous and is the same order of
// magnitude as the scanner's licence limit.
const assetFileBytes = 256 << 10

// assetSignals are the detection vocabulary. A signal is a fact — "a file with
// this name exists", "this text reserves a trademark" — never a judgement, for
// the same reason signalBin and signalHost are facts in upstream.go.
const (
	assetTrademarkFile = "trademark_file"  // a TRADEMARK / TRADEMARKS.md file
	assetNoticeClause  = "notice_clause"   // a NOTICE that reserves trademarks
	assetLicenceClause = "licence_clause"  // a LICENSE line that excludes the name/logo
	assetBrandFilename = "brand_filename"  // logo.*, icon.*, favicon.*, …
	assetBrandDir      = "brand_directory" // a brand/ directory
)

// brandFileStems are the file stems that name a brand asset. §2's row is
// "Files named logo.*, icon.*, favicon.*, wordmark.*, logotype.*, brand.* in a
// vendored dependency", and the stem is what that row keys on.
var brandFileStems = map[string]bool{
	"logo": true, "icon": true, "favicon": true,
	"wordmark": true, "logotype": true, "brand": true,
}

// trademarkFileStems are the file stems that, by their presence alone, reserve
// a brand. §2 rates any of them HIGH: a project that ships a TRADEMARK file has
// said, in the most deliberate way it can, that the name is not the licence.
var trademarkFileStems = map[string]bool{
	"trademark": true, "trademarks": true,
}

// brandNouns are the things a reservation clause can be about.
var brandNouns = []string{
	"trademark", "trade mark", "trade name", "trade names",
	"service mark", "logo", "brand name", "name and logo",
	"names and logos", "product name",
}

// brandNegations are the phrases that turn a mention of a brand noun into a
// reservation of one. Both a noun and a negation are required, so a page that
// merely says "Apache is a trademark of the ASF" is not read as a reservation.
//
// # WHY A PAIR AND NOT A LIST OF SENTENCES
//
// Matching whole sentences would be a list of the exact wordings that have been
// seen, and it would silently miss the next project that phrases the same
// reservation differently. A noun-plus-negation test is the property the clause
// actually has: the licence *does not cover* the mark. It is deliberately
// conservative in the direction that matters — a miss costs one finding, while
// a false positive tells a user to rebrand a product they are entitled to name.
var brandNegations = []string{
	"not covered", "not grant", "does not grant", "not granted",
	"not licensed", "not included", "not conveyed", "not permitted",
	"no right", "are excluded", "remain the property", "are reserved",
	"requires permission", "prior written permission", "not authorized to use",
	"may not use",
}

// assetSignal is one observed brand signal.
type assetSignal struct {
	Kind       string
	Confidence string
	Path       string
	Line       int
	Excerpt    string
}

// detectAssets finds brand-asset signals in vendored dependencies and records
// each affected dependency as a KindAsset node.
//
// One node per dependency, not per file (§4 step 4): a package with a TRADEMARK
// file and a logo and a brand/ directory is one unit carrying one obligation,
// and three findings for it would bury the one that matters. The node's
// Evidence points at the strongest signal found.
func (s *scan) detectAssets(entries []safefs.WalkEntry) {
	// Grouped by the directory that carries the signal. That directory is the
	// unit the spec calls "a dependency": the vendored package the file lives
	// in. Grouping by the file's own directory rather than by guessing a
	// package root is the conservative choice — it can never merge two
	// different packages into one node, which is the direction that would
	// attribute one project's trademark to another's.
	byDir := map[string]assetSignal{}
	var order []string

	record := func(sig assetSignal) {
		dir := path.Dir(sig.Path)
		if dir == "." || dir == "" {
			return
		}
		prev, seen := byDir[dir]
		if !seen {
			byDir[dir] = sig
			order = append(order, dir)
			return
		}
		// The strongest signal wins, so a package found both by a MEDIUM
		// filename and a HIGH reservation clause is recorded at HIGH rather
		// than at whichever file the walk reached first. Ties break on the
		// path so the choice is deterministic (INV-6).
		if assetStronger(sig, prev) {
			byDir[dir] = sig
		}
	}

	for _, e := range entries {
		if e.Rel == "" || !insideDependencyDir(e.Rel) {
			// Only vendored dependencies count. A brand asset in the project's
			// own source is the project's own asset. See the package comment.
			continue
		}

		if e.IsDir {
			if strings.EqualFold(e.Base(), "brand") {
				// A `brand/` directory. `assets/brand/` is the same directory
				// one level down, and the base-name test covers both.
				record(assetSignal{
					Kind: assetBrandDir, Confidence: detectMedium, Path: e.Rel,
				})
			}
			continue
		}

		base := strings.ToLower(e.Base())
		stem := brandStem(base)

		if brandFileStems[stem] {
			record(assetSignal{
				Kind: assetBrandFilename, Confidence: detectMedium, Path: e.Rel,
			})
		}
		if trademarkFileStems[stem] {
			// Presence alone is the HIGH signal §2 names. The file is read
			// anyway so that an unreadable one is reported rather than
			// silently counted: §6's failure table says "skip, warn, no finding
			// for that dependency".
			text, err := s.readBrandFile(e.Rel)
			if err != nil {
				s.warnErr(err, e.Rel)
				continue
			}
			line, excerpt := brandEvidenceLine(text)
			record(assetSignal{
				Kind: assetTrademarkFile, Confidence: detectHigh,
				Path: e.Rel, Line: line, Excerpt: excerpt,
			})
			continue
		}

		// NOTICE and LICENSE are the content-based signals. Both are read
		// without warning on failure: attachVendoredLicences already reads
		// every licence file and reports an unreadable one, and a second
		// warning for the same file would be noise rather than information.
		if isNoticeName(base) {
			text, err := s.readBrandFile(e.Rel)
			if err != nil || !hasBrandReservation(text) {
				continue
			}
			line, excerpt := brandEvidenceLine(text)
			record(assetSignal{
				Kind: assetNoticeClause, Confidence: detectHigh,
				Path: e.Rel, Line: line, Excerpt: excerpt,
			})
			continue
		}
		if IsLicenceFileName(e.Base()) {
			text, err := s.readBrandFile(e.Rel)
			if err != nil || !hasBrandReservation(text) {
				continue
			}
			line, excerpt := brandEvidenceLine(text)
			record(assetSignal{
				Kind: assetLicenceClause, Confidence: detectHigh,
				Path: e.Rel, Line: line, Excerpt: excerpt,
			})
		}
	}

	// Deterministic emission order. The map above is iterated to build the
	// graph and a map is never allowed to reach output (INV-6).
	sort.Strings(order)
	for _, dir := range order {
		sig := byDir[dir]
		s.g.Add(graph.Dependency{
			ID:        graph.LocalID(graph.KindAsset, dir),
			Kind:      graph.KindAsset,
			Name:      dir,
			Ecosystem: "local",
			Direct:    true,
			Scope:     s.containingScope(sig.Path),
			Licence: graph.LicenceRef{
				// Source is "detection" rather than a licence file: nothing
				// declared a licence for the asset, and a consumer of the JSON
				// must be able to tell that apart from a declared value. This
				// mirrors the upstream-CLI node in upstream.go.
				Source:     "detection",
				Confidence: sig.Confidence,
			},
			Evidence: []graph.Evidence{{
				Path:      sig.Path,
				LineStart: sig.Line,
				LineEnd:   sig.Line,
				Excerpt:   truncateExcerpt(sig.Excerpt),
			}},
			Metadata: map[string]string{
				"signal":      sig.Kind,
				"signal_path": sig.Path,
			},
		})
	}
}

// readBrandFile reads a brand-relevant text file through safefs.
func (s *scan) readBrandFile(rel string) (string, error) {
	data, err := s.root.ReadFile(rel, assetFileBytes)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// isNoticeName reports whether a base name is a NOTICE file. IsLicenceFileName
// also accepts "notice", but this is the explicit spelling the spec's signal
// names, and it keeps the NOTICE branch readable.
func isNoticeName(base string) bool {
	switch base {
	case "notice", "notice.txt", "notice.md":
		return true
	}
	return false
}

// brandStem returns the lowercased stem of a base name: the name without its
// final extension, so "logo.svg" yields "logo". A dotfile has no stem, and a
// bare name is its own stem.
func brandStem(base string) string {
	if strings.HasPrefix(base, ".") {
		return ""
	}
	return strings.TrimSuffix(base, path.Ext(base))
}

// hasBrandReservation reports whether a block of text reserves a brand. It
// requires both a brand noun and a reservation phrase anywhere in the file, and
// it normalises the text with the licence matcher's own normaliser so that a
// clause that has been through a word processor still matches. See the
// comments on brandNouns and brandNegations for why the test is a pair and not
// a list of sentences.
func hasBrandReservation(text string) bool {
	if text == "" {
		return false
	}
	norm := normaliseLicenceText(text)
	return hasBrandNoun(norm) && hasBrandNegation(norm)
}

func hasBrandNoun(norm string) bool {
	for _, n := range brandNouns {
		if strings.Contains(norm, n) {
			return true
		}
	}
	return false
}

func hasBrandNegation(norm string) bool {
	for _, neg := range brandNegations {
		if strings.Contains(norm, neg) {
			return true
		}
	}
	return false
}

// brandEvidenceLine returns the 1-based line and trimmed text of the first line
// that names a brand, falling back to the first non-empty line. Pointing the
// evidence at the line that carries the mark is what makes the finding
// actionable: the reader is sent to the reservation sentence, not to a
// copyright header.
func brandEvidenceLine(text string) (int, string) {
	lines := strings.Split(text, "\n")
	for i, raw := range lines {
		if hasBrandNoun(normaliseLicenceText(raw)) {
			return i + 1, strings.TrimSpace(raw)
		}
	}
	for i, raw := range lines {
		if t := strings.TrimSpace(raw); t != "" {
			return i + 1, t
		}
	}
	return 0, ""
}

// assetStronger reports whether a should replace b as a directory's recorded
// signal. HIGH beats MEDIUM; equal confidence breaks on the path, then the
// signal kind, so the result is independent of walk order.
func assetStronger(a, b assetSignal) bool {
	rank := func(c string) int {
		if c == detectHigh {
			return 0
		}
		return 1
	}
	if rank(a.Confidence) != rank(b.Confidence) {
		return rank(a.Confidence) < rank(b.Confidence)
	}
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	return a.Kind < b.Kind
}
