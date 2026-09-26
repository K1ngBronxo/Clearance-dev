package scanner

import "strings"

// Licence RECOGNITION, not licence JUDGEMENT.
//
// This file answers exactly one question: given a blob of text, which licence
// is it? It does not answer whether that licence is acceptable, what it
// obliges, or what it means for the user — that is the corpus's job and the
// policy engine's arithmetic (ADR-003). Keeping recognition here and judgement
// there is why a new licence can be added to the corpus without touching the
// scanner, and why the scanner is testable without a corpus at all.
//
// RECOGNITION IS BY DISTINCTIVE PHRASE, AND IT PREFERS TO FAIL
//
// Each recogniser requires phrases that appear verbatim in the canonical text
// of that licence. The table is ordered most-specific-first and the FIRST match
// wins, because several licences share an opening (BSD-2-Clause and
// BSD-3-Clause both begin "Redistribution and use in source and binary forms").
//
// When nothing matches, the caller records the licence as UNRESOLVED. That is
// the correct outcome rather than a gap to be closed: a wrong identification is
// worse than no identification, because it would attach another licence's
// obligations to this dependency and produce a confident verdict about the
// wrong terms. E-SCAN-011 exists precisely to say "a human should read this".
//
// Note the deliberate omissions. 0BSD and ISC differ only in whether the
// warranty disclaimer is present, which is too fine a line to draw from a
// phrase match; Zlib and a bare "as-is" disclaimer are similarly close. Those
// texts fall through to unresolved, which is honest, and a corpus recogniser
// entry can be added later when there is a real example to test against.

// recogniser identifies one licence from distinctive phrases.
type recogniser struct {
	spdx string
	// all phrases must be present. Matching is case-insensitive on
	// whitespace-normalised text.
	all []string
	// none phrases must be absent. This is what separates licences whose texts
	// contain one another, such as BSD-3-Clause and BSD-2-Clause.
	none []string
	// confidence in the identification. A licence that is only distinguishable
	// by a version-and-date line is still high confidence, because that line is
	// the licence's own version stamp.
	confidence string
}

// licenceRecognisers is ordered. The order is significant and load-bearing:
// the first match wins, so a more specific licence must appear before a less
// specific one that would also match its text.
var licenceRecognisers = []recogniser{
	// ── the GNU family, which is why order matters ──────────────────────────
	// "GNU AFFERO GENERAL PUBLIC LICENSE" does not contain the substring
	// "gnu general public license" (the "GNU " prefix is not repeated), so
	// these three do not actually collide. They are ordered anyway, because a
	// future edit that relaxes one marker must not silently start matching the
	// others.
	{
		spdx: "AGPL-3.0-only",
		all: []string{
			"gnu affero general public license",
			"version 3, 19 november 2007",
		},
		confidence: "high",
	},
	{
		spdx: "LGPL-3.0-only",
		all: []string{
			"gnu lesser general public license",
			"version 3, 29 june 2007",
		},
		confidence: "high",
	},
	{
		spdx: "GPL-3.0-only",
		all: []string{
			"gnu general public license",
			"version 3, 29 june 2007",
		},
		confidence: "high",
	},
	{
		spdx: "GPL-2.0-only",
		all: []string{
			"gnu general public license",
			"version 2, june 1991",
		},
		confidence: "high",
	},

	// ── source-available licences that are commonly mistaken for open source ─
	// These matter disproportionately: they are the licences most likely to
	// turn an assumed SHIP into a DO NOT SHIP, so they must never be missed.
	{
		spdx: "SSPL-1.0",
		all: []string{
			"server side public license",
		},
		confidence: "high",
	},
	{
		spdx: "Elastic-2.0",
		all: []string{
			"elastic license 2.0",
		},
		confidence: "high",
	},
	{
		spdx: "BUSL-1.1",
		all: []string{
			"business source license 1.1",
		},
		confidence: "high",
	},

	// ── permissive and weak-copyleft ────────────────────────────────────────
	{
		spdx: "MPL-2.0",
		all: []string{
			"mozilla public license version 2.0",
		},
		confidence: "high",
	},
	{
		spdx: "Apache-2.0",
		all: []string{
			"apache license",
			"version 2.0, january 2004",
		},
		confidence: "high",
	},

	// ── Creative Commons, including the non-commercial variant that is the
	//    single most common trap for model weights ───────────────────────────
	{
		spdx: "CC-BY-NC-4.0",
		all: []string{
			"attribution-noncommercial 4.0 international",
		},
		confidence: "high",
	},
	{
		spdx: "CC-BY-4.0",
		all: []string{
			"creative commons attribution 4.0 international",
		},
		confidence: "high",
	},
	{
		spdx: "CC0-1.0",
		all: []string{
			"cc0 1.0 universal",
		},
		confidence: "high",
	},

	// ── the BSD pair, separated by the third clause ─────────────────────────
	{
		spdx: "BSD-3-Clause",
		all: []string{
			"redistribution and use in source and binary forms",
			"neither the name of",
		},
		confidence: "high",
	},
	{
		spdx: "BSD-2-Clause",
		all: []string{
			"redistribution and use in source and binary forms",
		},
		none: []string{
			"neither the name of",
		},
		confidence: "high",
	},

	{
		spdx: "ISC",
		all: []string{
			"permission to use, copy, modify, and/or distribute this software for any purpose",
			"without fee is hereby granted",
		},
		confidence: "high",
	},
	{
		spdx: "MIT",
		all: []string{
			"permission is hereby granted, free of charge, to any person obtaining a copy",
			"without warranty of any kind",
		},
		confidence: "high",
	},
	{
		spdx: "Zlib",
		all: []string{
			"altered source versions must be plainly marked as such",
		},
		confidence: "high",
	},
	{
		spdx: "Unlicense",
		all: []string{
			"this is free and unencumbered software released into the public domain",
		},
		confidence: "high",
	},
}

// Recognise identifies a licence from its text.
//
// It returns the SPDX identifier, the confidence of the identification, and
// whether anything matched. On no match the caller must record the licence as
// unresolved rather than guessing — see the note at the top of this file.
func Recognise(text string) (spdx string, confidence string, ok bool) {
	haystack := normaliseLicenceText(text)
	if haystack == "" {
		return "", "", false
	}
	for _, r := range licenceRecognisers {
		if r.matches(haystack) {
			return r.spdx, r.confidence, true
		}
	}
	return "", "", false
}

// matches reports whether every `all` phrase is present and no `none` phrase
// is. The haystack must already be normalised.
func (r recogniser) matches(haystack string) bool {
	for _, p := range r.all {
		if !strings.Contains(haystack, p) {
			return false
		}
	}
	for _, p := range r.none {
		if strings.Contains(haystack, p) {
			return false
		}
	}
	return true
}

// normaliseLicenceText lowercases and collapses all whitespace to single
// spaces, so that a licence reflowed to a different column width still matches.
//
// It also folds the typographic characters that appear when a licence has been
// through a word processor: curly quotes, en and em dashes, and non-breaking
// spaces. Without this, a LICENSE file saved by a text editor that "smartens"
// punctuation would fail to match, and the tool would report an unresolved
// licence on a perfectly ordinary MIT file.
func normaliseLicenceText(text string) string {
	if len(text) > 4<<20 {
		text = text[:4<<20]
	}
	replacer := strings.NewReplacer(
		"\u2018", "'", "\u2019", "'",
		"\u201c", "\"", "\u201d", "\"",
		"\u2013", "-", "\u2014", "-",
		"\u00a0", " ", "\u202f", " ", "\ufeff", "",
	)
	s := replacer.Replace(text)
	s = strings.ToLower(s)
	return strings.Join(strings.Fields(s), " ")
}

// IsLicenceFileName reports whether a file's base name is conventionally a
// licence file. It is a *candidate* test, not a decision: the caller still has
// to recognise the contents, because a file called LICENSE can contain anything
// and a file called COPYING can be a build script.
func IsLicenceFileName(base string) bool {
	l := strings.ToLower(base)
	switch l {
	case "license", "licence", "license.txt", "licence.txt",
		"license.md", "licence.md", "copying", "copying.txt",
		"copyright", "copyright.txt", "unlicense", "notice":
		return true
	}
	for _, p := range []string{"license-", "licence-", "license.", "licence.", "copying.", "copyright."} {
		if strings.HasPrefix(l, p) && len(l) > len(p) {
			return true
		}
	}
	return false
}
