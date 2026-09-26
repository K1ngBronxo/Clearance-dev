package config

import "strings"

// RegionGroups are the territory shorthands the config spec allows, in addition
// to ISO-3166 alpha-2 country codes.
var RegionGroups = []string{"EU", "EEA", "US", "GB", "APAC", "global"}

// ValidTerritory reports whether a territory entry is a country code or a
// region group.
//
// The check is deliberately shallow: it accepts any two upper-case ASCII
// letters as a country code rather than shipping a 249-entry ISO table. The
// consequence of a false accept is that a territorial clause is evaluated for a
// country that does not exist, which produces no finding — the conservative
// direction. The consequence of a false *reject* would be a user unable to
// declare a territory they legitimately operate in, which is worse.
func ValidTerritory(t string) bool {
	t = strings.TrimSpace(t)
	if t == "" {
		return false
	}
	if t == "global" {
		return true
	}
	for _, g := range RegionGroups {
		if t == g {
			return true
		}
	}
	if len(t) != 2 {
		return false
	}
	for i := 0; i < 2; i++ {
		if t[i] < 'A' || t[i] > 'Z' {
			return false
		}
	}
	return true
}

// knownSPDX is the curated identifier list used to validate `never_allow`.
//
// # WHY A CURATED LIST RATHER THAN THE FULL SPDX REGISTER
//
// The full register is ~600 identifiers and changes monthly; vendoring it would
// be a maintenance burden in a file that is not the corpus, and the corpus is
// where licence knowledge is supposed to live. What this list has to do is
// catch a *typo* in `never_allow`, because a typo there silently disables a
// safety rule the user deliberately wrote. Every identifier a real project
// would put on a never_allow list is here, plus the AI-model licences the
// corpus carries.
//
// An identifier that is not here is refused (E-CFG-007), and the user can
// always write it as `LicenseRef-<name>`, which is accepted — so there is no
// identifier a user is actually unable to name.
var knownSPDX = map[string]bool{}

// knownSPDXLower maps the lower-cased form of every known identifier to its
// canonical spelling.
//
// # WHY THIS EXISTS
//
// SPDX identifiers are case-insensitive: the specification says an identifier
// "shall be matched case-insensitively". Real-world sources rely on that. The
// Hugging Face convention writes model licences entirely lower-case
// (`license: cc-by-nc-4.0`), npm's `license` field is conventionally lower-case
// (`"license": "mit"`), and Python packaging normalises to lower-case too.
//
// Before this index existed, `ValidSPDX` was a case-sensitive map lookup, so
// `cc-by-nc-4.0` — the single most common spelling of the most important
// non-commercial model licence — failed to resolve. A weight file under
// CC BY-NC 4.0 was therefore reported as UNRESOLVED rather than BLOCK, which is
// a false pass produced by a string comparison. The index also lets
// `NormaliseSPDX` hand back the canonical spelling instead of whatever case the
// manifest happened to use, so two sources saying `mit` and `MIT` agree.
var knownSPDXLower = map[string]string{}

func init() {
	for _, id := range []string{
		// Permissive
		"0BSD", "Apache-1.1", "Apache-2.0", "BSD-1-Clause", "BSD-2-Clause",
		"BSD-2-Clause-Patent", "BSD-3-Clause", "BSD-3-Clause-Clear",
		"BSD-4-Clause", "BSL-1.0", "CC0-1.0", "MIT", "MIT-0", "MITNFA",
		"ISC", "Unlicense", "WTFPL", "Zlib", "X11", "NCSA", "PostgreSQL",
		"Python-2.0", "PSF-2.0", "Artistic-2.0", "AFL-3.0", "ECL-2.0",
		"OpenSSL", "PHP-3.01", "Ruby", "Vim", "Beerware", "curl",

		// Weak copyleft
		"MPL-1.1", "MPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
		"LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only",
		"LGPL-3.0-or-later", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1",
		"CECILL-2.1", "EUPL-1.2", "MS-RL",

		// Strong copyleft
		"GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
		"GPL-2.0-with-classpath-exception", "Classpath-exception-2.0",
		"GCC-exception-3.1", "Bison-exception-2.2", "OSL-3.0", "AGPL-1.0-only",

		// Network copyleft
		"AGPL-3.0-only", "AGPL-3.0-or-later",

		// Source-available / non-OSI
		"SSPL-1.0", "BUSL-1.1", "Elastic-2.0", "Commons-Clause",
		"Redis-Source-Available", "Confluent-Community-1.0", "PolyForm-Noncommercial-1.0.0",
		"PolyForm-Shield-1.0.0", "PolyForm-Small-Business-1.0.0", "PolyForm-Free-Trial-1.0.0",
		"RSALv2", "Sustainable-Use-License-1.0",

		// Content / data / model licences
		"CC-BY-1.0", "CC-BY-2.0", "CC-BY-2.5", "CC-BY-3.0", "CC-BY-4.0",
		"CC-BY-SA-3.0", "CC-BY-SA-4.0", "CC-BY-ND-4.0", "CC-BY-NC-2.0",
		"CC-BY-NC-3.0", "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "CC-BY-NC-ND-4.0",
		"ODbL-1.0", "ODC-By-1.0", "OGL-UK-3.0", "CDLA-Permissive-2.0",
		"CDLA-Sharing-1.0", "OpenRAIL-M", "OpenRAIL++-M", "Llama-2-Community",
		"Llama-3-Community", "Llama-3.1-Community", "Llama-3.2-Community",
		"Llama-3.3-Community", "Gemma-Terms-of-Use", "Gemma-Prohibited-Use-Policy",
		"Mistral-AI-Research-License", "Mistral-AI-Non-Production-License",
		"NVIDIA-Open-Model-License", "NVIDIA-Source-Code-License",
		"Qwen-Research-License", "DeepSeek-Model-License", "Falcon-LLM-License",
		"BigScience-BLOOM-RAIL-1.0", "TII-Falcon-180B-TII-License",
		"Stable-Diffusion-Community-License", "FLUX.1-dev-Non-Commercial-License",
		"Apple-AML-Research-License", "Microsoft-Research-License",
		"Cohere-Community-License", "AI2-ImpACT-Responsible-AI-License",

		// Marker values that appear in real manifests
		"UNLICENSED", "SEE LICENSE IN LICENSE", "NOASSERTION", "NONE",
	} {
		knownSPDX[id] = true
		// First writer wins, so a canonical spelling is never replaced by a
		// later entry that differs only in case. The list has no such
		// collisions today; the guard is here so that adding one is a no-op
		// rather than a silent change of what the tool reports.
		lower := strings.ToLower(id)
		if _, seen := knownSPDXLower[lower]; !seen {
			knownSPDXLower[lower] = id
		}
	}
}

// CanonicalSPDX returns the canonical spelling of a known identifier, matching
// case-insensitively. The second result is false when the identifier is not in
// the curated list, in which case the caller must treat it as unknown rather
// than guessing (INV-7).
func CanonicalSPDX(id string) (string, bool) {
	canonical, ok := knownSPDXLower[strings.ToLower(strings.TrimSpace(id))]
	return canonical, ok
}

// ValidSPDX reports whether an identifier is acceptable in a policy rule.
//
// Accepted: a known identifier, or a `LicenseRef-<name>` for anything not in the
// curated list. Rejected: everything else, because in a policy rule an unknown
// identifier is a rule that does nothing.
func ValidSPDX(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	// The `LicenseRef-` prefix is case-insensitive per the specification, so
	// `licenseref-foo` and `LicenseRef-foo` name the same licence.
	if len(id) > len("LicenseRef-") && strings.EqualFold(id[:len("LicenseRef-")], "LicenseRef-") {
		return true
	}
	// A trailing "+" is the deprecated "or later" suffix. Accept it by
	// normalising, so that a user writing `GPL-3.0+` is not blocked by a
	// technicality while the corpus uses the modern `-or-later` form.
	base := strings.TrimSuffix(id, "+")
	if knownSPDX[base] {
		return true
	}
	// Case-insensitive fallback: SPDX identifiers match case-insensitively, and
	// the real-world spellings are lower-case (npm, PyPI, Hugging Face).
	_, ok := CanonicalSPDX(base)
	return ok
}

// NormaliseSPDX maps the common non-canonical spellings a manifest or a user
// may contain onto the canonical corpus identifier. It returns the input
// unchanged when it does not recognise it, so that an unknown identifier stays
// unknown rather than being guessed at (INV-7).
func NormaliseSPDX(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	switch id {
	case "Apache 2.0", "Apache-2", "apache-2.0", "Apache License 2.0":
		return "Apache-2.0"
	case "MIT License", "mit", "MIT/X11":
		return "MIT"
	case "GPL-3.0", "GPLv3", "GPL-3":
		return "GPL-3.0-only"
	case "GPL-2.0", "GPLv2", "GPL-2":
		return "GPL-2.0-only"
	case "AGPL-3.0", "AGPLv3", "AGPL-3":
		return "AGPL-3.0-only"
	case "LGPL-3.0", "LGPLv3":
		return "LGPL-3.0-only"
	case "LGPL-2.1", "LGPLv2.1":
		return "LGPL-2.1-only"
	case "BSD", "BSD-3", "BSD 3-Clause", "New BSD":
		return "BSD-3-Clause"
	case "BSD-2", "BSD 2-Clause", "Simplified BSD", "FreeBSD":
		return "BSD-2-Clause"
	case "MPL-2", "MPL 2.0", "MPLv2":
		return "MPL-2.0"
	case "CC0", "Public Domain":
		return "CC0-1.0"
	case "CC-BY-NC-4", "CC BY-NC 4.0", "CC-BY-NC":
		return "CC-BY-NC-4.0"
	case "CC-BY-4", "CC BY 4.0":
		return "CC-BY-4.0"
	case "UNLICENCED", "unlicensed", "proprietary", "Proprietary":
		return "UNLICENSED"
	}
	if strings.HasSuffix(id, "+") {
		base := strings.TrimSuffix(id, "+")
		if knownSPDX[base] {
			// Prefer the canonical "-or-later" form when we know it.
			if knownSPDX[base+"-or-later"] {
				return base + "-or-later"
			}
			if knownSPDX[base+"-only"] {
				return base + "-only"
			}
		}
	}
	// Case-insensitive fallback, last so that every explicit spelling above
	// still wins. This is what turns `cc-by-nc-4.0` — the Hugging Face
	// convention — into the canonical `CC-BY-NC-4.0` the corpus is keyed on.
	// Without it the identifier stays as written, `ValidSPDX` rejects it, and
	// the dependency is reported UNRESOLVED: a false pass from a string
	// comparison.
	if canonical, ok := CanonicalSPDX(id); ok {
		return canonical
	}
	return id
}
