// Package prov is the provenance vocabulary, inherited from AIO Core.
//
// Every value Clearance reports carries a provenance class. The classes are
// ordered from strongest to weakest, and the two rules that matter are:
//
//  1. Provenance degrades freely; it is upgraded only by audited correction
//     (INV-8, and the ecosystem rule inherited from AIO Core).
//  2. When several sources are combined, the result is the *weakest* of its
//     inputs. A strong source may never launder a weak one.
//
// This package is deliberately tiny and has no dependencies. It is L0.
package prov

// Class is how much a value can be trusted, and why.
type Class string

const (
	// Real — observed directly in the project: the bytes were read.
	// Example: a vendored LICENSE file whose text hashed to a known licence.
	Real Class = "real"

	// Derived — computed deterministically from real inputs by a rule that is
	// written down and reviewable.
	// Example: a lockfile's resolved version, or a verdict folded from findings.
	Derived Class = "derived"

	// Estimated — a curated statement about the world, not an observation of
	// this project. Carries a date, and goes stale.
	// Example: a platform ToS summary with a last_verified date.
	Estimated Class = "estimated"

	// Simulated — produced by a model or a synthetic process. Never a basis for
	// a verdict; may appear only as illustrative content.
	Simulated Class = "simulated"

	// Unknown — the tool could not determine this, and says so. This is a
	// first-class answer (INV-7) and is never rounded toward a pass.
	Unknown Class = "unknown"
)

// rank orders classes by strength. Higher is stronger. Unknown ranks below
// everything, so that combining it with anything yields Unknown — the
// conservative direction.
func rank(c Class) int {
	switch c {
	case Real:
		return 4
	case Derived:
		return 3
	case Estimated:
		return 2
	case Simulated:
		return 1
	case Unknown:
		return 0
	}
	return 0
}

// Combine returns the weakest of the given classes. This is the propagation
// rule: if one leg of an argument is uncertain, the conclusion is uncertain.
//
// Combine() with no arguments returns Unknown, because a claim with no support
// is exactly that.
func Combine(classes ...Class) Class {
	if len(classes) == 0 {
		return Unknown
	}
	weakest := classes[0]
	for _, c := range classes[1:] {
		if rank(c) < rank(weakest) {
			weakest = c
		}
	}
	return weakest
}

// Weaker reports whether a is weaker than b.
func Weaker(a, b Class) bool { return rank(a) < rank(b) }

// Valid reports whether c is one of the five defined classes. A provenance
// class that is not defined may not exist, for the same reason an error code
// that is not in the taxonomy may not exist.
func Valid(c Class) bool {
	switch c {
	case Real, Derived, Estimated, Simulated, Unknown:
		return true
	}
	return false
}

// Badge returns the short display label for a class. `real` deliberately has no
// badge: absence of a badge is the signal for the strongest class, the same
// convention the confidence model uses for HIGH.
func Badge(c Class) string {
	if c == Real {
		return ""
	}
	return string(c)
}
