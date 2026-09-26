package ai

import (
	"fmt"
	"strings"
)

// redacted is what a Secret renders as, everywhere, always.
const redacted = "[redacted]"

// Secret is an API key.
//
// # WHY THIS TYPE EXISTS
//
// An API key is the only piece of data Clearance handles that is both (a)
// supplied by the user and (b) worth stealing. The failure mode is not a
// malicious actor; it is a well-meaning developer writing
//
//	fmt.Fprintf(os.Stderr, "clearance: using key %s\n", key)
//
// while debugging at 1am, or a struct containing a key being marshalled into
// `--format json`, or a wrapped error printing its arguments. Every one of
// those is a *rendering*, and every rendering of a plain `string` succeeds.
//
// So the key is not a string. It is a Secret, and a Secret cannot be rendered.
// It has no exported field, no accessor that returns the raw bytes into a
// variable, and it implements fmt.Formatter so that *every* verb — %v, %s, %q,
// %x, %d — produces `[redacted]` rather than the key.
//
// The only way to use one is Use, whose callback cannot outlive the call. That
// is the same structural trick as INV-1 (a Finding cannot be built without a
// citation): the safe behaviour is the only behaviour the code can express, so
// it does not depend on anyone remembering.
// # WHY THE FIELD IS A POINTER
//
// `%p` is handled by fmt *before* it consults Formatter — see fmt's printArg,
// which special-cases %T and %p ahead of the interface check. So a Secret whose
// key lived in a string field would print
//
//	%!p(ai.Secret={sk-live-...})
//
// because fmt falls back to the struct's default rendering for a verb it cannot
// apply. A pointer field means that fallback prints an address instead of the
// key, and the address is not a secret. It is the last verb, and it is the only
// one that had to be solved with the field's type rather than with a method.
type Secret struct {
	raw *string
}

// NewSecret wraps raw key material. An empty string yields the zero Secret,
// which Set reports as absent — so "no key" and "an empty key" are the same
// state, which is what a user means by both.
func NewSecret(raw string) Secret {
	t := strings.TrimSpace(raw)
	if t == "" {
		return Secret{}
	}
	return Secret{raw: &t}
}

// value returns the raw key, or "" when there is none.
func (s Secret) value() string {
	if s.raw == nil {
		return ""
	}
	return *s.raw
}

// Set reports whether a key is present. It is the only question a caller may
// ask about a Secret without using it.
func (s Secret) Set() bool { return s.raw != nil && *s.raw != "" }

// Len reports the key's length. It exists so that a diagnostic can say "a
// 51-character key was supplied" without saying which one, which is the
// distinction between a useful log line and a leaked credential.
func (s Secret) Len() int { return len(s.value()) }

// Use calls fn with the raw key material.
//
// The callback receives the key as an argument rather than a value the caller
// can keep, and the key is never returned. A caller therefore cannot write
//
//	k := secret.Use()
//	log.Println(k)
//
// because there is nothing for Use to return but an error. Passing the key
// into a closure that logs it is still possible — this type cannot stop a
// determined mistake — but it cannot happen by accident, and `TestSecretNeverLeaks`
// greps every output surface for a canary to prove the accident does not happen.
func (s Secret) Use(fn func(raw string) error) error {
	if fn == nil {
		return nil
	}
	return fn(s.value())
}

// String makes Secret a fmt.Stringer, which covers %v and %s.
func (s Secret) String() string { return redacted }

// GoString covers %#v, the verb a developer reaches for when printing a whole
// struct during debugging — the single most likely place a key would escape.
func (s Secret) GoString() string { return redacted }

// Format covers every other verb.
//
// fmt.Stringer alone is not enough. %q would quote the String() result (safe),
// but %x, %X and %d reach the underlying value and a `[]byte(secret)` or a
// struct tag would print something. Implementing Formatter means there is no
// verb left that can render the key, and the type is then safe in any context
// — including one nobody has thought of yet.
//
// The method is defined on the value receiver, so both Secret and *Secret are
// covered. That matters: a pointer is what a struct field most often is, and a
// pointer that did not implement Formatter would print `&{[redacted]}` via the
// default struct rendering, which leaks the *field* even though it does not
// leak the key. It is still wrong, and it is still caught here.
func (s Secret) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, redacted)
}

// MarshalJSON makes the key unmarshallable into JSON. A verdict, an
// ai-suggestions artefact, a SARIF file or a crash report that happens to
// contain a Secret serialises as `"[redacted]"`.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}

// MarshalText covers YAML, TOML and anything else that asks for text.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(redacted), nil
}

// Redact removes a known key from arbitrary text.
//
// Format and MarshalJSON protect the type. This protects the *string*, for the
// one case the type cannot reach: a provider that echoes the key back inside an
// error message or a response body, and a transport that wraps the provider's
// text into an error Clearance then prints.
//
// It is a belt to the type's braces, and it is the reason `--verbose` can print
// a raw response body without a key in it. Empty needles are ignored so that a
// missing key cannot blank a whole message.
func Redact(text string, secrets ...Secret) string {
	for _, s := range secrets {
		if raw := s.value(); raw != "" {
			text = strings.ReplaceAll(text, raw, redacted)
		}
	}
	return text
}

// RedactKeys is Redact for a set of raw strings, for the callers that hold the
// material before it has been wrapped — the key file reader, the environment
// reader and the stdin reader.
func RedactKeys(text string, keys ...string) string {
	for _, k := range keys {
		if len(strings.TrimSpace(k)) < 8 {
			// A very short "key" is far more likely to be a substring of
			// ordinary text than a credential, and replacing it would corrupt
			// the message. Real keys are long; this is not a security boundary,
			// it is a guard against mangling output.
			continue
		}
		text = strings.ReplaceAll(text, k, redacted)
	}
	return text
}
