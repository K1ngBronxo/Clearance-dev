package corpus

import (
	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/safefs"
)

// LoadInstalled loads the corpus that is installed at opts.Dir.
//
// # WHY THIS EXISTS
//
// A corpus can be present in two shapes, and before this function the runtime
// could read only one of them.
//
//  1. **The compiled bundle** — `corpus.json`, `corpus.version.json` and
//     `corpus.json.sig`. This is what a release ships. It is the only shape that
//     can carry a signature, and therefore the only shape for which INV-9 ("no
//     verdict from an unverified corpus") is checkable at all.
//
//  2. **The YAML source tree** — `licences/`, `traps/`, `tos/`, `territories/`.
//     This is the contributor path: this repository's own `make dogfood`, every
//     fixture, and a corpus fork being edited. It carries no signature and
//     cannot carry one.
//
// `check` called `Load`, which reads only shape (2). `LoadBundle`, which reads
// shape (1) and *verifies* it, was reachable only from tests and from `corpus
// verify`. So a released binary — whose `corpus/` directory holds a bundle and
// no YAML — was handed a directory it could not parse, and `Load` refused it
// with `E-CORPUS-001`. The signature machinery worked perfectly and was never on
// the path a user's verdict travelled. That is the defect this function closes:
// the control existed, and nothing routed through it.
//
// # THE ORDER IS THE CONTROL, NOT A PREFERENCE
//
// The bundle is tried first, and when it is present it is **not optional**. A
// half-installed bundle — payload without manifest, or manifest without
// signature — must fail closed with the bundle loader's own error rather than
// quietly fall back to an unverified tree. Falling back would mean a partial
// copy produced a verdict indistinguishable from a verified one, which is the
// single failure this product exists to refuse.
//
// The YAML path stays available because development and contribution require
// it. It is not signature-verified, and the verdict says so out loud:
// `corpusIdentity` reports the version as `0.0.0-unsigned` and the meta block
// prints `UNSIGNED ✗`.
func LoadInstalled(opts LoadOptions) (*Corpus, error) {
	if opts.Dir == "" {
		return nil, cerr.New(cerr.ECorpus001, opts.Dir)
	}

	holds, err := holdsBundle(opts.Dir)
	if err != nil {
		return nil, err
	}
	if holds {
		// LoadBundle verifies the signature against the embedded public key and
		// refuses an unsigned or tampered bundle. Its errors are the ones a user
		// should see, so they are returned unmodified.
		return LoadBundle(opts.Dir)
	}
	return Load(opts)
}

// holdsBundle reports whether dir holds a compiled payload.
//
// It asks for the payload file **alone**, and deliberately not for the manifest
// or the signature. Their absence is the bundle loader's error to report, with
// the right code: `E-CORPUS-001` naming the missing file, or `E-CORPUS-002` for
// a bundle that is present but unsigned. Deciding here that an incomplete bundle
// "is not a bundle" would route it to the YAML loader instead, and that silent
// downgrade is precisely what this function exists to prevent.
//
// The probe goes through `safefs` for the same reason every other read does
// (INV-4 / C3): one function resolves paths and keeps reads inside the root, so
// a corpus directory that is itself a symlink is resolved once, in the place
// that also checks containment. Using `os.Stat` here would be a second, weaker
// answer to a question the codebase has already answered once.
//
// A directory that cannot be opened is not an error here. It is reported by the
// YAML loader with the `E-CORPUS-001` a user already recognises, so the message
// they see when they point the tool at nothing does not change.
func holdsBundle(dir string) (bool, error) {
	root, err := safefs.New(dir, safefs.Limits{MaxFiles: 16, MaxDepth: 4})
	if err != nil {
		return false, nil
	}
	if _, err := root.Stat(BundleFile); err != nil {
		return false, nil
	}
	return true, nil
}
