package parsers

import (
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/safejson"
)

// NPM reads package.json and package-lock.json.
//
// pnpm-lock.yaml and yarn.lock are NOT parsed in this slice, and that is a
// deliberate refusal rather than an oversight: their formats differ enough
// between versions that a heuristic parse would produce a dependency graph that
// is quietly wrong, and a quietly wrong graph produces a confident verdict
// about a project that does not exist. When a pnpm or yarn lockfile is the only
// one present, the manifest is used instead and the verdict carries the range
// caveat — which is the honest answer.
type NPM struct{}

func (NPM) Ecosystem() string { return "npm" }

func (NPM) ManifestNames() []string { return []string{"package.json"} }

func (NPM) LockfileNames() []string {
	return []string{"package-lock.json", "npm-shrinkwrap.json"}
}

// UnsupportedLockfiles are the lockfiles this parser recognises but does not
// read, so that the scanner can say so instead of silently falling back.
func (NPM) UnsupportedLockfiles() []string {
	return []string{"pnpm-lock.yaml", "yarn.lock"}
}

func (NPM) ParseManifest(rel string, data []byte) (Result, error) {
	obj, err := parseJSONObject(data)
	if err != nil {
		return Result{}, cerr.Wrap(cerr.EParse002, err, rel, describeParseError(err))
	}

	declaredLicence := jsonString(obj, "license")
	if declaredLicence == "" {
		// The older, deprecated `licenses` array form: [{ "type": "MIT", "url": … }].
		// The first entry's type is the declaration. Reading it matters because a
		// package that only uses the legacy form would otherwise look unlicensed,
		// and "unlicensed" is the strongest claim this tool can make.
		if arr, ok := obj.Get("licenses"); ok {
			if list, isList := arr.([]safejson.Value); isList && len(list) > 0 {
				if first, isObj := list[0].(safejson.Object); isObj {
					declaredLicence = jsonString(first, "type")
				} else if s, isStr := list[0].(string); isStr {
					declaredLicence = s
				}
			}
		}
		// `licence` is the British spelling and appears in the wild.
		if declaredLicence == "" {
			declaredLicence = jsonString(obj, "licence")
		}
	}

	var out []Declared
	groups := []struct {
		key      string
		dev      bool
		optional bool
	}{
		{"dependencies", false, false},
		{"devDependencies", true, false},
		{"peerDependencies", false, false},
		{"optionalDependencies", false, true},
		{"bundledDependencies", false, false},
	}
	for _, g := range groups {
		sub := jsonObjectMember(obj, g.key)
		for _, name := range sub.Keys {
			v, _ := sub.Get(name)
			ver, _ := v.(string)
			out = append(out, Declared{
				Ecosystem:  "npm",
				Name:       name,
				Version:    cleanVersion(ver),
				IsRange:    isRange(ver),
				Direct:     true,
				SourcePath: rel,
				Dev:        g.dev,
				Optional:   g.optional,
			})
		}
	}

	// The manifest's own licence belongs to the project, not to a dependency.
	// It travels on Result.OwnLicence and is NEVER stamped onto a Declared: a
	// project declaring MIT while depending on an AGPL package must not have
	// that dependency labelled MIT.
	sortDeclared(out)
	return Result{Declared: out, OwnLicence: declaredLicence}, nil
}

func (NPM) ParseLockfile(rel string, data []byte) (Result, error) {
	obj, err := parseJSONObject(data)
	if err != nil {
		return Result{}, cerr.Wrap(cerr.EParse001, err, rel, describeParseError(err))
	}

	var out []Declared

	// lockfileVersion 2 and 3 carry a flat `packages` map keyed by path.
	if pkgs := jsonObjectMember(obj, "packages"); len(pkgs.Keys) > 0 {
		for _, path := range pkgs.Keys {
			if path == "" {
				continue // the root project itself
			}
			entry := jsonObjectMember(pkgs, path)
			name := npmNameFromPath(path)
			if name == "" {
				continue
			}
			ver := jsonString(entry, "version")
			licence := jsonString(entry, "license")
			if licence == "" {
				licence = jsonString(entry, "licence")
			}
			out = append(out, Declared{
				Ecosystem:  "npm",
				Name:       name,
				Version:    ver,
				IsRange:    isRange(ver),
				Direct:     !strings.Contains(path, "node_modules/") || strings.Count(path, "node_modules/") == 1,
				LicenceRaw: licence,
				SourcePath: rel,
				Dev:        isTrue(entry, "dev"),
				Optional:   isTrue(entry, "optional"),
			})
		}
		if len(out) > 0 {
			sortDeclared(out)
			return Result{Declared: out}, nil
		}
	}

	// lockfileVersion 1 carries a nested `dependencies` tree. It is walked
	// breadth-first with an explicit stack, so that a pathological tree cannot
	// recurse the goroutine stack away.
	if deps := jsonObjectMember(obj, "dependencies"); len(deps.Keys) > 0 {
		type frame struct {
			obj   safejson.Object
			depth int
		}
		stack := []frame{{obj: deps, depth: 0}}
		for len(stack) > 0 {
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if cur.depth > 24 {
				// The same depth bound the walk uses. A lockfile nested deeper
				// than this is not a lockfile anyone wrote by hand.
				break
			}
			for _, name := range cur.obj.Keys {
				entry := jsonObjectMember(cur.obj, name)
				ver := jsonString(entry, "version")
				licence := jsonString(entry, "license")
				if licence == "" {
					licence = jsonString(entry, "licence")
				}
				out = append(out, Declared{
					Ecosystem:  "npm",
					Name:       name,
					Version:    ver,
					IsRange:    isRange(ver),
					Direct:     cur.depth == 0,
					LicenceRaw: licence,
					SourcePath: rel,
					Dev:        isTrue(entry, "dev"),
					Optional:   isTrue(entry, "optional"),
				})
				if nested := jsonObjectMember(entry, "dependencies"); len(nested.Keys) > 0 {
					stack = append(stack, frame{obj: nested, depth: cur.depth + 1})
				}
			}
		}
		sortDeclared(out)
		return Result{Declared: out}, nil
	}

	// A parseable lockfile with neither shape is a format this parser does not
	// know. Refusing is correct: an empty result would look like a project with
	// no dependencies, which is the most dangerous possible answer.
	return Result{}, cerr.New(cerr.EParse001, rel, "unrecognised package-lock structure")
}

// npmNameFromPath extracts a package name from a node_modules path.
//
//	"node_modules/express"                 → "express"
//	"node_modules/@scope/pkg"              → "@scope/pkg"
//	"node_modules/a/node_modules/@s/p"     → "@s/p"
func npmNameFromPath(path string) string {
	i := strings.LastIndex(path, "node_modules/")
	if i < 0 {
		return ""
	}
	rest := path[i+len("node_modules/"):]
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" {
		return ""
	}
	if strings.HasPrefix(rest, "@") {
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return rest
	}
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[:j]
	}
	return rest
}

func isTrue(o safejson.Object, key string) bool {
	v, ok := o.Bool(key)
	return ok && v
}
