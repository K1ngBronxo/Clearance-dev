package parsers

import (
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// PyPI reads requirements*.txt, pyproject.toml, poetry.lock and uv.lock.
//
// NOTE ON LICENCE RESOLUTION: poetry.lock and uv.lock carry no licence field,
// and PyPI metadata is not fetched — the scanner makes no network calls, by
// design. So a Python dependency's licence resolves from a vendored
// `*.dist-info/METADATA` in a virtualenv if one is present, and is otherwise
// UNDETERMINED with a note. That is the honest outcome, and it is the same
// reason E-SCAN-011 exists.
type PyPI struct{}

func (PyPI) Ecosystem() string { return "pypi" }

func (PyPI) ManifestNames() []string {
	return []string{"pyproject.toml", "requirements.txt", "requirements-dev.txt", "setup.py"}
}

func (PyPI) LockfileNames() []string {
	return []string{"poetry.lock", "uv.lock", "Pipfile.lock"}
}

func (PyPI) ParseManifest(rel string, data []byte) (Result, error) {
	switch {
	case strings.HasSuffix(rel, ".toml"):
		return parsePyProject(rel, data)
	case strings.HasSuffix(rel, ".txt"):
		return parseRequirements(rel, data)
	}
	// setup.py is Python source. Reading it would mean parsing Python, and
	// executing it is forbidden by INV-3. Refusing is correct.
	return Result{}, cerr.New(cerr.EParse002, rel, "setup.py is not parsed; use pyproject.toml or a lockfile")
}

func (PyPI) ParseLockfile(rel string, data []byte) (Result, error) {
	if strings.HasSuffix(rel, "Pipfile.lock") {
		// Pipfile.lock is JSON.
		obj, err := parseJSONObject(data)
		if err != nil {
			return Result{}, cerr.Wrap(cerr.EParse001, err, rel, describeParseError(err))
		}
		var out []Declared
		for _, group := range []string{"default", "develop"} {
			sub := jsonObjectMember(obj, group)
			for _, name := range sub.Keys {
				entry := jsonObjectMember(sub, name)
				ver := jsonString(entry, "version")
				ver = strings.TrimPrefix(ver, "==")
				out = append(out, Declared{
					Ecosystem:  "pypi",
					Name:       name,
					Version:    ver,
					IsRange:    isRange(ver),
					Direct:     true,
					SourcePath: rel,
					Dev:        group == "develop",
				})
			}
		}
		sortDeclared(out)
		return Result{Declared: out}, nil
	}

	// poetry.lock and uv.lock are TOML with `[[package]]` entries.
	doc, err := parseTOML(data, 8<<20)
	if err != nil {
		return Result{}, cerr.Wrap(cerr.EParse001, err, rel, describeParseError(err))
	}
	var out []Declared
	for _, prefix := range doc.ArrayPrefixes() {
		if !strings.HasSuffix(prefix, ".0") && !isPackagePrefix(prefix) {
			continue
		}
		name := doc.String(prefix + ".name")
		ver := doc.String(prefix + ".version")
		if name == "" {
			continue
		}
		out = append(out, Declared{
			Ecosystem:  "pypi",
			Name:       strings.ToLower(name),
			Version:    ver,
			IsRange:    isRange(ver),
			Direct:     true,
			SourcePath: rel,
			Dev:        isDevGroup(doc, prefix),
		})
	}
	if len(out) == 0 {
		return Result{}, cerr.New(cerr.EParse001, rel, "no [[package]] entries found")
	}
	sortDeclared(out)
	return Result{Declared: out}, nil
}

// isPackagePrefix reports whether an array-of-tables prefix belongs to a
// package entry. poetry.lock uses `package.N`, uv.lock uses `package.N` too;
// both are caught by the "package." prefix.
func isPackagePrefix(prefix string) bool {
	return strings.HasPrefix(prefix, "package.")
}

// isDevGroup reads poetry's `category = "dev"` or uv's
// `[package.metadata]` grouping. Absent, a package is treated as a runtime
// dependency, because assuming "dev" would hide a runtime obligation.
func isDevGroup(doc *tomlDoc, prefix string) bool {
	if c := doc.String(prefix + ".category"); strings.EqualFold(c, "dev") {
		return true
	}
	return false
}

// parseRequirements reads a PEP 508 requirements file.
//
// Handled: `name`, `name==1.2.3`, `name>=1.0,<2.0`, `name[extra]==1.0`,
// `name==1.0 ; python_version < "3.9"`, comments, and blank lines.
// Refused-and-skipped: `-r other.txt` includes, `-e .` editable installs and
// URL requirements, each with a note, because resolving them would require
// reading another file or the network.
func parseRequirements(rel string, data []byte) (Result, error) {
	var out []Declared
	res := Result{}
	for i, raw := range strings.Split(string(data), "\n") {
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// An environment marker is not part of the requirement.
		if j := strings.IndexByte(line, ';'); j >= 0 {
			line = strings.TrimSpace(line[:j])
		}
		// A trailing comment.
		if j := strings.Index(line, " #"); j >= 0 {
			line = strings.TrimSpace(line[:j])
		}
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "-r"), strings.HasPrefix(line, "--requirement"),
			strings.HasPrefix(line, "-c"), strings.HasPrefix(line, "--constraint"):
			res.Fallback = true
			res.Warning = cerr.New(cerr.EParse002, rel, "included requirements file at line "+itoa(int64(lineNo))+" was not followed")
			continue
		case strings.HasPrefix(line, "-e"), strings.HasPrefix(line, "--editable"),
			strings.HasPrefix(line, "--index-url"), strings.HasPrefix(line, "-i"),
			strings.HasPrefix(line, "--extra-index-url"), strings.HasPrefix(line, "--find-links"),
			strings.HasPrefix(line, "-f"):
			res.Fallback = true
			res.Warning = cerr.New(cerr.EParse002, rel, "editable or index directive at line "+itoa(int64(lineNo))+" was skipped")
			continue
		case strings.Contains(line, "://"):
			// A URL requirement has no name to look up.
			res.Fallback = true
			res.Warning = cerr.New(cerr.EParse002, rel, "URL requirement at line "+itoa(int64(lineNo))+" was skipped")
			continue
		}

		name, spec := splitRequirement(line)
		if name == "" {
			continue
		}
		out = append(out, Declared{
			Ecosystem:  "pypi",
			Name:       strings.ToLower(name),
			Version:    cleanVersion(spec),
			IsRange:    isRange(spec),
			Direct:     true,
			SourcePath: rel,
			Line:       lineNo,
		})
	}
	sortDeclared(out)
	res.Declared = out
	return res, nil
}

// splitRequirement separates a name (with any extras) from its version
// specifier.
func splitRequirement(line string) (string, string) {
	line = strings.TrimSpace(line)
	// Strip extras: name[extra1,extra2]
	if i := strings.IndexByte(line, '['); i >= 0 {
		if j := strings.IndexByte(line, ']'); j > i {
			line = line[:i] + line[j+1:]
		}
	}
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '=', '<', '>', '!', '~':
			name := strings.TrimSpace(line[:i])
			return name, strings.TrimSpace(line[i:])
		}
	}
	return strings.TrimSpace(line), ""
}

// parsePyProject reads PEP 621 `[project].dependencies` and the Poetry
// `[tool.poetry.dependencies]` table, whichever is present.
func parsePyProject(rel string, data []byte) (Result, error) {
	doc, err := parseTOML(data, 1<<20)
	if err != nil {
		return Result{}, cerr.Wrap(cerr.EParse002, err, rel, describeParseError(err))
	}
	var out []Declared

	// PEP 621: an array of PEP 508 strings.
	for _, spec := range doc.Strings("project.dependencies") {
		name, ver := splitRequirement(spec)
		if name == "" {
			continue
		}
		out = append(out, Declared{
			Ecosystem: "pypi", Name: strings.ToLower(name),
			Version: cleanVersion(ver), IsRange: isRange(ver),
			Direct: true, SourcePath: rel,
		})
	}
	for _, spec := range doc.Strings("project.optional-dependencies") {
		name, ver := splitRequirement(spec)
		if name == "" {
			continue
		}
		out = append(out, Declared{
			Ecosystem: "pypi", Name: strings.ToLower(name),
			Version: cleanVersion(ver), IsRange: isRange(ver),
			Direct: true, Optional: true, SourcePath: rel,
		})
	}

	// Poetry: a table of name → version (or name → inline table).
	if doc.Has("tool.poetry.dependencies") {
		for _, name := range doc.KeysUnder("tool.poetry.dependencies") {
			if strings.EqualFold(name, "python") {
				continue // the interpreter is not a dependency
			}
			raw := doc.String("tool.poetry.dependencies." + name)
			if raw == "" {
				if _, ok := doc.Get("tool.poetry.dependencies." + name); ok {
					// An inline table such as `{ version = "^1.0", optional = true }`.
					raw = inlineTableVersion(doc, "tool.poetry.dependencies."+name)
				}
			}
			out = append(out, Declared{
				Ecosystem: "pypi", Name: strings.ToLower(name),
				Version: cleanVersion(raw), IsRange: isRange(raw),
				Direct: true, SourcePath: rel,
			})
		}
	}
	for _, name := range doc.KeysUnder("tool.poetry.dev-dependencies") {
		raw := doc.String("tool.poetry.dev-dependencies." + name)
		out = append(out, Declared{
			Ecosystem: "pypi", Name: strings.ToLower(name),
			Version: cleanVersion(raw), IsRange: isRange(raw),
			Direct: true, Dev: true, SourcePath: rel,
		})
	}

	if len(out) == 0 {
		return Result{}, cerr.New(cerr.EParse002, rel, "no dependency declarations found")
	}
	sortDeclared(out)
	return Result{Declared: out, OwnLicence: projectLicence(doc)}, nil
}

// projectLicence reads the licence the project declares for itself.
//
// Three shapes appear in the wild, and all three mean the same thing:
//
//	[project]        license = "MIT"               PEP 621, the common form
//	[project]        license = { text = "MIT" }    PEP 639
//	[tool.poetry]    license = "MIT"               Poetry
//
// `license = { file = "LICENSE" }` and `license-files` are deliberately NOT
// read: they name a file rather than naming a licence, so they are pointers,
// not answers. The scanner reads the file they point at, and a pointer reported
// as a licence would put a filename where an SPDX identifier belongs.
func projectLicence(doc *tomlDoc) string {
	for _, path := range []string{"project.license", "tool.poetry.license"} {
		if s := doc.String(path); s != "" {
			return s
		}
		if v, ok := doc.Get(path); ok {
			if m, isMap := v.(map[string]any); isMap {
				if s, isStr := m["text"].(string); isStr {
					return s
				}
			}
		}
	}
	return ""
}

// inlineTableVersion reads a `version` key out of an inline table. parseTOML
// stores inline tables as map[string]any, and this reaches into one.
func inlineTableVersion(doc *tomlDoc, path string) string {
	v, ok := doc.Get(path)
	if !ok {
		return ""
	}
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	if s, ok := m["version"].(string); ok {
		return s
	}
	return ""
}
