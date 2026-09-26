// Package config holds the declared intent: the facts Clearance refuses to
// infer.
//
// Principle 5: "Intent is declared, not inferred." The policy engine may not
// guess commercial status. Absent intent produces UNDETERMINED for a
// conditional obligation, never a pass.
//
// This is the single most important design decision in the product's safety
// story, and it is why every config error is FATAL with exit 2: no intent means
// no answer, and a tool that guesses its user's intent is a tool that will one
// day tell someone they are compliant when they are not.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// SchemaVersion is the only config schema this binary understands. A config
// declaring a higher version is refused with E-CFG-008 rather than partially
// interpreted, because a field this binary does not know about might be one
// that changes a verdict.
const SchemaVersion = 1

// LicenceModel is how the project's own code is licensed.
//
// SourceAvailable is the case the other four cannot describe: a licence that
// publishes its source and restricts what a competitor may do with it — FSL,
// BUSL, Elastic. It is deliberately not a synonym for OpenSource. The source is
// readable; the licence is not OSI-approved; and a project that says "open
// source" when it means this is making a claim its own licence contradicts.
type LicenceModel string

const (
	ClosedSource    LicenceModel = "closed-source"
	OpenSource      LicenceModel = "open-source"
	SourceAvailable LicenceModel = "source-available"
	Dual            LicenceModel = "dual"
	InternalOnly    LicenceModel = "internal-only"
)

// ValidLicenceModels is the closed set from the config spec.
func ValidLicenceModels() []LicenceModel {
	return []LicenceModel{ClosedSource, OpenSource, SourceAvailable, Dual, InternalOnly}
}

func (m LicenceModel) Valid() bool {
	for _, v := range ValidLicenceModels() {
		if m == v {
			return true
		}
	}
	return false
}

// AllowRule whitelists a licence under a predicate. It can only reduce severity
// for the licence it names — never globally, and never for an unlisted one.
type AllowRule struct {
	Licence string `yaml:"licence" json:"licence"`
	When    any    `yaml:"when" json:"when"`
}

// IgnoreRule excludes a path from the scan. The reason is mandatory: an
// unexplained ignore is how a blocker gets hidden, and E-SCAN-020 exists to
// catch the broad case of the same failure.
type IgnoreRule struct {
	Path   string `yaml:"path" json:"path"`
	Reason string `yaml:"reason" json:"reason"`
}

// Intent is the declared facts about the project under scan.
//
// The nested anonymous structs mirror the config file's shape exactly, so that
// the file a user reads and the type the code uses are the same document. The
// `yaml` tags are the field paths the policy engine's predicate language
// addresses ("use.commercial", "scale.mau").
type Intent struct {
	SchemaVersion int `yaml:"schema_version" json:"schema_version"`

	Project struct {
		Name        string `yaml:"name" json:"name"`
		Description string `yaml:"description,omitempty" json:"description,omitempty"`
	} `yaml:"project" json:"project"`

	Use struct {
		Commercial     bool         `yaml:"commercial" json:"commercial"`
		LicenceModel   LicenceModel `yaml:"licence_model" json:"licence_model"`
		Modified       bool         `yaml:"modified" json:"modified"`
		NetworkExposed bool         `yaml:"network_exposed" json:"network_exposed"`
		Distributed    bool         `yaml:"distributed" json:"distributed"`
		SaaS           bool         `yaml:"saas" json:"saas"`
	} `yaml:"use" json:"use"`

	Scale struct {
		MonthlyActiveUsers int `yaml:"mau" json:"mau"`
		Employees          int `yaml:"employees" json:"employees"`
		RevenueEUR         int `yaml:"revenue_eur,omitempty" json:"revenue_eur,omitempty"`
	} `yaml:"scale" json:"scale"`

	Territories []string `yaml:"territories" json:"territories"`

	// AI is the bring-your-own-key block.
	//
	// It is deliberately absent from Hash(). Turning AI on adds an explanation
	// beside a verdict; it must not change the verdict, and it must not change
	// the hash that identifies one. See the note on AIOptions.
	AI AIOptions `yaml:"ai" json:"ai"`

	Policy struct {
		NeverAllow []string     `yaml:"never_allow" json:"never_allow"`
		AllowIf    []AllowRule  `yaml:"allow_if" json:"allow_if"`
		BlockOn    []string     `yaml:"block_on" json:"block_on"`
		Ignore     []IgnoreRule `yaml:"ignore" json:"ignore"`
	} `yaml:"policy" json:"policy"`

	// Declared records which optional field paths were actually written in the
	// file. This is the mechanism that makes "absent" different from "zero":
	// `mau` omitted is UNKNOWN, `mau: 0` is a claim that you have no users.
	//
	// It is not serialised, and it is not part of the hash (the hash covers the
	// values; presence is implied by the value for every field that has one).
	Declared map[string]bool `yaml:"-" json:"-"`

	// SourcePath is the file this intent was loaded from, for the verdict's
	// meta block.
	SourcePath string `yaml:"-" json:"-"`
}

// RequiredUseFields are the six facts the spec requires. They are the minimum
// needed to evaluate a conditional obligation, and they are all required
// because omitting one does not make the obligation "not apply" — it makes it
// UNKNOWN, and a config that cannot answer is a config that cannot verdict.
func RequiredUseFields() []string {
	return []string{
		"use.commercial",
		"use.licence_model",
		"use.modified",
		"use.network_exposed",
		"use.distributed",
		"use.saas",
	}
}

// IsDeclared reports whether a predicate field path was declared.
//
// The `use.*` fields are always declared, because load-time validation refuses
// a config without them. Everything else depends on the file.
func (in *Intent) IsDeclared(path string) bool {
	if in == nil {
		return false
	}
	if strings.HasPrefix(path, "use.") {
		return true
	}
	if path == "project.name" {
		return in.Project.Name != ""
	}
	if path == "territories" {
		return len(in.Territories) > 0
	}
	return in.Declared[path]
}

// IsDeclaredForLookup is the same question asked of the intent hash, used by
// tests that need to assert presence without holding an Intent.
func (in *Intent) DeclaredPaths() []string {
	out := make([]string, 0, len(in.Declared))
	for k, v := range in.Declared {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Hash is the SHA-256 of the canonical serialisation of the intent.
//
// It appears in the verdict's meta block so that a verdict can be tied to the
// exact declared facts that produced it. If a user says "you told me last week
// this was fine", the hash plus the corpus version is the answer.
//
// Canonical means: a fixed field order, one field per line, `path=value`, and
// no map iteration order anywhere. Two runs on the same config produce the same
// hash on any machine (INV-6).
func (in *Intent) Hash() string {
	var b strings.Builder
	w := func(path string, v string) {
		b.WriteString(path)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}

	w("schema_version", strconv.Itoa(in.SchemaVersion))
	w("project.name", in.Project.Name)
	w("use.commercial", strconv.FormatBool(in.Use.Commercial))
	w("use.licence_model", string(in.Use.LicenceModel))
	w("use.modified", strconv.FormatBool(in.Use.Modified))
	w("use.network_exposed", strconv.FormatBool(in.Use.NetworkExposed))
	w("use.distributed", strconv.FormatBool(in.Use.Distributed))
	w("use.saas", strconv.FormatBool(in.Use.SaaS))

	// Scale: presence is part of the meaning, so a declared 0 hashes
	// differently from an omitted field.
	w("scale.mau.declared", strconv.FormatBool(in.IsDeclared("scale.mau")))
	w("scale.mau", strconv.Itoa(in.Scale.MonthlyActiveUsers))
	w("scale.employees.declared", strconv.FormatBool(in.IsDeclared("scale.employees")))
	w("scale.employees", strconv.Itoa(in.Scale.Employees))
	w("scale.revenue_eur.declared", strconv.FormatBool(in.IsDeclared("scale.revenue_eur")))
	w("scale.revenue_eur", strconv.Itoa(in.Scale.RevenueEUR))

	// Territories are sorted: `[EU, US]` and `[US, EU]` declare the same fact,
	// so they must hash the same.
	terr := append([]string(nil), in.Territories...)
	sort.Strings(terr)
	w("territories", strings.Join(terr, ","))

	na := append([]string(nil), in.Policy.NeverAllow...)
	sort.Strings(na)
	w("policy.never_allow", strings.Join(na, ","))

	bo := append([]string(nil), in.Policy.BlockOn...)
	sort.Strings(bo)
	w("policy.block_on", strings.Join(bo, ","))

	for _, r := range in.Policy.Ignore {
		w("policy.ignore", r.Path+"|"+r.Reason)
	}

	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BlockOn returns the severities that fail CI, defaulting to BLOCK.
func (in *Intent) BlockOn() []string {
	if len(in.Policy.BlockOn) == 0 {
		return []string{"BLOCK"}
	}
	return in.Policy.BlockOn
}

// NeverAllowContains reports whether an SPDX id is on the always-block list.
// The comparison is case-insensitive because a user writing `agpl-3.0-only`
// means the same thing as `AGPL-3.0-only`, and a rule that silently fails to
// match would be a safety rule that silently does nothing.
func (in *Intent) NeverAllowContains(spdx string) bool {
	for _, id := range in.Policy.NeverAllow {
		if strings.EqualFold(id, spdx) {
			return true
		}
	}
	return false
}

// IgnoreMatches reports whether a project-relative path is ignored, and by
// which rule. Matching supports a trailing `/**` (everything under a directory)
// and a trailing `/*` (direct children), plus exact matches. It deliberately
// does not support arbitrary glob syntax: a path pattern a reader cannot verify
// by eye is a path pattern that will one day hide a blocker.
func (in *Intent) IgnoreMatches(rel string) (IgnoreRule, bool) {
	rel = strings.ReplaceAll(rel, "\\", "/")
	for _, r := range in.Policy.Ignore {
		pat := strings.ReplaceAll(strings.TrimSpace(r.Path), "\\", "/")
		switch {
		case pat == "":
			continue
		case strings.HasSuffix(pat, "/**"):
			prefix := strings.TrimSuffix(pat, "/**")
			if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
				return r, true
			}
		case strings.HasSuffix(pat, "/*"):
			prefix := strings.TrimSuffix(pat, "/*")
			if strings.HasPrefix(rel, prefix+"/") && !strings.Contains(strings.TrimPrefix(rel, prefix+"/"), "/") {
				return r, true
			}
		default:
			if rel == pat {
				return r, true
			}
		}
	}
	return IgnoreRule{}, false
}
