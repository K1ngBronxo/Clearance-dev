package corpus

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// lastVerifiedRe matches a `last_verified: "2026-09-25"` line in a corpus
// source file. It is a text scan rather than a YAML decode on purpose: the
// helper below must see every declared date, including any in an entry the
// loader might reject, and decoding would couple the helper to the very schema
// it exists to stay ahead of.
var lastVerifiedRe = regexp.MustCompile(`(?m)^\s*last_verified:\s*"?(\d{4}-\d{2}-\d{2})"?`)

// newestLastVerified returns the latest `last_verified` date anywhere in the
// corpus source tree at dir, as an ISO-8601 day string.
//
// # WHY THE TEST DATE IS DERIVED RATHER THAN FROZEN
//
// TestLoadShippedCorpus used to pass a hardcoded Today ("2026-09-23"). A corpus
// entry whose last_verified is later than Today fails E-CORPUS-008
// ("last_verified is in the future"), so the frozen date was a landmine: the
// next person to add an entry verified on a later day broke the test, and the
// only fix was to bump the constant — which moves the landmine rather than
// removing it. Deriving Today from the newest date already in the corpus means
// adding a current entry can never trip the check, and this stays a test of the
// loader rather than of the calendar (INV-6: no test reads the clock).
func newestLastVerified(t *testing.T, dir string) string {
	t.Helper()
	newest := ""
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yaml", ".yml":
		default:
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, m := range lastVerifiedRe.FindAllStringSubmatch(string(b), -1) {
			if m[1] > newest { // ISO-8601 days compare lexicographically
				newest = m[1]
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("scanning %s for last_verified dates: %v", dir, walkErr)
	}
	if newest == "" {
		t.Fatalf("%s declares no last_verified date; this test cannot derive a Today", dir)
	}
	return newest
}

// TestLoadShippedCorpus loads the corpus that ships with the binary from its
// source tree and asserts it is structurally valid end to end.
//
// It is deliberately an integration test rather than a unit test: the corpus is
// data, and the only meaningful assertion about data is that the validator
// accepts it. Today is injected so the run does not depend on the clock (INV-6).
func TestLoadShippedCorpus(t *testing.T) {
	dir := filepath.Join("..", "..", "corpus")
	c, err := Load(LoadOptions{Dir: dir, Today: newestLastVerified(t, dir)})
	if err != nil {
		t.Fatalf("Load(%q): %v", dir, err)
	}
	if c == nil {
		t.Fatal("Load returned a nil corpus")
	}

	stats := c.Stats()
	t.Logf("corpus stats: licences=%d obligations=%d traps=%d tos=%d territories=%d citations=%d",
		stats.Licences, stats.Obligations, stats.Traps, stats.ToS, stats.Territories, stats.Citations)
	if stats.Licences < 12 {
		t.Errorf("licences = %d, want >= 12", stats.Licences)
	}
	if got := len(c.GlobalTraps()); got < 10 {
		t.Errorf("global traps = %d, want >= 10", got)
	}
	if stats.ToS < 2 {
		t.Errorf("tos platforms = %d, want >= 2", stats.ToS)
	}
	if stats.Territories < 4 {
		t.Errorf("territories = %d, want >= 4", stats.Territories)
	}

	// INV-1: every obligation and trap must cite something that resolves.
	for _, e := range c.Entries() {
		if len(e.Obligations) == 0 {
			t.Errorf("licence %s carries no obligations", e.ID)
		}
		for _, ob := range e.Obligations {
			if _, err := c.Citations.Resolve(ob.Citation); err != nil {
				t.Errorf("obligation %s: citation does not resolve: %v", ob.ID, err)
			}
		}
		for _, tr := range e.Traps {
			if _, err := c.Citations.Resolve(tr.Citation); err != nil {
				t.Errorf("trap %s: citation does not resolve: %v", tr.ID, err)
			}
		}
	}
	for _, tr := range c.GlobalTraps() {
		if _, err := c.Citations.Resolve(tr.Citation); err != nil {
			t.Errorf("trap %s: citation does not resolve: %v", tr.ID, err)
		}
	}

	// The policy engine looks these two trap ids up by name. If either is
	// missing, the code-vs-weights divergence check and the declared-vs-actual
	// conflict check silently do nothing, so their presence is load-bearing.
	for _, id := range []string{
		"trap.code-weights-divergence",
		"trap.declared-vs-actual-conflict",
	} {
		if _, ok := findGlobalTrapByID(c, id); !ok {
			t.Errorf("required global trap %q is missing", id)
		}
	}

	// Two entries citing the same clause with different excerpts is a corpus
	// inconsistency the loader reports as E-CORPUS-004. The shipped corpus must
	// have none.
	for _, n := range c.Notices {
		if n.Code == string(cerr.ECorpus004) {
			t.Errorf("corpus inconsistency: %s", n.Message)
		}
	}
}

// TestLoadDerivesTodayFromTheNewestEntry pins the frozen-clock fix and the
// failure mode it removes.
//
// A corpus entry whose last_verified is later than the loader's Today fails
// E-CORPUS-008. That is correct behaviour, but it made a hardcoded Today in a
// test a landmine: the next entry verified on a later day broke the test, and
// the only fix was to bump the constant. This test builds a corpus dated
// 2027-01-15 and asserts both halves — the old hardcoded date rejects it, and
// the derived date accepts it — so the reason the derivation exists cannot be
// quietly undone.
func TestLoadDerivesTodayFromTheNewestEntry(t *testing.T) {
	dir := t.TempDir()
	entry := `id: licence.synthetic
spdx_id: Synthetic-1.0
name: Synthetic Licence 1.0
family: permissive
osi_approved: false
fsf_libre: false
permissiveness: 3
confidence: HIGH
last_verified: "2027-01-15"
citation:
  url: https://example.test/synthetic
  section: "Synthetic Licence"
obligations:
  - id: synthetic.attribution
    kind: ATTRIBUTION
    severity: CONDITION
    confidence: HIGH
    message: >
      A synthetic obligation whose text is comfortably longer than the ten
      character minimum the corpus validator enforces.
    when:
      op: "=="
      field: use.commercial
      value: true
    citation:
      url: https://example.test/synthetic
      section: "Clause 1"
`
	if err := os.MkdirAll(filepath.Join(dir, "licences"), 0o755); err != nil {
		t.Fatalf("creating the synthetic corpus tree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "licences", "synthetic.yaml"), []byte(entry), 0o644); err != nil {
		t.Fatalf("writing the synthetic entry: %v", err)
	}

	// The landmine: a Today earlier than the entry's date is refused. This is
	// the exact failure a hardcoded constant produced when the corpus moved on.
	if _, err := Load(LoadOptions{Dir: dir, Today: "2026-09-23"}); cerr.CodeOf(err) != cerr.ECorpus008 {
		t.Fatalf("loading a 2027-01-15 entry at 2026-09-23 gave %v, want E-CORPUS-008.\n"+
			"If this no longer fails, the future-date guard has been weakened and "+
			"the derivation below is protecting nothing.", err)
	}

	// The fix: the date derived from the corpus accepts it.
	today := newestLastVerified(t, dir)
	if today != "2027-01-15" {
		t.Fatalf("newestLastVerified = %q, want the entry's own date", today)
	}
	if _, err := Load(LoadOptions{Dir: dir, Today: today}); err != nil {
		t.Fatalf("loading the corpus at its own newest date %s failed: %v", today, err)
	}
}

func findGlobalTrapByID(c *Corpus, id string) (*Trap, bool) {
	for _, tr := range c.GlobalTraps() {
		if tr.ID == id {
			return tr, true
		}
	}
	return nil, false
}
