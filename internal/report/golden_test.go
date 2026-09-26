package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// update is the standard Go golden-file flag:
//
//	go test ./internal/report -update
//
// regenerates every golden under testdata/ instead of comparing against it.
// CONTRIBUTING.md documented this workflow before any test in this package
// existed; this is the flag that makes the documented workflow real.
var update = flag.Bool("update", false, "update golden files under testdata/")

// goldenDir is the directory every golden lives in, relative to this package.
const goldenDir = "testdata"

// renderer names one output format and how to render a fixture in it.
//
// A function per format rather than a switch inside the test: adding a format
// is adding one entry, and the structural tests can reuse the same dispatch
// instead of each re-deriving which writer to call.
type renderer struct {
	name   string
	render func(v verdict.Verdict, g *graph.Graph) ([]byte, error)
}

// renderers returns every format, in the order the golden files are written.
func renderers() []renderer {
	return []renderer{
		{"human", func(v verdict.Verdict, _ *graph.Graph) ([]byte, error) {
			var buf bytes.Buffer
			err := WriteHuman(&buf, v, Options{})
			return buf.Bytes(), err
		}},
		{"markdown", func(v verdict.Verdict, _ *graph.Graph) ([]byte, error) {
			var buf bytes.Buffer
			err := WriteMarkdown(&buf, v, Options{})
			return buf.Bytes(), err
		}},
		{"json", func(v verdict.Verdict, _ *graph.Graph) ([]byte, error) {
			return MarshalJSON(v)
		}},
		{"sarif", func(v verdict.Verdict, _ *graph.Graph) ([]byte, error) {
			return MarshalSARIF(v)
		}},
		{"cyclonedx", func(v verdict.Verdict, g *graph.Graph) ([]byte, error) {
			return MarshalCycloneDX(v, g)
		}},
		{"spdx", func(v verdict.Verdict, g *graph.Graph) ([]byte, error) {
			return MarshalSPDX(v, g)
		}},
	}
}

// TestGolden renders every fixture through every format and pins the bytes.
//
// Subtests are named `<fixture>/<format>`, so a failure names the exact golden
// file that moved and the run is reproducible.
func TestGolden(t *testing.T) {
	for _, fx := range allFixtures() {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			g := graphFor(fx.name)
			for _, r := range renderers() {
				r := r
				t.Run(r.name, func(t *testing.T) {
					got, err := r.render(fx.v, g)
					if err != nil {
						t.Fatalf("render %s/%s: %v", fx.name, r.name, err)
					}
					checkGolden(t, fx.name+"."+r.name, got)
				})
			}
		})
	}
}

// checkGolden compares got against testdata/<name>.golden, or writes it when
// -update was passed.
//
// A missing golden is a failure, not a skip. A test that skips when its golden
// is absent passes on a fresh clone while pinning nothing, which is the exact
// "a target that reports success while doing nothing" failure the project's
// logs catalogue.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()

	path := filepath.Join(goldenDir, name+".golden")

	if *update {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", goldenDir, err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v\n"+
			"Regenerate the goldens with: go test ./internal/report -update", path, err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("golden mismatch: %s\n"+
			"--- want (%d bytes) ---\n%s\n--- got (%d bytes) ---\n%s",
			path, len(want), want, len(got), got)
	}
}
