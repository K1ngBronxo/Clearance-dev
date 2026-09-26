// Benchmarks for the paths that run on every invocation.
//
// # WHY THIS FILE EXISTS
//
// `make bench` ran `go test ./... -run '^$' -bench . -benchmem`, and the module
// contained no Benchmark functions at all. So the target printed `ok` and
// exited 0 while measuring nothing — the same silent-success shape as the
// fixture and guard targets documented in LOGS.md §5.15-§5.17, in a target that
// is easy to overlook because nobody expects a benchmark suite to fail.
//
// # WHAT IS MEASURED, AND WHY ONLY THIS
//
// Corpus loading. `clearance check` loads the corpus before it looks at the
// project, so load time is paid by every invocation whether or not the project
// has dependencies — and the corpus is the one input that grows without bound
// as entries are added. A regression here is invisible in wall-clock terms on a
// laptop and very visible in a CI matrix.
//
// Nothing else is benchmarked on purpose. A benchmark that is not read is a
// slower test; the scanner's cost is dominated by the size of the project being
// audited, which a synthetic benchmark cannot represent honestly, and the
// predicate evaluator is a few hundred nanoseconds against a corpus load of
// tens of milliseconds. Measuring those would add noise and imply rigour the
// numbers do not have.
package clearance_test

import (
	"path/filepath"
	"testing"

	"github.com/clearance-dev/clearance/internal/corpus"
)

// BenchmarkCorpusLoad measures loading and validating the shipped corpus.
//
// It is the only thing `make bench` runs, so if this file is ever emptied the
// target goes back to reporting success for nothing — which is what
// TestEveryBenchmarkFileHasABenchmark in guard_corpus_test.go exists to notice.
func BenchmarkCorpusLoad(b *testing.B) {
	dir := filepath.Join(moduleRootB(b), "corpus")

	// One load outside the loop, so a corpus that does not load fails the
	// benchmark instead of reporting a number for a broken input.
	if _, err := corpus.Load(corpus.LoadOptions{Dir: dir, Today: "2026-09-23"}); err != nil {
		b.Fatalf("the shipped corpus does not load, so there is nothing to "+
			"measure: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := corpus.Load(corpus.LoadOptions{Dir: dir, Today: "2026-09-23"}); err != nil {
			b.Fatalf("load %d failed: %v", i, err)
		}
	}
}

// moduleRootB is moduleRoot for benchmarks, which have no *testing.T.
//
// The walk is duplicated rather than shared because the alternative is a
// testing.TB parameter threaded through the guard helpers for one caller, and
// because this is the second place that needs it rather than the fifth.
func moduleRootB(b *testing.B) string {
	b.Helper()
	// go test runs with the working directory set to the package directory, so
	// the module root is one level up from internal/.
	root, err := filepath.Abs("..")
	if err != nil {
		b.Fatalf("resolving the module root: %v", err)
	}
	return root
}
