package gcasm

import (
	"errors"
	"testing"
)

// jtSitesWithRuns builds one synthetic dispatch site with n runs.
func jtSitesWithRuns(n int) map[int]*jtSite {
	s := &jtSite{}
	for i := 0; i < n; i++ {
		s.runs = append(s.runs, jtRun{start: i, target: i * 8})
	}
	return map[int]*jtSite{0: s}
}

func TestJumpTableFallbackPolicy(t *testing.T) {
	t.Run("no sites", func(t *testing.T) {
		if err := jumpTableFallbackErr(nil); err != nil {
			t.Fatalf("nil sites: %v", err)
		}
	})
	t.Run("below default threshold", func(t *testing.T) {
		if err := jumpTableFallbackErr(jtSitesWithRuns(jtFallbackMinRuns - 1)); err != nil {
			t.Fatalf("below threshold: %v", err)
		}
	})
	t.Run("at default threshold", func(t *testing.T) {
		err := jumpTableFallbackErr(jtSitesWithRuns(jtFallbackMinRuns))
		if !errors.Is(err, errLargeJumpTable) {
			t.Fatalf("at threshold: got %v, want errLargeJumpTable", err)
		}
	})
	t.Run("env off", func(t *testing.T) {
		t.Setenv("GCASM_JT_FALLBACK", "off")
		if err := jumpTableFallbackErr(jtSitesWithRuns(500)); err != nil {
			t.Fatalf("off: %v", err)
		}
	})
	t.Run("env custom threshold", func(t *testing.T) {
		t.Setenv("GCASM_JT_FALLBACK", "8")
		if err := jumpTableFallbackErr(jtSitesWithRuns(7)); err != nil {
			t.Fatalf("7 runs under custom 8: %v", err)
		}
		if err := jumpTableFallbackErr(jtSitesWithRuns(8)); !errors.Is(err, errLargeJumpTable) {
			t.Fatalf("8 runs at custom 8: got %v, want errLargeJumpTable", err)
		}
	})
	t.Run("env invalid", func(t *testing.T) {
		for _, v := range []string{"zero", "0", "-3"} {
			t.Setenv("GCASM_JT_FALLBACK", v)
			err := jumpTableFallbackErr(jtSitesWithRuns(1))
			if err == nil || errors.Is(err, errLargeJumpTable) {
				t.Fatalf("GCASM_JT_FALLBACK=%q: got %v, want a config error", v, err)
			}
		}
	})
}
