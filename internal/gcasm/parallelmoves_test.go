package gcasm

import (
	"fmt"
	"strings"
	"testing"
)

func runParallelMoves(moves map[int]int) string {
	var b strings.Builder
	emitParallelMoves(&b, moves, func(dst, src int) string {
		return fmt.Sprintf("mov %d->%d;", src, dst)
	}, func(dst, src int) (string, string) {
		return fmt.Sprintf("save %d;", src), fmt.Sprintf("land %d;", dst)
	})
	return b.String()
}

// TestParallelMovesDeterministic: independent moves must come out in
// sorted destination order every run — the emitted asm is part of the
// transpiler's deterministic-output contract, and a map-order walk
// here made whole-module builds differ between identical runs.
func TestParallelMovesDeterministic(t *testing.T) {
	moves := map[int]int{7: 1, 5: 3, 9: 2, 6: 4}
	want := runParallelMoves(moves)
	if want != "mov 3->5;mov 4->6;mov 1->7;mov 2->9;" {
		t.Fatalf("unexpected order: %q", want)
	}
	for i := 0; i < 50; i++ {
		if got := runParallelMoves(moves); got != want {
			t.Fatalf("run %d differs: %q vs %q", i, got, want)
		}
	}
}

// TestParallelMovesChain: a move whose source is another pending
// destination must wait for it.
func TestParallelMovesChain(t *testing.T) {
	// 3 reads 2, 2 reads 1: emit 2->3 first, then 1->2.
	got := runParallelMoves(map[int]int{3: 2, 2: 1})
	if got != "mov 2->3;mov 1->2;" {
		t.Fatalf("chain order wrong: %q", got)
	}
}

// TestParallelMovesCycle: a swap breaks through the temp register,
// starting from the lowest destination.
func TestParallelMovesCycle(t *testing.T) {
	got := runParallelMoves(map[int]int{1: 2, 2: 1})
	if got != "save 2;mov 1->2;land 1;" {
		t.Fatalf("cycle realization wrong: %q", got)
	}
}

// TestParallelMovesSelfDropped: identity moves emit nothing.
func TestParallelMovesSelfDropped(t *testing.T) {
	if got := runParallelMoves(map[int]int{4: 4}); got != "" {
		t.Fatalf("self-move emitted: %q", got)
	}
}
