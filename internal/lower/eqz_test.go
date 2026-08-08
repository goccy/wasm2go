package lower

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestLowerEqzIsComparison pins the eqz lowering: i32.eqz / i64.eqz
// become first-class OpEq{32,64}-against-zero comparisons (TypeBool),
// NOT i32_eqz / i64_eqz helper calls. The comparison form is what lets
// a branch on the result fuse into a direct Go comparison at emit —
// measured at ~10% of the SpiderMonkey interpreter's hot loop.
func TestLowerEqzIsComparison(t *testing.T) {
	bin := testfixture.Wasm(t, "eqz_fuse")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for fnIdx, wantOp := range map[uint32]string{
		0: "OpEq32", // branch32: i32.eqz feeding the if control
		1: "OpEq32", // value32: i32.eqz as the return value
		2: "OpEq64", // value64: i64.eqz as the return value
	} {
		fn, err := LowerFunction(mod, fnIdx, "fn", testThrowSet(mod))
		if err != nil {
			t.Fatalf("lower fn%d: %v", fnIdx, err)
		}
		dump := dumpSSAFunc(fn)
		if strings.Contains(dump, "eqz") {
			t.Errorf("fn%d: eqz still lowers to a helper call:\n%s", fnIdx, dump)
		}
		if !strings.Contains(dump, wantOp) {
			t.Errorf("fn%d: expected %s in lowered SSA:\n%s", fnIdx, wantOp, dump)
		}
	}
}
