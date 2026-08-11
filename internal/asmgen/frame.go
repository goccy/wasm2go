package asmgen

import (
	"fmt"
	"strings"

	"github.com/goccy/wasm2go/internal/wasm"
)

// argFrame captures the Go ABI0 argument-frame layout for one wasm
// function. The host's *Module pointer is always argument 0; the
// wasm signature's params and results follow.
//
// The emitter reads parameters as `lN+paramOffsets[N](FP)` and writes
// results as `retN+resultOffsets[N](FP)`. argSize is the total bytes
// the asm `$frame-args` syntax must declare.
type argFrame struct {
	argSize       int
	paramOffsets  []int
	resultOffsets []int
}

// computeArgFrame walks the signature and assigns each argument its
// naturally-aligned offset within the Go ABI0 frame. The frame
// starts with the host *Module pointer (8 bytes at offset 0), then
// the wasm params, then the result slot(s).
//
// Two alignment rules beyond natural alignment apply:
//   - the result section's start is rounded up to 8 bytes, so a
//     caller compiled from Go (whose ABI0 stub aligns
//     args-and-results that way) finds the result at the offset
//     the asm wrote it to;
//   - total argSize is also rounded up to 8 bytes so the caller's
//     stack-alignment expectation is preserved.
//
// The first rule was traced empirically: a Go caller of an asm
// function declared `(m *Module, l0 int32) int32` writes m@0 and
// l0@8 but reads the return at @16 — there is a 4-byte hole between
// the last param and the result. Without rounding the results-base
// the asm would store the return one slot too low and main would
// read uninitialised stack bytes (the symptom was the same return
// value across all inputs, which is what gave the bug away in
// fact/gcd/switch3 — every result printed as `10`).
func computeArgFrame(sig wasm.FuncType) (argFrame, error) {
	off := 8 // *Module pointer at FP+0
	params := make([]int, len(sig.Params))
	for i, p := range sig.Params {
		sz, al, err := abiSize(p)
		if err != nil {
			return argFrame{}, fmt.Errorf("param %d: %w", i, err)
		}
		off = alignUp(off, al)
		params[i] = off
		off += sz
	}
	if len(sig.Results) > 0 {
		off = alignUp(off, 8)
	}
	results := make([]int, len(sig.Results))
	for i, r := range sig.Results {
		sz, al, err := abiSize(r)
		if err != nil {
			return argFrame{}, fmt.Errorf("result %d: %w", i, err)
		}
		off = alignUp(off, al)
		results[i] = off
		off += sz
	}
	// argsize is the raw bytes occupied by args + results — NO
	// final 8-byte padding. go vet asmdecl rejects an over-padded
	// declaration (`wrong argument size 24; expected $...-20`)
	// because the Go side computes the expected size from the
	// declared parameter list without the extra slop.
	return argFrame{argSize: off, paramOffsets: params, resultOffsets: results}, nil
}

// abiSize returns (size, alignment) for a wasm value type as it
// appears in the Go ABI0 argument frame. The wasm-to-Go scalar
// mapping mirrors the codegen translator's existing emission so the
// asm body's frame layout matches what a caller compiled against
// the Go-output decl would observe.
func abiSize(t wasm.ValType) (size, align int, err error) {
	switch t {
	case wasm.ValI32, wasm.ValF32:
		return 4, 4, nil
	case wasm.ValI64, wasm.ValF64:
		return 8, 8, nil
	case wasm.ValV128:
		// [2]uint64 by value, mirroring the Go emission's v128 pair.
		return 16, 8, nil
	}
	return 0, 0, fmt.Errorf("unsupported value type %v", t)
}

func alignUp(off, al int) int {
	if off%al == 0 {
		return off
	}
	return off + (al - off%al)
}

// goSignature renders the Go-side function signature (parens-and-types)
// for one wasm function. modulePkgRef is the *Module type expression
// — "*Module" or "*base.Module" depending on the caller's packaging.
//
// Produces e.g. `(m *Module, l0 int32, l1 int32) int32` for
// (i32, i32) -> i32.
func goSignature(sig wasm.FuncType, modulePkgRef string) string {
	var b strings.Builder
	b.WriteByte('(')
	fmt.Fprintf(&b, "m %s", modulePkgRef)
	for i, p := range sig.Params {
		fmt.Fprintf(&b, ", l%d %s", i, goTypeName(p))
	}
	b.WriteByte(')')
	switch len(sig.Results) {
	case 0:
		// no return clause
	case 1:
		fmt.Fprintf(&b, " %s", goTypeName(sig.Results[0]))
	default:
		b.WriteString(" (")
		for i, r := range sig.Results {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(goTypeName(r))
		}
		b.WriteByte(')')
	}
	return b.String()
}

func goTypeName(t wasm.ValType) string {
	switch t {
	case wasm.ValI32:
		return "int32"
	case wasm.ValI64:
		return "int64"
	case wasm.ValF32:
		return "float32"
	case wasm.ValF64:
		return "float64"
	}
	return "<?>"
}
