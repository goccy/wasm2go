package gcasm

import (
	"fmt"
	"strings"

	"github.com/goccy/wasm2go/internal/wasm"
)

// simdGemmF32Export resolves the f32 GEMM retarget target: llama-wasm
// exports ggml's simd_gemm (the tiled flash-attention QK^T / PV
// micro-GEMM) under a stable debug name so the transpiler can swap its
// body for a native register-tiled kernel. The kernel reproduces the
// wasm arithmetic exactly — per element a k-ordered multiply-then-add
// into the running sum — so it is bit-identical to the transformed
// body; the FastMath gate is only the retarget infrastructure's.
// Returns the FnN symbol, or "" when the export is absent.
func simdGemmF32Export(mod *wasm.Module, cfg Config) string {
	if !cfg.FastMath || cfg.DisableRepackGemm {
		return ""
	}
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc && e.Name == "dbg_simd_gemm_f32" {
			return fmt.Sprintf("Fn%d", e.Index)
		}
	}
	return ""
}

// simdGemmF32Args returns the ABI0 stack offsets of the GEMM's
// arguments (l0 C, l1 A, l2 B pointers; l3 M, l4 K, l5 N int32) and
// the argument-byte count for the module's pointer width. Shared by
// the a64 and x64 emitters.
func simdGemmF32Args(wide bool) (map[string]int, int) {
	if wide {
		return map[string]int{"l0": 8, "l1": 16, "l2": 24, "l3": 32, "l4": 36, "l5": 40}, 44
	}
	return map[string]int{"l0": 8, "l1": 12, "l2": 16, "l3": 20, "l4": 24, "l5": 28}, 32
}

// a64SimdGemmF32Kernel emits C[M x N] += A[M x K] * B[K x N] (row-major
// f32, unit inner strides) under sym for arm64.
//
// Tiles: 4 rows x 16 columns (16 f32x4 accumulators, four B vectors
// per k shared by the rows, one LD1R broadcast per row) for the bulk;
// 4 rows x 4 columns and 4 rows x 1 column for the column tail; then
// the same three shapes for the row tail one row at a time. Every
// element's sum is formed as acc = fma(b, a, acc) in k order: the wasm
// body rounds the product and the sum separately, the kernel fuses
// them (one rounding, the more accurate result) — the native-style
// rounding the FastMath gate admits, as in the vec_dot tile kernels.
//
// Bounds: the three spans A[M*K], B[K*N], C[M*N] are checked against
// memSize once at entry; a non-positive dimension returns without
// touching memory (the wasm body reads and rewrites C unchanged when
// K == 0 — no observable difference).
//
// Register file after the prologue: R2 C row base, R3 A row base,
// R4 B base (host pointers); R5 rows left, R6 K, R7 N; R8 N*4 (B/C row
// stride), R9 K*4 (A row stride); R10 cols left, R11 C column cursor,
// R12 B column cursor; R16/R17/R19/R23 A row cursors, R22 B k cursor,
// R24 k counter; R13/R14/R15 C row pointers; R26 scratch.
func a64SimdGemmF32Kernel(sym, trapSym string, offs *ModuleOffsets, wide bool) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	word := func(enc uint32, dis string) { w("\tWORD $0x%08x // %s", enc, dis) }
	ldurQ := func(rt, rn, imm int) {
		word(0x3CC00000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("ldur q%d, [x%d, #%d]", rt, rn, imm))
	}
	sturQ := func(rt, rn, imm int) {
		word(0x3C800000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("stur q%d, [x%d, #%d]", rt, rn, imm))
	}
	// ld1r {vT.4s}, [xN], #4 — broadcast one f32 and post-increment.
	ld1rPost := func(t, n int) {
		word(0x4DDFC800|uint32(n)<<5|uint32(t), fmt.Sprintf("ld1r {v%d.4s}, [x%d], #4", t, n))
	}
	// fmla d.4s, n.4s, m.4s: d += n * m, one rounding (fast-math).
	fmlaV := func(d, n, m int) {
		word(0x4E20CC00|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmla v%d.4s, v%d.4s, v%d.4s", d, n, m))
	}

	argOff, argBytes := simdGemmF32Args(wide)
	movPtr := "MOVWU"
	if wide {
		movPtr = "MOVD"
	}

	w("// %s: f32 GEMM C += A*B, 4x16 / 4x4 / 4x1 tiles (row tail 1xN).", sym)
	w("TEXT ·%s(SB), $16-%d", sym, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVD\tm+0(FP), R0")
	w("\tMOVD\t%d(R0), R21", offs.MemSize)
	w("\tMOVD\t(R21), R21")
	w("\tMOVD\t%d(R0), R20", offs.M)
	w("\tMOVW\tl3+%d(FP), R5", argOff["l3"])
	w("\tMOVW\tl4+%d(FP), R6", argOff["l4"])
	w("\tMOVW\tl5+%d(FP), R7", argOff["l5"])
	w("\tCMPW\t$1, R5")
	w("\tBLT\tsgdone")
	w("\tCMPW\t$1, R6")
	w("\tBLT\tsgdone")
	w("\tCMPW\t$1, R7")
	w("\tBLT\tsgdone")
	w("\t%s\tl0+%d(FP), R2", movPtr, argOff["l0"])
	w("\t%s\tl1+%d(FP), R3", movPtr, argOff["l1"])
	w("\t%s\tl2+%d(FP), R4", movPtr, argOff["l2"])
	// Spans: A M*K*4, B K*N*4, C M*N*4 (all positive int32 products,
	// exact in 64 bits).
	w("\tMUL\tR5, R6, R26")
	w("\tLSL\t$2, R26, R26")
	w("\tADD\tR3, R26, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tsgoob")
	w("\tMUL\tR6, R7, R26")
	w("\tLSL\t$2, R26, R26")
	w("\tADD\tR4, R26, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tsgoob")
	w("\tMUL\tR5, R7, R26")
	w("\tLSL\t$2, R26, R26")
	w("\tADD\tR2, R26, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tsgoob")
	w("\tADD\tR20, R2, R2")
	w("\tADD\tR20, R3, R3")
	w("\tADD\tR20, R4, R4")
	w("\tLSL\t$2, R7, R8") // N*4
	w("\tLSL\t$2, R6, R9") // K*4

	// kloop4 emits the k loop for a 4-row tile with nv B vectors
	// (nv = 4 or 1): accumulators v(4r+c) for row r, vector c.
	kloop4 := func(p string, nv int) {
		w("\tMOVD\tR3, R16")
		w("\tADD\tR16, R9, R17")
		w("\tADD\tR17, R9, R19")
		w("\tADD\tR19, R9, R23")
		w("\tMOVD\tR12, R22")
		w("\tMOVW\tR6, R24")
		w("%sk:", p)
		for c := 0; c < nv; c++ {
			ldurQ(16+c, 22, 16*c)
		}
		ld1rPost(20, 16)
		ld1rPost(21, 17)
		ld1rPost(22, 19)
		ld1rPost(23, 23)
		for r := 0; r < 4; r++ {
			for c := 0; c < nv; c++ {
				fmlaV(4*r+c, 16+c, 20+r)
			}
		}
		w("\tADD\tR8, R22, R22")
		w("\tSUBW\t$1, R24, R24")
		w("\tCBNZW\tR24, %sk", p)
	}
	// kloop1 emits the k loop for a 1-row tile with nv B vectors:
	// accumulators v(c).
	kloop1 := func(p string, nv int) {
		w("\tMOVD\tR3, R16")
		w("\tMOVD\tR12, R22")
		w("\tMOVW\tR6, R24")
		w("%sk:", p)
		for c := 0; c < nv; c++ {
			ldurQ(16+c, 22, 16*c)
		}
		ld1rPost(20, 16)
		for c := 0; c < nv; c++ {
			fmlaV(c, 16+c, 20)
		}
		w("\tADD\tR8, R22, R22")
		w("\tSUBW\t$1, R24, R24")
		w("\tCBNZW\tR24, %sk", p)
	}
	// scalar column: rows x 1 element, F0..F3 accumulators.
	kscalar := func(p string, rows int) {
		w("\tMOVD\tR3, R16")
		if rows == 4 {
			w("\tADD\tR16, R9, R17")
			w("\tADD\tR17, R9, R19")
			w("\tADD\tR19, R9, R23")
		}
		w("\tMOVD\tR12, R22")
		w("\tMOVW\tR6, R24")
		w("%sk:", p)
		w("\tFMOVS\t(R22), F16")
		w("\tFMOVS\t(R16), F20")
		w("\tADD\t$4, R16, R16")
		w("\tFMADDS\tF16, F0, F20, F0")
		if rows == 4 {
			w("\tFMOVS\t(R17), F21")
			w("\tADD\t$4, R17, R17")
			w("\tFMADDS\tF16, F1, F21, F1")
			w("\tFMOVS\t(R19), F22")
			w("\tADD\t$4, R19, R19")
			w("\tFMADDS\tF16, F2, F22, F2")
			w("\tFMOVS\t(R23), F23")
			w("\tADD\t$4, R23, R23")
			w("\tFMADDS\tF16, F3, F23, F3")
		}
		w("\tADD\tR8, R22, R22")
		w("\tSUBW\t$1, R24, R24")
		w("\tCBNZW\tR24, %sk", p)
	}
	rowPtrs := func() {
		w("\tADD\tR11, R8, R13")
		w("\tADD\tR13, R8, R14")
		w("\tADD\tR14, R8, R15")
	}

	// ---- 4-row blocks.
	w("sgrows4:")
	w("\tCMPW\t$4, R5")
	w("\tBLT\tsgrows1")
	w("\tMOVW\tR7, R10")
	w("\tMOVD\tR2, R11")
	w("\tMOVD\tR4, R12")
	w("sg4c16:")
	w("\tCMPW\t$16, R10")
	w("\tBLT\tsg4c4")
	rowPtrs()
	for r, reg := range []int{11, 13, 14, 15} {
		for c := 0; c < 4; c++ {
			ldurQ(4*r+c, reg, 16*c)
		}
	}
	kloop4("sg4c16", 4)
	for r, reg := range []int{11, 13, 14, 15} {
		for c := 0; c < 4; c++ {
			sturQ(4*r+c, reg, 16*c)
		}
	}
	w("\tADD\t$64, R11, R11")
	w("\tADD\t$64, R12, R12")
	w("\tSUBW\t$16, R10, R10")
	w("\tB\tsg4c16")
	w("sg4c4:")
	w("\tCMPW\t$4, R10")
	w("\tBLT\tsg4c1")
	rowPtrs()
	for r, reg := range []int{11, 13, 14, 15} {
		ldurQ(4*r, reg, 0)
	}
	kloop4("sg4c4", 1)
	for r, reg := range []int{11, 13, 14, 15} {
		sturQ(4*r, reg, 0)
	}
	w("\tADD\t$16, R11, R11")
	w("\tADD\t$16, R12, R12")
	w("\tSUBW\t$4, R10, R10")
	w("\tB\tsg4c4")
	w("sg4c1:")
	w("\tCBZW\tR10, sg4next")
	rowPtrs()
	w("\tFMOVS\t(R11), F0")
	w("\tFMOVS\t(R13), F1")
	w("\tFMOVS\t(R14), F2")
	w("\tFMOVS\t(R15), F3")
	kscalar("sg4c1", 4)
	w("\tFMOVS\tF0, (R11)")
	w("\tFMOVS\tF1, (R13)")
	w("\tFMOVS\tF2, (R14)")
	w("\tFMOVS\tF3, (R15)")
	w("\tADD\t$4, R11, R11")
	w("\tADD\t$4, R12, R12")
	w("\tSUBW\t$1, R10, R10")
	w("\tB\tsg4c1")
	w("sg4next:")
	w("\tADD\tR8<<2, R2, R2")
	w("\tADD\tR9<<2, R3, R3")
	w("\tSUBW\t$4, R5, R5")
	w("\tB\tsgrows4")

	// ---- row tail, one row at a time.
	w("sgrows1:")
	w("\tCBZW\tR5, sgdone")
	w("\tMOVW\tR7, R10")
	w("\tMOVD\tR2, R11")
	w("\tMOVD\tR4, R12")
	w("sg1c16:")
	w("\tCMPW\t$16, R10")
	w("\tBLT\tsg1c4")
	for c := 0; c < 4; c++ {
		ldurQ(c, 11, 16*c)
	}
	kloop1("sg1c16", 4)
	for c := 0; c < 4; c++ {
		sturQ(c, 11, 16*c)
	}
	w("\tADD\t$64, R11, R11")
	w("\tADD\t$64, R12, R12")
	w("\tSUBW\t$16, R10, R10")
	w("\tB\tsg1c16")
	w("sg1c4:")
	w("\tCMPW\t$4, R10")
	w("\tBLT\tsg1c1")
	ldurQ(0, 11, 0)
	kloop1("sg1c4", 1)
	sturQ(0, 11, 0)
	w("\tADD\t$16, R11, R11")
	w("\tADD\t$16, R12, R12")
	w("\tSUBW\t$4, R10, R10")
	w("\tB\tsg1c4")
	w("sg1c1:")
	w("\tCBZW\tR10, sg1next")
	w("\tFMOVS\t(R11), F0")
	kscalar("sg1c1", 1)
	w("\tFMOVS\tF0, (R11)")
	w("\tADD\t$4, R11, R11")
	w("\tADD\t$4, R12, R12")
	w("\tSUBW\t$1, R10, R10")
	w("\tB\tsg1c1")
	w("sg1next:")
	w("\tADD\tR8, R2, R2")
	w("\tADD\tR9, R3, R3")
	w("\tSUBW\t$1, R5, R5")
	w("\tB\tsgrows1")
	w("sgdone:")
	w("\tRET")
	w("sgoob:")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return b.String()
}
