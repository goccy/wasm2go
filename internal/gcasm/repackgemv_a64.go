package gcasm

import (
	"fmt"
	"strings"
)

// a64RepackGemvKernel emits the q8_0x4 repack GEMV under sym: one
// activation row (block_q8_0) against nc columns of interleaved
// weights (block_q8_0x4), the decode-time matmul.
//
// Four column groups (16 outputs) per pass share the activation
// loads: per block the 32 quant bytes arrive as two 16-byte registers
// whose 4-byte lanes are the eight k-quads, and each weight group
// SDOTs against the matching lane (sdot .4b[k]) into its own i32
// accumulator — 32 independent SDOTs per block over four weight
// streams, then per group scvtf -> x (dcol * da) -> + running f32 sum
// (the wasm gemv's own per-block order). Leftover groups run one at a
// time. The kernel exists to replace the transpiled fused loop, which
// pays a bounds check per load and a table lookup per f16 scale; it is
// bandwidth-bound after that.
//
// C signature (llama-wasm arch/wasm/repack.cpp):
//
//	gemv(int n, float *s, size_t bs, void *vx, void *vy, int nr, int nc)
//
// nr is 1 by contract (asserted in C); the kernel computes row 0.
// Bounds: vx + nc4*xtotal, vy + nb*34 and s + nc*4 are checked against
// memSize at entry.
// a64GemvFourGroups selects the four-groups-per-pass main loop; when
// false (the default) every group runs through the single-group loop,
// two SDOT chains per block. Decode is DRAM-bound and one sequential
// weight stream feeds the prefetchers best: on Apple M5 the single
// stream decodes 3% faster than four interleaved streams (and 5% faster
// than the transpiled fused loop), even though the four-stream loop
// wins a warm-cache micro-benchmark (90 vs 83 GB/s).
var a64GemvFourGroups = false

func a64RepackGemvKernel(sym, trapSym string, offs *ModuleOffsets, wide bool) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	word := func(enc uint32, dis string) { w("\tWORD $0x%08x // %s", enc, dis) }
	ldurQ := func(rt, rn, imm int) {
		word(0x3CC00000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("ldur q%d, [x%d, #%d]", rt, rn, imm))
	}
	sturQ := func(rt, rn, imm int) {
		word(0x3C800000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("stur q%d, [x%d, #%d]", rt, rn, imm))
	}
	ldurD := func(rt, rn, imm int) {
		word(0xFC400000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("ldur d%d, [x%d, #%d]", rt, rn, imm))
	}
	ldurH := func(t, n, imm int) {
		word(0x7C400000|uint32(imm&0x1FF)<<12|uint32(n)<<5|uint32(t), fmt.Sprintf("ldur h%d, [x%d, #%d]", t, n, imm))
	}
	fcvtSH := func(d, n int) { word(0x1EE24000|uint32(n)<<5|uint32(d), fmt.Sprintf("fcvt s%d, h%d", d, n)) }
	movi0 := func(d int) { word(0x4F000400|uint32(d), fmt.Sprintf("movi v%d.4s, #0", d)) }
	sdotLane := func(d, n, m, idx int) {
		enc := 0x4F80E000 | uint32(idx&1)<<21 | uint32(idx>>1)<<11 | uint32(m)<<16 | uint32(n)<<5 | uint32(d)
		word(enc, fmt.Sprintf("sdot v%d.4s, v%d.16b, v%d.4b[%d]", d, n, m, idx))
	}
	fcvtl := func(d, n int) { word(0x0E217800|uint32(n)<<5|uint32(d), fmt.Sprintf("fcvtl v%d.4s, v%d.4h", d, n)) }
	scvtf := func(d, n int) { word(0x4E21D800|uint32(n)<<5|uint32(d), fmt.Sprintf("scvtf v%d.4s, v%d.4s", d, n)) }
	fmulLane := func(d, n, m, idx int) {
		enc := 0x4F809000 | uint32(idx&1)<<21 | uint32(idx>>1)<<11 | uint32(m)<<16 | uint32(n)<<5 | uint32(d)
		word(enc, fmt.Sprintf("fmul v%d.4s, v%d.4s, v%d.s[%d]", d, n, m, idx))
	}
	fmulV := func(d, n, m int) {
		word(0x6E20DC00|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmul v%d.4s, v%d.4s, v%d.4s", d, n, m))
	}
	faddV := func(d, n, m int) {
		word(0x4E20D400|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fadd v%d.4s, v%d.4s, v%d.4s", d, n, m))
	}

	argOff, argBytes := repackGemmArgs(wide)
	movArg := "MOVWU"
	if wide {
		movArg = "MOVD"
	}
	arg := func(name string, reg int) {
		mv := movArg
		if name == "l5" || name == "l6" {
			mv = "MOVWU"
		}
		w("\t%s\t%s+%d(FP), R%d", mv, name, argOff[name], reg)
	}

	// Per-group block tail: v(acc) i32 -> f32, x (dcol * da), into v(sum).
	// dcol comes from the group's block header, da is in v18.s[0].
	tail := func(acc, sum, bp int) {
		ldurD(19, bp, 0)
		fcvtl(19, 19)
		fmulLane(19, 19, 18, 0)
		scvtf(acc, acc)
		fmulV(acc, acc, 19)
		faddV(sum, sum, acc)
	}

	w("// %s: q8_0x4 repack GEMV, four column groups per pass via by-element SDOT.", sym)
	w("TEXT ·%s(SB), $16-%d", sym, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVD\tm+0(FP), R0")
	w("\tMOVD\t%d(R0), R21", offs.MemSize)
	w("\tMOVD\t(R21), R21")
	w("\tMOVD\t%d(R0), R20", offs.M)
	w("\tMOVW\tl0+8(FP), R1")
	w("\tLSRW\t$5, R1, R1") // nb
	w("\tMOVD\t$136, R8")
	w("\tMUL\tR1, R8, R8") // xtotal
	arg("l6", 7)
	w("\tLSRW\t$2, R7, R7") // nc4
	w("\tCBZW\tR7, gvdone")
	arg("l3", 4)
	w("\tMUL\tR7, R8, R26")
	w("\tADD\tR4, R26, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tgvoob")
	arg("l4", 5)
	w("\tMOVD\t$34, R26")
	w("\tMUL\tR1, R26, R26")
	w("\tADD\tR5, R26, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tgvoob")
	arg("l1", 2)
	w("\tLSL\t$4, R7, R26")
	w("\tADD\tR2, R26, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tgvoob")
	w("\tADD\tR20, R2, R2") // s (host)
	w("\tADD\tR20, R4, R4") // vx (host)
	w("\tADD\tR20, R5, R5") // vy (host)
	w("\tLSL\t$2, R8, R9")  // 4*xtotal: stride of a 4-group pass

	// ---- four groups per pass.
	w("gv4:")
	if !a64GemvFourGroups {
		w("\tB\tgv1")
	}
	w("\tCMPW\t$4, R7")
	w("\tBLT\tgv1")
	movi0(28)
	movi0(29)
	movi0(30)
	movi0(31)
	w("\tMOVD\tR4, R13")
	w("\tADD\tR13, R8, R14")
	w("\tADD\tR14, R8, R19")
	w("\tADD\tR19, R8, R23")
	w("\tMOVD\tR5, R17")
	w("\tMOVW\tR1, R15")
	w("\tCBZW\tR15, gv4store")
	w("gv4blk:")
	movi0(24)
	movi0(25)
	movi0(26)
	movi0(27)
	ldurQ(16, 17, 2)  // quads 0..3
	ldurQ(17, 17, 18) // quads 4..7
	ldurH(18, 17, 0)
	fcvtSH(18, 18) // da
	for k := 0; k < 8; k++ {
		act := 16 + k/4
		for g, bp := range []int{13, 14, 19, 23} {
			ldurQ(g, bp, 8+16*k)
			sdotLane(24+g, g, act, k%4)
		}
	}
	tail(24, 28, 13)
	tail(25, 29, 14)
	tail(26, 30, 19)
	tail(27, 31, 23)
	w("\tADD\t$136, R13, R13")
	w("\tADD\t$136, R14, R14")
	w("\tADD\t$136, R19, R19")
	w("\tADD\t$136, R23, R23")
	w("\tADD\t$34, R17, R17")
	w("\tSUBW\t$1, R15, R15")
	w("\tCBNZW\tR15, gv4blk")
	w("gv4store:")
	sturQ(28, 2, 0)
	sturQ(29, 2, 16)
	sturQ(30, 2, 32)
	sturQ(31, 2, 48)
	w("\tADD\t$64, R2, R2")
	w("\tADD\tR9, R4, R4")
	w("\tSUBW\t$4, R7, R7")
	w("\tB\tgv4")

	// ---- leftover groups, one at a time.
	w("gv1:")
	w("\tCBZW\tR7, gvdone")
	movi0(28)
	w("\tMOVD\tR4, R13")
	w("\tMOVD\tR5, R17")
	w("\tMOVW\tR1, R15")
	w("\tCBZW\tR15, gv1store")
	w("gv1blk:")
	movi0(24)
	movi0(25)
	ldurQ(16, 17, 2)
	ldurQ(17, 17, 18)
	ldurH(18, 17, 0)
	fcvtSH(18, 18)
	for k := 0; k < 8; k++ {
		ldurQ(k%2, 13, 8+16*k)
		sdotLane(24+k%2, k%2, 16+k/4, k%4)
	}
	word(0x4EA08400|uint32(25)<<16|uint32(24)<<5|uint32(24), "add v24.4s, v24.4s, v25.4s")
	tail(24, 28, 13)
	w("\tADD\t$136, R13, R13")
	w("\tADD\t$34, R17, R17")
	w("\tSUBW\t$1, R15, R15")
	w("\tCBNZW\tR15, gv1blk")
	w("gv1store:")
	sturQ(28, 2, 0)
	w("\tADD\t$16, R2, R2")
	w("\tADD\tR8, R4, R4")
	w("\tSUBW\t$1, R7, R7")
	w("\tB\tgv1")
	w("gvdone:")
	w("\tRET")
	w("gvoob:")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return b.String()
}
