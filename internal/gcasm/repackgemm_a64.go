package gcasm

import (
	"fmt"
	"strings"
)

// a64RepackGemmChunkBlocks / a64RepackGemmScratch / a64RepackGemmFrame
// size the SMMLA nest's stack scratch, the arm64 twin of the amd64
// constants: per block, the two activation row groups' four 8-column
// pairs zipped into SMMLA A operands = 4 x 64 bytes.
const (
	a64RepackGemmChunkBlocks = 256
	a64RepackGemmScratch     = a64RepackGemmChunkBlocks * 256
	a64RepackGemmFrame       = 64 + a64RepackGemmScratch
)

// a64RepackGemmKernel emits the q8_0x4 repack GEMM under sym.
//
// Two nests share the prologue and the bounds contract:
//
// SMMLA nest (FEAT_I8MM, package mirror gcasmCPUI8MM): an 8-rows x
// 4-columns tile over two activation row groups at once, so every
// weight byte streamed from memory feeds 1024 MACs (the native
// q8_0_4x8 gemm's shape; the 4x4 SDOT tile below feeds 512). The
// weights stay in their 4x4 interleave: two consecutive 16-byte
// groups zip (zip1/zip2 .4s) into the two 2-columns x 8-k SMMLA B
// operands, shared by all eight rows. The activations are zipped the
// same way ONCE per chunk into the stack scratch, so the block loop
// loads its A operands ready-made. Eight 2x2 i32 tiles accumulate
// per block; each converts and scales by drow[r]*dcol[c] built from
// the two f16 quads (dup .2d of the column pair, zip of the row pair)
// and adds into eight f32 tiles that unzip (zip1/zip2 .2d) to rows at
// store time. Row groups beyond the last pair, and every CPU without
// I8MM, run the SDOT nest.
//
// SDOT nest: the 4-rows x 4-columns tile the native q8_0_4x4 dotprod
// path computes. The wasm activation block (block_q8_0x4) already
// interleaves the four rows' 4-byte groups contiguously, so each
// 16-byte weight group pairs with ONE 16-byte activation load and
// four BY-ELEMENT SDOTs:
//
//	sdot vAcc_r.4s, vWeights.16b, vActs.4b[r]
//
// Both nests keep the exact i32 sums and the block order and fuse the
// row scale into the accumulate ((f32(sum) * dcol) * drow, one
// rounding), the native-style rounding the FastMath gate admits — and
// the same sequence in both, so a row's result does not depend on the
// nest it fell into. (The SMMLA block tail was 36% of the kernel's time;
// the fused form is three ops per tile.) Larger K than the scratch
// holds runs as chunks that accumulate into the output rows in place,
// in the same block order.
//
// C signature (see llama-wasm's arch/wasm/repack.cpp):
//
//	gemm(int n, float *s, size_t bs, void *vx, void *vy, int nr, int nc)
//
// with n%32==0, nr%4==0, nc%4==0 by the caller's contract; memory
// safety does not rely on that contract — every span the loops will
// touch is bounds-checked against memSize at entry.
//
// ABI0 stack args mirror the transformed Go body. ILP32: m+0,
// l0(n)+8, l1(s)+12, l2(bs)+16, l3(vx)+20, l4(vy)+24, l5(nr)+28,
// l6(nc)+32. LP64: l1..l4 are int64, 8-aligned — l0+8, l1+16, l2+24,
// l3+32, l4+40, l5(nr)+48, l6(nc)+52.
//
// Requires FEAT_DotProd; callers gate the retarget on the dotprod
// feature dispatch that guards the SDOT bodies. FEAT_I8MM is checked
// here, at entry.
// repackGemmArgs returns the ABI0 stack offsets of the GEMM's l1..l6
// arguments and the frame's argument-byte count for the module's
// pointer width (see the layout comment above). Shared by the a64 and
// x64 emitters — the frame is arch-independent.
func repackGemmArgs(wide bool) (map[string]int, int) {
	if wide {
		return map[string]int{"l1": 16, "l2": 24, "l3": 32, "l4": 40, "l5": 48, "l6": 52}, 56
	}
	return map[string]int{"l1": 12, "l2": 16, "l3": 20, "l4": 24, "l5": 28, "l6": 32}, 36
}

func a64RepackGemmKernel(sym, trapSym string, offs *ModuleOffsets, wide bool) string {
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
	movi0 := func(d int) { word(0x4F000400|uint32(d), fmt.Sprintf("movi v%d.4s, #0", d)) }
	// SDOT (by element, 4S): acc.4s += dot4(weights.16b per lane,
	// acts.4b[idx]).
	sdotLane := func(d, n, m, idx int) {
		enc := 0x4F80E000 | uint32(idx&1)<<21 | uint32(idx>>1)<<11 | uint32(m)<<16 | uint32(n)<<5 | uint32(d)
		word(enc, fmt.Sprintf("sdot v%d.4s, v%d.16b, v%d.4b[%d]", d, n, m, idx))
	}
	// SMMLA: d.4s (2x2) += n (2 rows x 8 i8) · m (2 rows x 8 i8)^T.
	smmla := func(d, n, m int) {
		word(0x4E80A400|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("smmla v%d.4s, v%d.16b, v%d.16b", d, n, m))
	}
	zip1S := func(d, n, m int) {
		word(0x4E803800|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("zip1 v%d.4s, v%d.4s, v%d.4s", d, n, m))
	}
	zip2S := func(d, n, m int) {
		word(0x4E807800|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("zip2 v%d.4s, v%d.4s, v%d.4s", d, n, m))
	}
	zip1D := func(d, n, m int) {
		word(0x4EC03800|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("zip1 v%d.2d, v%d.2d, v%d.2d", d, n, m))
	}
	zip2D := func(d, n, m int) {
		word(0x4EC07800|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("zip2 v%d.2d, v%d.2d, v%d.2d", d, n, m))
	}
	dupD := func(d, n, idx int) {
		word(0x4E080400|uint32(idx)<<20|uint32(n)<<5|uint32(d), fmt.Sprintf("dup v%d.2d, v%d.d[%d]", d, n, idx))
	}
	fcvtl := func(d, n int) { word(0x0E217800|uint32(n)<<5|uint32(d), fmt.Sprintf("fcvtl v%d.4s, v%d.4h", d, n)) }
	scvtf := func(d, n int) { word(0x4E21D800|uint32(n)<<5|uint32(d), fmt.Sprintf("scvtf v%d.4s, v%d.4s", d, n)) }
	fmulV := func(d, n, m int) {
		word(0x6E20DC00|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmul v%d.4s, v%d.4s, v%d.4s", d, n, m))
	}
	fmlaV := func(d, n, m int) {
		word(0x4E20CC00|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmla v%d.4s, v%d.4s, v%d.4s", d, n, m))
	}
	fmlaLane := func(d, n, m, idx int) {
		enc := 0x4F801000 | uint32(idx&1)<<21 | uint32(idx>>1)<<11 | uint32(m)<<16 | uint32(n)<<5 | uint32(d)
		word(enc, fmt.Sprintf("fmla v%d.4s, v%d.4s, v%d.s[%d]", d, n, m, idx))
	}

	argOff, argBytes := repackGemmArgs(wide)
	movArg := "MOVWU"
	if wide {
		movArg = "MOVD"
	}
	arg := func(name string, reg int) {
		mv := movArg
		if name == "l5" || name == "l6" {
			mv = "MOVWU" // nr/nc stay int32 at either width
		}
		w("\t%s\t%s+%d(FP), R%d", mv, name, argOff[name], reg)
	}

	w("// %s: q8_0x4 repack GEMM, 8x4 tile via SMMLA / 4x4 tile via by-element SDOT.", sym)
	w("TEXT ·%s(SB), $%d-%d", sym, a64RepackGemmFrame, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVD\tm+0(FP), R0")
	w("\tMOVD\t%d(R0), R21", offs.MemSize)
	w("\tMOVD\t(R21), R21")
	w("\tMOVD\t%d(R0), R20", offs.M)
	// nb = n >> 5; xtotal = nb*136 (the per-column-group byte span:
	// nb interleaved blocks of 8-byte scales + 128-byte quants).
	w("\tMOVW\tl0+8(FP), R1")
	w("\tLSRW\t$5, R1, R1")
	w("\tMOVD\t$136, R8")
	w("\tMUL\tR1, R8, R8")
	arg("l5", 6)
	w("\tLSRW\t$2, R6, R6") // nr/4
	arg("l6", 7)
	w("\tLSRW\t$2, R7, R7") // nc/4
	// Empty problem: nothing is read or written.
	w("\tCBZW\tR6, gemmdone")
	w("\tCBZW\tR7, gemmdone")
	// Bounds: vx + nc4*xtotal, vy + nr4*xtotal, and the last store
	// byte s + ((nr-1)*bs + nc)*4 must all sit inside memSize.
	arg("l3", 4)
	w("\tMUL\tR7, R8, R26")
	w("\tADD\tR4, R26, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tgemmoob")
	arg("l4", 5)
	w("\tMUL\tR6, R8, R26")
	w("\tADD\tR5, R26, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tgemmoob")
	arg("l1", 2)
	arg("l2", 3)
	w("\tLSL\t$2, R3, R3") // bs in bytes
	w("\tLSL\t$2, R6, R9")
	w("\tSUB\t$1, R9, R9") // nr-1
	w("\tMUL\tR3, R9, R26")
	w("\tADD\tR2, R26, R26")
	w("\tLSL\t$4, R7, R9")
	w("\tADD\tR9, R26, R26") // + nc*4 bytes
	w("\tCMP\tR26, R21")
	w("\tBLO\tgemmoob")
	// Host pointers: activations row-group cursor, output row cursor.
	w("\tADD\tR20, R5, R10") // a base (host)
	w("\tADD\tR20, R2, R11") // s row base (host)
	w("\tADD\tR20, R4, R22") // vx base (host)
	w("\tLSL\t$2, R3, R23")  // 4*bs bytes: s row-group stride
	w("\tMOVBU\t·gcasmCPUI8MM(SB), R26")
	w("\tCBZ\tR26, gemmsdot")

	// ---- SMMLA nest: row-group pairs.
	//
	// R9 chunk byte offset | R24 blocks left | R25 chunk blocks
	// R19 scratch cursor | R17 ap (group a) | R27 ap (group b)
	// v0..v7 i32 2x2 tiles (index 2*rowpair+colpair, row pairs
	// 01a 23a 01b 23b) | v24..v31 f32 tiles | v16..v23 operands.
	w("gemmm:")
	w("\tCMPW\t$2, R6")
	w("\tBLO\tgemmsdot") // 0 or 1 row groups left
	w("\tMOVD\t$0, R9")
	w("\tMOVW\tR1, R24")
	w("gemmmchunk:")
	w("\tMOVW\t$%d, R25", a64RepackGemmChunkBlocks)
	w("\tCMPW\tR25, R24")
	w("\tCSELW\tLO, R24, R25, R25")
	// Zip this tile's activation chunk: per block and 8-column pair,
	// A01/A23 of row group a then of row group b (4 x 16 bytes).
	w("\tADD\tR10, R9, R17")
	w("\tADD\tR17, R8, R27")
	w("\tMOVD\t$gemmscratch-%d(SP), R19", a64RepackGemmScratch)
	w("\tMOVW\tR25, R15")
	w("\tCBZW\tR15, gemmmx0")
	w("gemmmpre:")
	for p := 0; p < 4; p++ {
		ldurQ(16, 17, 8+32*p)
		ldurQ(17, 17, 24+32*p)
		zip1S(18, 16, 17)
		zip2S(19, 16, 17)
		sturQ(18, 19, 64*p)
		sturQ(19, 19, 64*p+16)
		ldurQ(16, 27, 8+32*p)
		ldurQ(17, 27, 24+32*p)
		zip1S(20, 16, 17)
		zip2S(21, 16, 17)
		sturQ(20, 19, 64*p+32)
		sturQ(21, 19, 64*p+48)
	}
	w("\tADD\t$136, R17, R17")
	w("\tADD\t$136, R27, R27")
	w("\tADD\t$256, R19, R19")
	w("\tSUBW\t$1, R15, R15")
	w("\tCBNZW\tR15, gemmmpre")
	w("gemmmx0:")
	w("\tADD\tR22, R9, R13") // b column-group cursor at the chunk offset
	w("\tMOVD\tR11, R14")    // s column cursor
	w("\tMOVW\tR7, R12")     // x counter
	w("gemmmx:")
	// f32 tiles: zero on the first chunk, else the rows' running
	// sums re-zipped into 2x2 form.
	w("\tCBNZ\tR9, gemmmxload")
	for i := 24; i < 32; i++ {
		movi0(i)
	}
	w("\tB\tgemmmxgo")
	w("gemmmxload:")
	w("\tMOVD\tR14, R26")
	for rp := 0; rp < 4; rp++ {
		ldurQ(16, 26, 0)
		w("\tADD\tR3, R26, R26")
		ldurQ(17, 26, 0)
		w("\tADD\tR3, R26, R26")
		zip1D(24+2*rp, 16, 17)
		zip2D(25+2*rp, 16, 17)
	}
	w("gemmmxgo:")
	w("\tMOVD\tR13, R16")
	w("\tADD\tR10, R9, R17")
	w("\tADD\tR17, R8, R27")
	w("\tMOVD\t$gemmscratch-%d(SP), R19", a64RepackGemmScratch)
	w("\tMOVW\tR25, R15")
	w("\tCBZW\tR15, gemmmstore")
	w("gemmmblk:")
	for i := 0; i < 8; i++ {
		movi0(i)
	}
	for p := 0; p < 4; p++ {
		ldurQ(16, 16, 8+32*p)
		ldurQ(17, 16, 24+32*p)
		zip1S(18, 16, 17) // B01: columns 0,1 x 8 k
		zip2S(19, 16, 17) // B23
		ldurQ(20, 19, 64*p)
		ldurQ(21, 19, 64*p+16)
		ldurQ(22, 19, 64*p+32)
		ldurQ(23, 19, 64*p+48)
		smmla(0, 20, 18)
		smmla(1, 20, 19)
		smmla(2, 21, 18)
		smmla(3, 21, 19)
		smmla(4, 22, 18)
		smmla(5, 22, 19)
		smmla(6, 23, 18)
		smmla(7, 23, 19)
	}
	// Scales. dcol -> [dc0 dc1 dc0 dc1] / [dc2 dc3 dc2 dc3]; each
	// row group's drow -> [dr0 dr0 dr1 dr1] / [dr2 dr2 dr3 dr3].
	ldurD(16, 16, 0)
	fcvtl(16, 16)
	dupD(18, 16, 0)
	dupD(19, 16, 1)
	ldurD(17, 17, 0)
	fcvtl(17, 17)
	zip1S(20, 17, 17)
	zip2S(21, 17, 17)
	ldurD(17, 27, 0)
	fcvtl(17, 17)
	zip1S(22, 17, 17)
	zip2S(23, 17, 17)
	// tile(rp, cp): f32 += (f32(i32) * dcol_cp) * drow_rp — the column
	// scale by multiply, the row scale fused into the accumulate
	// (one rounding; fast-math, as the f32 GEMM). This block tail was
	// 36% of the kernel's time measured with it removed, so it pays
	// to keep it at three ops per tile.
	for i := 0; i < 8; i++ {
		rp, cp := i/2, i%2
		scvtf(i, i)
		fmulV(i, i, 18+cp)
		fmlaV(24+i, i, 20+rp)
	}
	w("\tADD\t$136, R16, R16")
	w("\tADD\t$136, R17, R17")
	w("\tADD\t$136, R27, R27")
	w("\tADD\t$256, R19, R19")
	w("\tSUBW\t$1, R15, R15")
	w("\tCBNZW\tR15, gemmmblk")
	w("gemmmstore:")
	// Rows 2rp / 2rp+1 = the low / high halves of tiles (rp,01),(rp,23).
	w("\tMOVD\tR14, R26")
	for rp := 0; rp < 4; rp++ {
		zip1D(16, 24+2*rp, 25+2*rp)
		zip2D(17, 24+2*rp, 25+2*rp)
		sturQ(16, 26, 0)
		w("\tADD\tR3, R26, R26")
		sturQ(17, 26, 0)
		w("\tADD\tR3, R26, R26")
	}
	w("\tADD\tR8, R13, R13")
	w("\tADD\t$16, R14, R14")
	w("\tSUBW\t$1, R12, R12")
	w("\tCBNZW\tR12, gemmmx")
	// Next chunk of this tile, if any.
	w("\tSUBW\tR25, R24, R24")
	w("\tMOVD\t$136, R26")
	w("\tMUL\tR25, R26, R26")
	w("\tADD\tR26, R9, R9")
	w("\tCBNZW\tR24, gemmmchunk")
	// Next row-group pair.
	w("\tADD\tR8<<1, R10, R10")
	w("\tADD\tR23<<1, R11, R11")
	w("\tSUBW\t$2, R6, R6")
	w("\tB\tgemmm")

	// ---- SDOT nest: remaining row groups (all of them without I8MM).
	w("gemmsdot:")
	w("\tCBZW\tR6, gemmdone")
	w("gemmy:")
	w("\tMOVD\tR22, R13") // b column-group cursor
	w("\tMOVD\tR11, R14") // s column cursor
	w("\tMOVW\tR7, R12")  // x counter
	w("gemmx:")
	movi0(28)
	movi0(29)
	movi0(30)
	movi0(31)
	w("\tMOVD\tR13, R16") // bp
	w("\tMOVD\tR10, R17") // ap
	w("\tMOVW\tR1, R15")  // block counter
	w("\tCBZW\tR15, gemmstore")
	w("gemmblk:")
	movi0(24)
	movi0(25)
	movi0(26)
	movi0(27)
	for k := 0; k < 8; k++ {
		ldurQ(0, 16, 8+16*k)
		ldurQ(1, 17, 8+16*k)
		sdotLane(24, 0, 1, 0)
		sdotLane(25, 0, 1, 1)
		sdotLane(26, 0, 1, 2)
		sdotLane(27, 0, 1, 3)
	}
	// Scales: column d[4] and row d[4] (f16 -> f32), then per row
	// sumv_r += (f32(acc_r) * dcol) * drow[r] with the row scale fused
	// — the SAME sequence and rounding as the SMMLA nest's tail, so a
	// row's result does not depend on whether it fell into a pair or
	// into this tail group.
	ldurD(2, 16, 0)
	fcvtl(2, 2)
	ldurD(3, 17, 0)
	fcvtl(3, 3)
	for r := 0; r < 4; r++ {
		scvtf(24+r, 24+r)
		fmulV(24+r, 24+r, 2)
		fmlaLane(28+r, 24+r, 3, r)
	}
	w("\tADD\t$136, R16, R16")
	w("\tADD\t$136, R17, R17")
	w("\tSUBW\t$1, R15, R15")
	w("\tCBNZW\tR15, gemmblk")
	w("gemmstore:")
	sturQ(28, 14, 0)
	w("\tADD\tR14, R3, R26")
	sturQ(29, 26, 0)
	w("\tADD\tR26, R3, R26")
	sturQ(30, 26, 0)
	w("\tADD\tR26, R3, R26")
	sturQ(31, 26, 0)
	w("\tADD\tR8, R13, R13")  // next column group's weights
	w("\tADD\t$16, R14, R14") // next 4 output floats
	w("\tSUBW\t$1, R12, R12")
	w("\tCBNZW\tR12, gemmx")
	w("\tADD\tR8, R10, R10")  // next activation row group
	w("\tADD\tR23, R11, R11") // next 4 output rows
	w("\tSUBW\t$1, R6, R6")
	w("\tCBNZW\tR6, gemmy")
	w("gemmdone:")
	w("\tRET")
	w("gemmoob:")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return b.String()
}
