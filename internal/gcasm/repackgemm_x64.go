package gcasm

import (
	"fmt"
	"strings"
)

// x64RepackGemmChunkBlocks is the number of q8_0 blocks (32 columns
// each, so 8192 columns of K) whose activation row group the AVX2
// nest widens into its stack scratch at a time. Larger K runs as a
// sequence of chunks that accumulate into the output rows in place,
// in the same block order as a single pass — the f32 sums are
// identical, only a register-to-memory round trip is added.
const x64RepackGemmChunkBlocks = 256

// x64RepackGemmScratch is the AVX2 nest's stack scratch: per block,
// the 8 activation groups sign-extended to i16 (16 lanes = 4 rows x
// 4 columns) = 8 x 32 bytes.
const x64RepackGemmScratch = x64RepackGemmChunkBlocks * 256

// x64RepackGemmFrame is the kernel frame: the widened-activation
// scratch behind 64 bytes of loop bookkeeping.
const x64RepackGemmFrame = 64 + x64RepackGemmScratch

// x64RepackGemmKernel emits the q8_0x4 repack GEMM under sym for
// amd64 — the 4x4 tile the a64 twin computes with by-element SDOT,
// with an entry branch to a VNNI loop on CPUs reporting AVX-512 VNNI
// at 256-bit width. See a64RepackGemmKernel for the tile shape, the
// bounds-check contract and the fast-math gating; the memory layouts
// and the ABI0 argument frame are identical.
//
// AVX2 nest. The activation row group is widened ONCE per chunk into
// the stack scratch (a 16-byte group of four 4-byte row quads becomes
// 32 bytes of i16), so the block loop's per-(group, row) work is a
// pure-load VPBROADCASTQ of the row's four i16 plus VPMADDWD and
// VPADDD into that row's pair-domain ymm accumulator — no in-loop
// shuffles or sign extensions besides the one VPMOVSXBW per weight
// group that all four rows share. Per block the four pair-domain
// accumulators collapse with two VPHADDD, two VPERM2I128 and two
// unpacks into [row0|row2] and [row1|row3] column vectors, which
// convert and scale as ymm pairs into two f32 accumulators. The
// per-block arithmetic on each output element is the wasm kernel's
// own: exact i32 column sum -> f32 -> x (dcol * drow) -> + running
// sum, in block order.
//
// VNNI nest: the same chunk/prepass structure at 256-bit width. The
// prepass stores, per group pair and row, the 8 bytes [quad_k,
// quad_k+1] xor 0x80 (u8); the weight pair is VPERMD'd to per-column
// pairs (s8) and ONE VPDPBUSD per row covers 8 columns x 4 k; the
// +128 activation bias is undone with a weight column sum shared by
// the four rows (one VPDPBUSD(ones, weights) per pair, one subtract
// per row per block), then the AVX2 collapse applies unchanged.
//
// Register file after the prologue (memSize/M die once the entry
// checks pass and every pointer is host-absolute):
//
//	CX vx base | SI a-row-group cursor | BX s-row-group cursor
//	R8 nb | R9 xtotal | R10 y ctr | R14 bs bytes | R15 4*bs
//	DX b-col cursor | DI s-col cursor | R13 x ctr (VNNI: R11 nc4)
//	R12 bp | AX ap | R11 scratch cursor (AVX2)
//	0(SP) block ctr | 8(SP) blocks left | 16(SP) chunk byte offset
//	24(SP) nc4 | 32(SP) chunk blocks | 64(SP).. scratch
func x64RepackGemmKernel(sym, trapSym string, offs *ModuleOffsets, pool *ConstPool, wide bool) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	c16 := func(bt byte) string {
		blob := make([]byte, 16)
		for i := range blob {
			blob[i] = bt
		}
		return pool.addBlob(blob)
	}
	biasSym := c16(0x80)
	onesSym := c16(0x01)
	// VPERMPS index vectors: lanes [0 0 0 0 2 2 2 2] / [1 1 1 1 3 3 3 3]
	// broadcast the row scales of the [row0|row2] and [row1|row3]
	// accumulator halves.
	idxSym := func(lo, hi byte) string {
		blob := make([]byte, 32)
		for i := 0; i < 4; i++ {
			blob[4*i] = lo
			blob[16+4*i] = hi
		}
		return pool.addBlob(blob)
	}
	idx02Sym := idxSym(0, 2)
	idx13Sym := idxSym(1, 3)
	// VPERMD index [0 4 1 5 2 6 3 7]: a 32-byte weight pair
	// [c0..c3 of group k | c0..c3 of group k+1] -> per-column pairs.
	permSym := func() string {
		blob := make([]byte, 32)
		for i, v := range []byte{0, 4, 1, 5, 2, 6, 3, 7} {
			blob[4*i] = v
		}
		return pool.addBlob(blob)
	}()

	argOff, argBytes := repackGemmArgs(wide)
	movArg := "MOVL"
	if wide {
		movArg = "MOVQ"
	}
	arg := func(name, reg string) {
		mv := movArg
		if name == "l5" || name == "l6" {
			mv = "MOVL"
		}
		w("\t%s\t%s+%d(FP), %s", mv, name, argOff[name], reg)
	}
	memCheck := func() {
		w("\tCMPQ\tR15, R12")
		w("\tJCS\tgemmoob")
	}

	w("// %s: q8_0x4 repack GEMM, 4x4 tile via AVX2 / VNNI.", sym)
	w("TEXT ·%s(SB), $%d-%d", sym, x64RepackGemmFrame, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVQ\tm+0(FP), AX")
	w("\tMOVQ\t%d(AX), R15", offs.MemSize)
	w("\tMOVQ\t(R15), R15")
	w("\tMOVQ\t%d(AX), R14", offs.M)
	w("\tMOVL\tl0+8(FP), R8")
	w("\tSHRL\t$5, R8")
	w("\tIMUL3Q\t$136, R8, R9")
	arg("l5", "R10")
	w("\tSHRL\t$2, R10")
	arg("l6", "R11")
	w("\tSHRL\t$2, R11")
	w("\tTESTL\tR10, R10")
	w("\tJZ\tgemmdone")
	w("\tTESTL\tR11, R11")
	w("\tJZ\tgemmdone")
	// Bounds: vx + nc4*xtotal, vy + nr4*xtotal, s + ((nr-1)*bs+nc)*4.
	arg("l3", "CX")
	w("\tMOVQ\tR11, R12")
	w("\tIMULQ\tR9, R12")
	w("\tADDQ\tCX, R12")
	memCheck()
	arg("l4", "SI")
	w("\tMOVQ\tR10, R12")
	w("\tIMULQ\tR9, R12")
	w("\tADDQ\tSI, R12")
	memCheck()
	arg("l1", "BX")
	arg("l2", "DX")
	w("\tSHLQ\t$2, DX")
	w("\tMOVQ\tR10, R12")
	w("\tSHLQ\t$2, R12")
	w("\tSUBQ\t$1, R12")
	w("\tIMULQ\tDX, R12")
	w("\tADDQ\tBX, R12")
	w("\tMOVQ\tR11, R13")
	w("\tSHLQ\t$4, R13")
	w("\tADDQ\tR13, R12")
	memCheck()
	// Host pointers; the strides take over memSize/M's registers.
	w("\tADDQ\tR14, CX")
	w("\tADDQ\tR14, SI")
	w("\tADDQ\tR14, BX")
	w("\tMOVQ\tDX, R14")
	w("\tMOVQ\tDX, R15")
	w("\tSHLQ\t$2, R15")
	w("\tMOVL\tR11, 24(SP)")
	w("\tCMPB\t·gcasmHasAVX512VNNI(SB), $0")
	w("\tJNE\tvgemmy")

	// ---- AVX2 nest: chunked, widened activations in the scratch.
	fmt.Fprintf(&b, "\tVMOVDQU ·%s(SB), Y14\n", idx02Sym)
	fmt.Fprintf(&b, "\tVMOVDQU ·%s(SB), Y15\n", idx13Sym)
	w("gemmy:")
	w("\tMOVQ\t$0, 16(SP)")
	w("\tMOVL\tR8, 8(SP)")
	w("gemmchunk:")
	// cnt = min(blocks left, chunk)
	w("\tMOVL\t8(SP), R13")
	w("\tMOVL\t$%d, AX", x64RepackGemmChunkBlocks)
	w("\tCMPL\tR13, AX")
	w("\tCMOVLGT\tAX, R13")
	w("\tMOVL\tR13, 32(SP)")
	// Widen this row group's chunk: 16 bytes [r0 r1 r2 r3] x 4 i8
	// -> 32 bytes of i16 per group, 8 groups per block.
	w("\tMOVQ\tSI, AX")
	w("\tADDQ\t16(SP), AX")
	w("\tLEAQ\t64(SP), R11")
	w("\tTESTL\tR13, R13")
	w("\tJZ\tgemmxinit")
	w("gemmpre:")
	for k := 0; k < 8; k++ {
		w("\tVPMOVSXBW\t%d(AX), Y4", 8+16*k)
		w("\tVMOVDQU\tY4, %d(R11)", 32*k)
	}
	w("\tADDQ\t$136, AX")
	w("\tADDQ\t$256, R11")
	w("\tDECL\tR13")
	w("\tJNZ\tgemmpre")
	w("gemmxinit:")
	w("\tMOVQ\tCX, DX")
	w("\tADDQ\t16(SP), DX")
	w("\tMOVQ\tBX, DI")
	w("\tMOVL\t24(SP), R13")
	w("gemmx:")
	// f32 accumulators [row0|row2] / [row1|row3]: zero on the first
	// chunk, else the rows' running sums from s.
	w("\tCMPQ\t16(SP), $0")
	w("\tJNE\tgemmxload")
	w("\tVPXOR\tY8, Y8, Y8")
	w("\tVPXOR\tY9, Y9, Y9")
	w("\tJMP\tgemmxgo")
	w("gemmxload:")
	w("\tLEAQ\t(DI)(R14*2), R12")
	w("\tVMOVUPS\t(DI), X8")
	w("\tVINSERTF128\t$1, (R12), Y8, Y8")
	w("\tVMOVUPS\t(DI)(R14*1), X9")
	w("\tVINSERTF128\t$1, (R12)(R14*1), Y9, Y9")
	w("gemmxgo:")
	w("\tMOVQ\tDX, R12")
	w("\tMOVQ\tSI, AX")
	w("\tADDQ\t16(SP), AX")
	w("\tMOVL\t32(SP), R11")
	w("\tMOVL\tR11, 0(SP)")
	w("\tLEAQ\t64(SP), R11")
	w("\tCMPL\t0(SP), $0")
	w("\tJZ\tgemmstore")
	w("gemmblk:")
	w("\tVPXOR\tY0, Y0, Y0")
	w("\tVPXOR\tY1, Y1, Y1")
	w("\tVPXOR\tY2, Y2, Y2")
	w("\tVPXOR\tY3, Y3, Y3")
	for k := 0; k < 8; k++ {
		w("\tVPMOVSXBW\t%d(R12), Y4", 8+16*k)
		for row := 0; row < 4; row++ {
			w("\tVPBROADCASTQ\t%d(R11), Y5", 32*k+8*row)
			w("\tVPMADDWD\tY4, Y5, Y5")
			w("\tVPADDD\tY5, Y%d, Y%d", row, row)
		}
	}
	// Collapse the pair domain: T01 = [r0c0 r0c1 r1c0 r1c1 | r0c2
	// r0c3 r1c2 r1c3], T23 likewise; the lane swap + unpacks yield
	// [row0 | row2] and [row1 | row3].
	w("\tVPHADDD\tY1, Y0, Y10")
	w("\tVPHADDD\tY3, Y2, Y11")
	w("\tVPERM2I128\t$0x20, Y11, Y10, Y4")
	w("\tVPERM2I128\t$0x31, Y11, Y10, Y5")
	w("\tVPUNPCKLQDQ\tY5, Y4, Y10")
	w("\tVPUNPCKHQDQ\tY5, Y4, Y11")
	// Scales: dcol[4] in both halves; drow broadcast per half.
	w("\tVMOVQ\t(R12), X6")
	w("\tVCVTPH2PS\tX6, X12")
	w("\tVINSERTF128\t$1, X12, Y12, Y12")
	w("\tVMOVQ\t(AX), X6")
	w("\tVCVTPH2PS\tX6, X13")
	w("\tVPERMPS\tY13, Y14, Y4")
	w("\tVMULPS\tY12, Y4, Y4")
	w("\tVPERMPS\tY13, Y15, Y5")
	w("\tVMULPS\tY12, Y5, Y5")
	w("\tVCVTDQ2PS\tY10, Y10")
	w("\tVMULPS\tY4, Y10, Y10")
	w("\tVADDPS\tY10, Y8, Y8")
	w("\tVCVTDQ2PS\tY11, Y11")
	w("\tVMULPS\tY5, Y11, Y11")
	w("\tVADDPS\tY11, Y9, Y9")
	w("\tADDQ\t$136, R12")
	w("\tADDQ\t$136, AX")
	w("\tADDQ\t$256, R11")
	w("\tDECL\t0(SP)")
	w("\tJNZ\tgemmblk")
	w("gemmstore:")
	w("\tLEAQ\t(DI)(R14*2), R12")
	w("\tVMOVUPS\tX8, (DI)")
	w("\tVMOVUPS\tX9, (DI)(R14*1)")
	w("\tVEXTRACTF128\t$1, Y8, X6")
	w("\tVMOVUPS\tX6, (R12)")
	w("\tVEXTRACTF128\t$1, Y9, X6")
	w("\tVMOVUPS\tX6, (R12)(R14*1)")
	w("\tADDQ\tR9, DX")
	w("\tADDQ\t$16, DI")
	w("\tSUBL\t$1, R13")
	w("\tJNZ\tgemmx")
	// Next chunk of this row group, if any.
	w("\tMOVL\t32(SP), R13")
	w("\tSUBL\tR13, 8(SP)")
	w("\tIMUL3Q\t$136, R13, R13")
	w("\tADDQ\tR13, 16(SP)")
	w("\tCMPL\t8(SP), $0")
	w("\tJNE\tgemmchunk")
	w("\tADDQ\tR9, SI")
	w("\tADDQ\tR15, BX")
	w("\tSUBL\t$1, R10")
	w("\tJNZ\tgemmy")
	w("\tJMP\tgemmdone")

	// ---- VNNI nest: chunked like the AVX2 nest, but the activation
	// prepass produces, per group PAIR and row, the 8 bytes
	// [quad_k, quad_k+1] xor 0x80 (u8), so one VPBROADCASTQ serves a
	// 256-bit VPDPBUSD against the pair of weight groups permuted to
	// [c0g0 c0g1 c1g0 c1g1 | c2g0 c2g1 c3g0 c3g1] (s8). The +128 bias
	// then sits on the ACTIVATION side and its correction is a weight
	// column sum shared by all four rows: one VPDPBUSD(ones, weights)
	// per pair, subtracted once per block in the pair domain before
	// the same collapse the AVX2 nest uses.
	//
	//	R12 bp | AX ap (scales) | R11 scratch cursor | Y6 wsum
	//	Y14 permute index | Y15 u8 ones
	w("vgemmy:")
	fmt.Fprintf(&b, "\tVMOVDQU ·%s(SB), Y14\n", permSym)
	fmt.Fprintf(&b, "\tVMOVDQU ·%s(SB), X15\n", onesSym)
	w("\tVINSERTI128\t$1, X15, Y15, Y15")
	w("vgemmyy:")
	w("\tMOVQ\t$0, 16(SP)")
	w("\tMOVL\tR8, 8(SP)")
	w("vgemmchunk:")
	w("\tMOVL\t8(SP), R13")
	w("\tMOVL\t$%d, AX", x64RepackGemmChunkBlocks)
	w("\tCMPL\tR13, AX")
	w("\tCMOVLGT\tAX, R13")
	w("\tMOVL\tR13, 32(SP)")
	// Prepass: per pair, rows 0/1 and 2/3 interleaved by dword.
	w("\tMOVQ\tSI, AX")
	w("\tADDQ\t16(SP), AX")
	w("\tLEAQ\t64(SP), R11")
	w("\tTESTL\tR13, R13")
	w("\tJZ\tvgemmxinit")
	w("vgemmpre:")
	for p := 0; p < 4; p++ {
		w("\tVMOVDQU\t%d(AX), X4", 8+32*p)
		w("\tVMOVDQU\t%d(AX), X5", 8+32*p+16)
		w("\tVPUNPCKLDQ\tX5, X4, X6")
		w("\tVPUNPCKHDQ\tX5, X4, X7")
		fmt.Fprintf(&b, "\tVPXOR ·%s(SB), X6, X6\n", biasSym)
		fmt.Fprintf(&b, "\tVPXOR ·%s(SB), X7, X7\n", biasSym)
		w("\tVMOVDQU\tX6, %d(R11)", 32*p)
		w("\tVMOVDQU\tX7, %d(R11)", 32*p+16)
	}
	w("\tADDQ\t$136, AX")
	w("\tADDQ\t$128, R11")
	w("\tDECL\tR13")
	w("\tJNZ\tvgemmpre")
	w("vgemmxinit:")
	w("\tMOVQ\tCX, DX")
	w("\tADDQ\t16(SP), DX")
	w("\tMOVQ\tBX, DI")
	w("\tMOVL\t24(SP), R13")
	w("vgemmx:")
	w("\tCMPQ\t16(SP), $0")
	w("\tJNE\tvgemmxload")
	w("\tVPXOR\tY8, Y8, Y8")
	w("\tVPXOR\tY9, Y9, Y9")
	w("\tJMP\tvgemmxgo")
	w("vgemmxload:")
	w("\tLEAQ\t(DI)(R14*2), R12")
	w("\tVMOVUPS\t(DI), X8")
	w("\tVINSERTF128\t$1, (R12), Y8, Y8")
	w("\tVMOVUPS\t(DI)(R14*1), X9")
	w("\tVINSERTF128\t$1, (R12)(R14*1), Y9, Y9")
	w("vgemmxgo:")
	w("\tMOVQ\tDX, R12")
	w("\tMOVQ\tSI, AX")
	w("\tADDQ\t16(SP), AX")
	w("\tMOVL\t32(SP), R11")
	w("\tMOVL\tR11, 0(SP)")
	w("\tLEAQ\t64(SP), R11")
	w("\tCMPL\t0(SP), $0")
	w("\tJZ\tvgemmstore")
	w("vgemmblk:")
	w("\tVPXOR\tY0, Y0, Y0")
	w("\tVPXOR\tY1, Y1, Y1")
	w("\tVPXOR\tY2, Y2, Y2")
	w("\tVPXOR\tY3, Y3, Y3")
	w("\tVPXOR\tY6, Y6, Y6")
	for p := 0; p < 4; p++ {
		w("\tVPERMD\t%d(R12), Y14, Y4", 8+32*p)
		w("\tVPDPBUSD\tY4, Y15, Y6") // wsum += column sums (u8 ones x s8 weights)
		for row := 0; row < 4; row++ {
			w("\tVPBROADCASTQ\t%d(R11), Y5", 32*p+8*row)
			w("\tVPDPBUSD\tY4, Y5, Y%d", row) // acc_row += u8 acts x s8 weights
		}
	}
	// acc_row -= 128 * wsum (pair domain), then the AVX2 collapse.
	w("\tVPSLLD\t$7, Y6, Y6")
	for row := 0; row < 4; row++ {
		w("\tVPSUBD\tY6, Y%d, Y%d", row, row)
	}
	w("\tVPHADDD\tY1, Y0, Y10")
	w("\tVPHADDD\tY3, Y2, Y11")
	w("\tVPERM2I128\t$0x20, Y11, Y10, Y4")
	w("\tVPERM2I128\t$0x31, Y11, Y10, Y5")
	w("\tVPUNPCKLQDQ\tY5, Y4, Y10")
	w("\tVPUNPCKHQDQ\tY5, Y4, Y11")
	w("\tVMOVQ\t(R12), X7")
	w("\tVCVTPH2PS\tX7, X12")
	w("\tVINSERTF128\t$1, X12, Y12, Y12")
	w("\tVMOVQ\t(AX), X7")
	w("\tVCVTPH2PS\tX7, X13")
	// Row scales per half without an index register: [d0 x4 | d2 x4]
	// and [d1 x4 | d3 x4] from lane shuffles.
	w("\tVPSHUFD\t$0x00, X13, X4")
	w("\tVPSHUFD\t$0xaa, X13, X7")
	w("\tVINSERTI128\t$1, X7, Y4, Y4")
	w("\tVMULPS\tY12, Y4, Y4")
	w("\tVPSHUFD\t$0x55, X13, X5")
	w("\tVPSHUFD\t$0xff, X13, X7")
	w("\tVINSERTI128\t$1, X7, Y5, Y5")
	w("\tVMULPS\tY12, Y5, Y5")
	w("\tVCVTDQ2PS\tY10, Y10")
	w("\tVMULPS\tY4, Y10, Y10")
	w("\tVADDPS\tY10, Y8, Y8")
	w("\tVCVTDQ2PS\tY11, Y11")
	w("\tVMULPS\tY5, Y11, Y11")
	w("\tVADDPS\tY11, Y9, Y9")
	w("\tADDQ\t$136, R12")
	w("\tADDQ\t$136, AX")
	w("\tADDQ\t$128, R11")
	w("\tDECL\t0(SP)")
	w("\tJNZ\tvgemmblk")
	w("vgemmstore:")
	w("\tLEAQ\t(DI)(R14*2), R12")
	w("\tVMOVUPS\tX8, (DI)")
	w("\tVMOVUPS\tX9, (DI)(R14*1)")
	w("\tVEXTRACTF128\t$1, Y8, X7")
	w("\tVMOVUPS\tX7, (R12)")
	w("\tVEXTRACTF128\t$1, Y9, X7")
	w("\tVMOVUPS\tX7, (R12)(R14*1)")
	w("\tADDQ\tR9, DX")
	w("\tADDQ\t$16, DI")
	w("\tSUBL\t$1, R13")
	w("\tJNZ\tvgemmx")
	w("\tMOVL\t32(SP), R13")
	w("\tSUBL\tR13, 8(SP)")
	w("\tIMUL3Q\t$136, R13, R13")
	w("\tADDQ\tR13, 16(SP)")
	w("\tCMPL\t8(SP), $0")
	w("\tJNE\tvgemmchunk")
	w("\tADDQ\tR9, SI")
	w("\tADDQ\tR15, BX")
	w("\tSUBL\t$1, R10")
	w("\tJNZ\tvgemmyy")
	w("gemmdone:")
	w("\tVZEROUPPER")
	w("\tRET")
	w("gemmoob:")
	w("\tVZEROUPPER")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return b.String()
}
