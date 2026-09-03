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
// VNNI nest: VPDPBUSD with the exact +128 bias identity — the per-row
// byte sums the identity needs accumulate in ONE extra VPDPBUSD per
// group (ones · activation block = all four rows' group sums, one
// lane each); each row's quad arrives by VPBROADCASTD straight from
// memory.
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

	// ---- VNNI nest.
	fmt.Fprintf(&b, "vgemmy:\n\tVMOVDQU ·%s(SB), X14\n", onesSym)
	w("\tMOVL\t24(SP), R11")
	w("vgemmyy:")
	w("\tMOVQ\tCX, DX")
	w("\tMOVQ\tBX, DI")
	w("\tMOVQ\tR11, R13")
	w("vgemmx:")
	w("\tVPXOR\tX8, X8, X8")
	w("\tVPXOR\tX9, X9, X9")
	w("\tVPXOR\tX10, X10, X10")
	w("\tVPXOR\tX11, X11, X11")
	w("\tMOVQ\tDX, R12")
	w("\tMOVQ\tSI, AX")
	w("\tMOVL\tR8, 0(SP)")
	w("\tTESTL\tR8, R8")
	w("\tJZ\tvgemmstore")
	w("vgemmblk:")
	w("\tVPXOR\tX0, X0, X0")
	w("\tVPXOR\tX1, X1, X1")
	w("\tVPXOR\tX2, X2, X2")
	w("\tVPXOR\tX3, X3, X3")
	w("\tVPXOR\tX7, X7, X7")
	for k := 0; k < 8; k++ {
		w("\tVMOVDQU\t%d(R12), X4", 8+16*k)
		fmt.Fprintf(&b, "\tVPXOR ·%s(SB), X4, X4\n", biasSym)
		w("\tVMOVDQU\t%d(AX), X5", 8+16*k)
		w("\tVPDPBUSD\tX5, X14, X7") // rowsum += group sums
		for row := 0; row < 4; row++ {
			w("\tVPBROADCASTD\t%d(AX), X6", 8+16*k+4*row)
			w("\tVPDPBUSD\tX6, X4, X%d", row)
		}
	}
	// acc_row -= 128 * rowsum[row].
	for row := 0; row < 4; row++ {
		w("\tVPSHUFD\t$%#02x, X7, X6", row*0x55)
		w("\tVPSLLD\t$7, X6, X6")
		w("\tVPSUBD\tX6, X%d, X%d", row, row)
	}
	// Scales: sumv_row += f32(acc_row) * (dcol * drow[row]).
	w("\tVMOVQ\t(R12), X6")
	w("\tVCVTPH2PS\tX6, X12")
	w("\tVMOVQ\t(AX), X6")
	w("\tVCVTPH2PS\tX6, X13")
	for row := 0; row < 4; row++ {
		w("\tVCVTDQ2PS\tX%d, X%d", row, row)
		w("\tVPSHUFD\t$%#02x, X13, X7", row*0x55)
		w("\tVMULPS\tX12, X7, X7")
		w("\tVMULPS\tX%d, X7, X7", row)
		w("\tVADDPS\tX7, X%d, X%d", 8+row, 8+row)
	}
	w("\tADDQ\t$136, R12")
	w("\tADDQ\t$136, AX")
	w("\tDECL\t0(SP)")
	w("\tJNZ\tvgemmblk")
	w("vgemmstore:")
	w("\tVMOVUPS\tX8, (DI)")
	w("\tLEAQ\t(DI)(R14*1), R12")
	w("\tVMOVUPS\tX9, (R12)")
	w("\tADDQ\tR14, R12")
	w("\tVMOVUPS\tX10, (R12)")
	w("\tADDQ\tR14, R12")
	w("\tVMOVUPS\tX11, (R12)")
	w("\tADDQ\tR9, DX")
	w("\tADDQ\t$16, DI")
	w("\tSUBL\t$1, R13")
	w("\tJNZ\tvgemmx")
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
