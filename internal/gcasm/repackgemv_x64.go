package gcasm

import (
	"fmt"
	"strings"
)

// x64RepackGemvChunkBlocks / x64RepackGemvFrame size the GEMV's stack
// scratch: the activation row is prepared once per chunk of blocks
// (AVX2: the eight k-quads widened to i16, 64 bytes per block; VNNI:
// the four k-quad pairs each laid out as [quad 2j x4 | quad 2j+1 x4]
// for a 256-bit VPDPBUSD, plus 128 x the block's byte sum, 144 bytes
// per block).
const (
	x64RepackGemvChunkBlocks = 512
	x64RepackGemvFrame       = 64 + x64RepackGemvChunkBlocks*144
)

// x64RepackGemvKernel emits the q8_0x4 repack GEMV under sym for amd64
// (see a64RepackGemvKernel for the contract): one activation row
// against nc columns, four column groups per pass sharing the
// activation operands, leftover groups one at a time.
//
// AVX2 nest: per weight group VPMOVSXBW (16 i16 = 4 columns x 4 k),
// VPMADDWD against the row's widened k-quad broadcast (VPBROADCASTQ
// from the scratch) and VPADDD into the group's pair-domain ymm; per
// block the pair domain collapses (VPHADDD + lane fold) to the four
// column sums, converts, scales by dcol * da and accumulates.
//
// VNNI nest: 32 weight bytes at a time — two consecutive k-quads of
// the four columns — biased to u8 (xor 0x80) in register, against the
// prepared activation pair [quad 2j x4 | quad 2j+1 x4] (s8) straight
// from the scratch as the VPDPBUSD memory operand: two instructions per
// 32 bytes, two independent accumulators per column group (even and odd
// pairs), the halves folded per block. The +128 weight bias is undone
// with the block's activation byte sum, which the prepass stores once
// per block and every column group reuses. (The first version did
// 16 bytes per VPDPBUSD with a broadcast activation quad: half the work
// per instruction, and on Zen 4 decode sat at ~18 GB/s while native
// llama.cpp pulled 24.)
func x64RepackGemvKernel(sym, trapSym string, offs *ModuleOffsets, pool *ConstPool, wide bool) string {
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
		w("\tJCS\tgvoob")
	}

	// Register file after the prologue:
	//	CX vx (host, current pass) | SI vy (host) | BX s (host)
	//	R8 nb | R9 xtotal | R10 nc4 left
	//	0(SP) blocks left | 8(SP) chunk byte offset (weights/acts)
	//	16(SP) chunk blocks | 24(SP) groups left | 32(SP) 4th weight cursor
	//	64(SP).. scratch
	//	per pass: R13/R14/R15/DX weight cursors, AX act cursor,
	//	R11 scratch cursor, DI block counter
	w("// %s: q8_0x4 repack GEMV, four column groups per pass via AVX2 / VNNI.", sym)
	w("TEXT ·%s(SB), $%d-%d", sym, x64RepackGemvFrame, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVQ\tm+0(FP), AX")
	w("\tMOVQ\t%d(AX), R15", offs.MemSize)
	w("\tMOVQ\t(R15), R15")
	w("\tMOVQ\t%d(AX), R14", offs.M)
	w("\tMOVL\tl0+8(FP), R8")
	w("\tSHRL\t$5, R8")
	w("\tIMUL3Q\t$136, R8, R9")
	arg("l6", "R10")
	w("\tSHRL\t$2, R10")
	w("\tTESTL\tR10, R10")
	w("\tJZ\tgvdone")
	arg("l3", "CX")
	w("\tMOVQ\tR10, R12")
	w("\tIMULQ\tR9, R12")
	w("\tADDQ\tCX, R12")
	memCheck()
	arg("l4", "SI")
	w("\tIMUL3Q\t$34, R8, R12")
	w("\tADDQ\tSI, R12")
	memCheck()
	arg("l1", "BX")
	w("\tMOVQ\tR10, R12")
	w("\tSHLQ\t$4, R12")
	w("\tADDQ\tBX, R12")
	memCheck()
	w("\tADDQ\tR14, CX")
	w("\tADDQ\tR14, SI")
	w("\tADDQ\tR14, BX")
	w("\tCMPB\t·gcasmHasAVX512VNNI(SB), $0")
	w("\tJNE\tvgvy")

	// chunkHead emits the chunk bookkeeping shared by both nests:
	// blocks left, chunk size, and the prepass over the activation
	// chunk (perBlock emits one block's prepass at AX -> R11).
	chunkLoop := func(p string, perBlock func(), blockBytes int, pass func(p string)) {
		w("\tMOVQ\t$0, 8(SP)")
		w("\tMOVL\tR8, 0(SP)")
		w("%schunk:", p)
		w("\tMOVL\t0(SP), R13")
		w("\tMOVL\t$%d, AX", x64RepackGemvChunkBlocks)
		w("\tCMPL\tR13, AX")
		w("\tCMOVLGT\tAX, R13")
		w("\tMOVL\tR13, 16(SP)")
		w("\tMOVQ\t8(SP), AX")
		w("\tIMUL3Q\t$34, AX, AX")
		w("\tADDQ\tSI, AX")
		w("\tLEAQ\t64(SP), R11")
		w("\tTESTL\tR13, R13")
		w("\tJZ\t%spassinit", p)
		w("%spre:", p)
		perBlock()
		w("\tADDQ\t$34, AX")
		w("\tADDQ\t$%d, R11", blockBytes)
		w("\tDECL\tR13")
		w("\tJNZ\t%spre", p)
		w("%spassinit:", p)
		pass(p)
		// Next chunk: advance the chunk byte offsets (acts 34/block,
		// weights 136/block are tracked from the same block count).
		w("\tMOVL\t16(SP), R13")
		w("\tSUBL\tR13, 0(SP)")
		w("\tADDQ\tR13, 8(SP)")
		w("\tCMPL\t0(SP), $0")
		w("\tJNE\t%schunk", p)
		w("\tJMP\tgvdone")
	}

	// ---- AVX2 nest.
	avx2Pass := func(p string) {
		// Column groups: R10 counts; CX advances by xtotal per group.
		// The pass loops over ALL column groups for this chunk, adding
		// into s (zeroed on the first chunk).
		w("\tMOVQ\tCX, DX") // group cursor (weights base of group 0)
		w("\tMOVQ\tBX, DI") // s cursor
		w("\tMOVL\tR10, R12")
		w("\tMOVL\tR12, 24(SP)") // groups left
		w("%sg4:", p)
		w("\tCMPL\t24(SP), $4")
		w("\tJLT\t%sg1", p)
		// f32 accumulators Y8..Y11: zero on chunk 0, else reload.
		w("\tCMPQ\t8(SP), $0")
		w("\tJNE\t%sg4load", p)
		for g := 0; g < 4; g++ {
			w("\tVPXOR\tX%d, X%d, X%d", 8+g, 8+g, 8+g)
		}
		w("\tJMP\t%sg4go", p)
		w("%sg4load:", p)
		for g := 0; g < 4; g++ {
			w("\tVMOVUPS\t%d(DI), X%d", 16*g, 8+g)
		}
		w("%sg4go:", p)
		// weight cursors at the chunk offset (blocks * 136)
		w("\tMOVQ\t8(SP), R12")
		w("\tIMUL3Q\t$136, R12, R12")
		w("\tLEAQ\t(DX)(R12*1), R13")
		w("\tLEAQ\t(R13)(R9*1), R14")
		w("\tLEAQ\t(R14)(R9*1), R15")
		w("\tLEAQ\t(R15)(R9*1), AX")
		w("\tMOVQ\tAX, 32(SP)") // 4th weight cursor lives in memory (AX is the act cursor)
		w("\tMOVQ\tSI, AX")
		w("\tMOVQ\t8(SP), R12")
		w("\tIMUL3Q\t$34, R12, R12")
		w("\tADDQ\tR12, AX")
		w("\tLEAQ\t64(SP), R11")
		w("\tMOVL\t16(SP), R12")
		w("\tTESTL\tR12, R12")
		w("\tJZ\t%sg4store", p)
		w("%sg4blk:", p)
		for g := 0; g < 4; g++ {
			w("\tVPXOR\tY%d, Y%d, Y%d", g, g, g)
		}
		w("\tMOVQ\t32(SP), DI") // 4th cursor
		for k := 0; k < 8; k++ {
			w("\tVPBROADCASTQ\t%d(R11), Y5", 8*k)
			for g, cur := range []string{"R13", "R14", "R15", "DI"} {
				w("\tVPMOVSXBW\t%d(%s), Y4", 8+16*k, cur)
				w("\tVPMADDWD\tY4, Y5, Y4")
				w("\tVPADDD\tY4, Y%d, Y%d", g, g)
			}
		}
		// da: f16 at (AX) -> broadcast f32 in Y6 (low lane used).
		w("\tVMOVD\t(AX), X6")
		w("\tVCVTPH2PS\tX6, X6")
		w("\tVPSHUFD\t$0x00, X6, X6")
		for g, cur := range []string{"R13", "R14", "R15", "DI"} {
			// collapse pair domain -> 4 column sums in X(g)
			w("\tVPHADDD\tY%d, Y%d, Y%d", g, g, g)
			w("\tVEXTRACTI128\t$1, Y%d, X4", g)
			w("\tVPUNPCKLQDQ\tX4, X%d, X%d", g, g)
			w("\tVCVTDQ2PS\tX%d, X%d", g, g)
			w("\tVMOVQ\t(%s), X7", cur)
			w("\tVCVTPH2PS\tX7, X7")
			w("\tVMULPS\tX6, X7, X7")
			w("\tVMULPS\tX7, X%d, X%d", g, g)
			w("\tVADDPS\tX%d, X%d, X%d", g, 8+g, 8+g)
		}
		w("\tADDQ\t$136, DI")
		w("\tMOVQ\tDI, 32(SP)")
		w("\tADDQ\t$136, R13")
		w("\tADDQ\t$136, R14")
		w("\tADDQ\t$136, R15")
		w("\tADDQ\t$34, AX")
		w("\tADDQ\t$64, R11")
		w("\tDECL\tR12")
		w("\tJNZ\t%sg4blk", p)
		w("%sg4store:", p)
		w("\tMOVQ\tBX, DI")
		w("\tMOVL\tR10, R12")
		w("\tSUBL\t24(SP), R12") // groups done
		w("\tSHLL\t$4, R12")
		w("\tADDQ\tR12, DI")
		for g := 0; g < 4; g++ {
			w("\tVMOVUPS\tX%d, %d(DI)", 8+g, 16*g)
		}
		w("\tLEAQ\t(DX)(R9*4), DX")
		w("\tSUBL\t$4, 24(SP)")
		w("\tJMP\t%sg4", p)
		// ---- leftover groups
		w("%sg1:", p)
		w("\tCMPL\t24(SP), $0")
		w("\tJEQ\t%spassend", p)
		w("\tMOVQ\tBX, DI")
		w("\tMOVL\tR10, R12")
		w("\tSUBL\t24(SP), R12")
		w("\tSHLL\t$4, R12")
		w("\tADDQ\tR12, DI")
		w("\tCMPQ\t8(SP), $0")
		w("\tJNE\t%sg1load", p)
		w("\tVPXOR\tX8, X8, X8")
		w("\tJMP\t%sg1go", p)
		w("%sg1load:", p)
		w("\tVMOVUPS\t(DI), X8")
		w("%sg1go:", p)
		w("\tMOVQ\t8(SP), R12")
		w("\tIMUL3Q\t$136, R12, R12")
		w("\tLEAQ\t(DX)(R12*1), R13")
		w("\tMOVQ\tSI, AX")
		w("\tMOVQ\t8(SP), R12")
		w("\tIMUL3Q\t$34, R12, R12")
		w("\tADDQ\tR12, AX")
		w("\tLEAQ\t64(SP), R11")
		w("\tMOVL\t16(SP), R12")
		w("\tTESTL\tR12, R12")
		w("\tJZ\t%sg1store", p)
		w("%sg1blk:", p)
		w("\tVPXOR\tY0, Y0, Y0")
		for k := 0; k < 8; k++ {
			w("\tVPBROADCASTQ\t%d(R11), Y5", 8*k)
			w("\tVPMOVSXBW\t%d(R13), Y4", 8+16*k)
			w("\tVPMADDWD\tY4, Y5, Y4")
			w("\tVPADDD\tY4, Y0, Y0")
		}
		w("\tVMOVD\t(AX), X6")
		w("\tVCVTPH2PS\tX6, X6")
		w("\tVPSHUFD\t$0x00, X6, X6")
		w("\tVPHADDD\tY0, Y0, Y0")
		w("\tVEXTRACTI128\t$1, Y0, X4")
		w("\tVPUNPCKLQDQ\tX4, X0, X0")
		w("\tVCVTDQ2PS\tX0, X0")
		w("\tVMOVQ\t(R13), X7")
		w("\tVCVTPH2PS\tX7, X7")
		w("\tVMULPS\tX6, X7, X7")
		w("\tVMULPS\tX7, X0, X0")
		w("\tVADDPS\tX0, X8, X8")
		w("\tADDQ\t$136, R13")
		w("\tADDQ\t$34, AX")
		w("\tADDQ\t$64, R11")
		w("\tDECL\tR12")
		w("\tJNZ\t%sg1blk", p)
		w("%sg1store:", p)
		w("\tVMOVUPS\tX8, (DI)")
		w("\tADDQ\tR9, DX")
		w("\tSUBL\t$1, 24(SP)")
		w("\tJMP\t%sg1", p)
		w("%spassend:", p)
	}
	avx2Pre := func() {
		// quads 0..3 and 4..7 -> i16, 32 bytes each
		w("\tVPMOVSXBW\t2(AX), Y4")
		w("\tVMOVDQU\tY4, (R11)")
		w("\tVPMOVSXBW\t18(AX), Y4")
		w("\tVMOVDQU\tY4, 32(R11)")
	}
	chunkLoop("gv", avx2Pre, 64, avx2Pass)

	// ---- VNNI nest: scratch per block = 32 bytes of u8 quads (xor
	// 0x80) followed by the block's byte sum as i32 x4 (16 bytes).
	vnniPre := func() {
		w("\tVMOVDQU\t2(AX), X4")
		w("\tVMOVDQU\t18(AX), X5")
		// byte sum (s8): VPDPBUSD(ones u8, quads s8) -> 4 lanes, then fold
		w("\tVPXOR\tX6, X6, X6")
		w("\tVPDPBUSD\tX4, X15, X6")
		w("\tVPDPBUSD\tX5, X15, X6")
		w("\tVPHADDD\tX6, X6, X6")
		w("\tVPHADDD\tX6, X6, X6")
		w("\tVPSLLD\t$7, X6, X6") // 128 * sum, replicated
		w("\tVMOVDQU\tX6, 128(R11)")
		// pairs: [quad 2j x4 | quad 2j+1 x4] at 32j(R11)
		for j := 0; j < 4; j++ {
			src := 4 + j/2
			lo, hi := 0x00, 0x55
			if j%2 == 1 {
				lo, hi = 0xAA, 0xFF
			}
			w("\tVPSHUFD\t$0x%02x, X%d, X6", lo, src)
			w("\tVPSHUFD\t$0x%02x, X%d, X7", hi, src)
			w("\tVINSERTI128\t$1, X7, Y6, Y6")
			w("\tVMOVDQU\tY6, %d(R11)", 32*j)
		}
	}
	// vnniBlock emits one block of the VNNI nest for the given weight
	// cursors: acc[g] (even pairs) / accB[g] (odd pairs) accumulate the
	// four column sums of group g in both 128-bit halves; the tail folds
	// them, removes the bias, scales and adds into X(8+g).
	vnniAccB := []int{5, 7, 12, 14}
	vnniBlock := func(curs []string) {
		for g := range curs {
			w("\tVPXOR\tY%d, Y%d, Y%d", g, g, g)
			w("\tVPXOR\tY%d, Y%d, Y%d", vnniAccB[g], vnniAccB[g], vnniAccB[g])
		}
		for j := 0; j < 4; j++ {
			for g, cur := range curs {
				acc := g
				if j%2 == 1 {
					acc = vnniAccB[g]
				}
				w("\tVPXOR\t%d(%s), Y13, Y4", 8+32*j, cur)
				w("\tVPDPBUSD\t%d(R11), Y4, Y%d", 32*j, acc) // acc += u8(w+128) . s8(a)
			}
		}
		w("\tVMOVD\t(AX), X6")
		w("\tVCVTPH2PS\tX6, X6")
		w("\tVPSHUFD\t$0x00, X6, X6")
		for g, cur := range curs {
			w("\tVPADDD\tY%d, Y%d, Y%d", vnniAccB[g], g, g)
			w("\tVEXTRACTI128\t$1, Y%d, X4", g)
			w("\tVPADDD\tX4, X%d, X%d", g, g)
			w("\tVPSUBD\t128(R11), X%d, X%d", g, g) // - 128 * sum(a)
			w("\tVCVTDQ2PS\tX%d, X%d", g, g)
			w("\tVMOVQ\t(%s), X7", cur)
			w("\tVCVTPH2PS\tX7, X7")
			w("\tVMULPS\tX6, X7, X7")
			w("\tVMULPS\tX7, X%d, X%d", g, g)
			w("\tVADDPS\tX%d, X%d, X%d", g, 8+g, 8+g)
		}
	}
	vnniPass := func(p string) {
		w("\tMOVQ\tCX, DX")
		w("\tMOVL\tR10, R12")
		w("\tMOVL\tR12, 24(SP)")
		w("%sg4:", p)
		w("\tCMPL\t24(SP), $4")
		w("\tJLT\t%sg1", p)
		w("\tMOVQ\tBX, DI")
		w("\tMOVL\tR10, R12")
		w("\tSUBL\t24(SP), R12")
		w("\tSHLL\t$4, R12")
		w("\tADDQ\tR12, DI")
		w("\tCMPQ\t8(SP), $0")
		w("\tJNE\t%sg4load", p)
		for g := 0; g < 4; g++ {
			w("\tVPXOR\tX%d, X%d, X%d", 8+g, 8+g, 8+g)
		}
		w("\tJMP\t%sg4go", p)
		w("%sg4load:", p)
		for g := 0; g < 4; g++ {
			w("\tVMOVUPS\t%d(DI), X%d", 16*g, 8+g)
		}
		w("%sg4go:", p)
		w("\tMOVQ\t8(SP), R12")
		w("\tIMUL3Q\t$136, R12, R12")
		w("\tLEAQ\t(DX)(R12*1), R13")
		w("\tLEAQ\t(R13)(R9*1), R14")
		w("\tLEAQ\t(R14)(R9*1), R15")
		w("\tLEAQ\t(R15)(R9*1), AX")
		w("\tMOVQ\tAX, 32(SP)")
		w("\tMOVQ\tSI, AX")
		w("\tMOVQ\t8(SP), R12")
		w("\tIMUL3Q\t$34, R12, R12")
		w("\tADDQ\tR12, AX")
		w("\tLEAQ\t64(SP), R11")
		w("\tMOVL\t16(SP), R12")
		w("\tTESTL\tR12, R12")
		w("\tJZ\t%sg4store", p)
		w("%sg4blk:", p)
		w("\tMOVQ\t32(SP), DI")
		vnniBlock([]string{"R13", "R14", "R15", "DI"})
		w("\tADDQ\t$136, DI")
		w("\tMOVQ\tDI, 32(SP)")
		w("\tADDQ\t$136, R13")
		w("\tADDQ\t$136, R14")
		w("\tADDQ\t$136, R15")
		w("\tADDQ\t$34, AX")
		w("\tADDQ\t$144, R11")
		w("\tDECL\tR12")
		w("\tJNZ\t%sg4blk", p)
		w("%sg4store:", p)
		w("\tMOVQ\tBX, DI")
		w("\tMOVL\tR10, R12")
		w("\tSUBL\t24(SP), R12")
		w("\tSHLL\t$4, R12")
		w("\tADDQ\tR12, DI")
		for g := 0; g < 4; g++ {
			w("\tVMOVUPS\tX%d, %d(DI)", 8+g, 16*g)
		}
		w("\tLEAQ\t(DX)(R9*4), DX")
		w("\tSUBL\t$4, 24(SP)")
		w("\tJMP\t%sg4", p)
		w("%sg1:", p)
		w("\tCMPL\t24(SP), $0")
		w("\tJEQ\t%spassend", p)
		w("\tMOVQ\tBX, DI")
		w("\tMOVL\tR10, R12")
		w("\tSUBL\t24(SP), R12")
		w("\tSHLL\t$4, R12")
		w("\tADDQ\tR12, DI")
		w("\tCMPQ\t8(SP), $0")
		w("\tJNE\t%sg1load", p)
		w("\tVPXOR\tX8, X8, X8")
		w("\tJMP\t%sg1go", p)
		w("%sg1load:", p)
		w("\tVMOVUPS\t(DI), X8")
		w("%sg1go:", p)
		w("\tMOVQ\t8(SP), R12")
		w("\tIMUL3Q\t$136, R12, R12")
		w("\tLEAQ\t(DX)(R12*1), R13")
		w("\tMOVQ\tSI, AX")
		w("\tMOVQ\t8(SP), R12")
		w("\tIMUL3Q\t$34, R12, R12")
		w("\tADDQ\tR12, AX")
		w("\tLEAQ\t64(SP), R11")
		w("\tMOVL\t16(SP), R12")
		w("\tTESTL\tR12, R12")
		w("\tJZ\t%sg1store", p)
		w("%sg1blk:", p)
		vnniBlock([]string{"R13"})
		w("\tADDQ\t$136, R13")
		w("\tADDQ\t$34, AX")
		w("\tADDQ\t$144, R11")
		w("\tDECL\tR12")
		w("\tJNZ\t%sg1blk", p)
		w("%sg1store:", p)
		w("\tVMOVUPS\tX8, (DI)")
		w("\tADDQ\tR9, DX")
		w("\tSUBL\t$1, 24(SP)")
		w("\tJMP\t%sg1", p)
		w("%spassend:", p)
	}
	fmt.Fprintf(&b, "vgvy:\n\tVMOVDQU ·%s(SB), X15\n\tVBROADCASTI128 ·%s(SB), Y13\n", onesSym, biasSym)
	chunkLoop("vgv", vnniPre, 144, vnniPass)

	w("gvdone:")
	w("\tVZEROUPPER")
	w("\tRET")
	w("gvoob:")
	w("\tVZEROUPPER")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return b.String()
}
