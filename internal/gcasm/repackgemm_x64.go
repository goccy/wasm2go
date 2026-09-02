package gcasm

import (
	"fmt"
	"strings"
)

// x64RepackGemmKernel emits the q8_0x4 repack GEMM under sym for
// amd64 — the 4x4 tile the a64 twin computes with by-element SDOT,
// with an entry branch to a VNNI loop on CPUs reporting AVX-512 VNNI
// at 256-bit width. See a64RepackGemmKernel for the tile shape, the
// bounds-check contract and the fast-math gating; the memory layouts
// and the ABI0 argument frame are identical.
//
// AVX2 nest, per 16-byte weight group: the group sign-extends ONCE
// across a ymm and each row's broadcast 4-byte activation group
// multiplies into that row's pair-domain ymm accumulator
// (VPMADDWD + VPADDD); the four accumulators collapse to per-column
// i32x4 sums once per block. VNNI nest: VPDPBUSD with the exact +128
// bias identity — the per-row byte sums the identity needs
// accumulate in ONE extra VPDPBUSD per group (ones · activation
// block = all four rows' group sums, one lane each).
//
// Register file after the prologue (memSize/M die once the entry
// checks pass and every pointer is host-absolute):
//
//	CX vx base | SI a-row cursor | BX s-row cursor | R8 nb
//	R9 xtotal | R10 y ctr | R11 nc4 | R14 bs bytes | R15 4*bs
//	DX b-col cursor | DI s-col cursor | R13 x ctr
//	R12 bp | AX ap | 0(SP) block ctr
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

	argOff := map[string]int{"l1": 12, "l2": 16, "l3": 20, "l4": 24, "l5": 28, "l6": 32}
	movArg, argBytes := "MOVL", 36
	if wide {
		argOff = map[string]int{"l1": 16, "l2": 24, "l3": 32, "l4": 40, "l5": 48, "l6": 52}
		movArg, argBytes = "MOVQ", 56
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
	w("TEXT ·%s(SB), $8-%d", sym, argBytes)
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
	fmt.Fprintf(&b, "\tVMOVDQU ·%s(SB), X14\n", onesSym)
	w("\tCMPB\t·gcasmHasAVX512VNNI(SB), $0")
	w("\tJNE\tvgemmy")

	// nest emits one complete y/x/block loop nest under the label
	// prefix; the AVX2 and VNNI bodies differ only in the per-block
	// integer tile.
	nest := func(p string, vnni bool) {
		w("%sy:", p)
		w("\tMOVQ\tCX, DX")
		w("\tMOVQ\tBX, DI")
		w("\tMOVQ\tR11, R13")
		w("%sx:", p)
		w("\tVPXOR\tX8, X8, X8")
		w("\tVPXOR\tX9, X9, X9")
		w("\tVPXOR\tX10, X10, X10")
		w("\tVPXOR\tX11, X11, X11")
		w("\tMOVQ\tDX, R12")
		w("\tMOVQ\tSI, AX")
		w("\tMOVL\tR8, 0(SP)")
		w("\tTESTL\tR8, R8")
		w("\tJZ\t%sstore", p)
		w("%sblk:", p)
		if vnni {
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
					w("\tVPSHUFD\t$%#02x, X5, X6", row*0x55)
					w("\tVPDPBUSD\tX6, X4, X%d", row)
				}
			}
			// acc_row -= 128 * rowsum[row].
			for row := 0; row < 4; row++ {
				w("\tVPSHUFD\t$%#02x, X7, X6", row*0x55)
				w("\tVPSLLD\t$7, X6, X6")
				w("\tVPSUBD\tX6, X%d, X%d", row, row)
			}
		} else {
			w("\tVPXOR\tY0, Y0, Y0")
			w("\tVPXOR\tY1, Y1, Y1")
			w("\tVPXOR\tY2, Y2, Y2")
			w("\tVPXOR\tY3, Y3, Y3")
			for k := 0; k < 8; k++ {
				w("\tVPMOVSXBW\t%d(R12), Y4", 8+16*k)
				w("\tVMOVDQU\t%d(AX), X5", 8+16*k)
				for row := 0; row < 4; row++ {
					w("\tVPSHUFD\t$%#02x, X5, X6", row*0x55)
					w("\tVPMOVSXBW\tX6, Y6")
					w("\tVPMADDWD\tY4, Y6, Y6")
					w("\tVPADDD\tY6, Y%d, Y%d", row, row)
				}
			}
			// Collapse pair-domain ymm to the per-column grouping.
			for row := 0; row < 4; row++ {
				w("\tVPHADDD\tY%d, Y%d, Y%d", row, row, row)
				w("\tVEXTRACTI128\t$1, Y%d, X6", row)
				w("\tVPUNPCKLQDQ\tX6, X%d, X%d", row, row)
			}
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
		w("\tJNZ\t%sblk", p)
		w("%sstore:", p)
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
		w("\tJNZ\t%sx", p)
		w("\tADDQ\tR9, SI")
		w("\tADDQ\tR15, BX")
		w("\tSUBL\t$1, R10")
		w("\tJNZ\t%sy", p)
		w("\tJMP\tgemmdone")
	}
	nest("gemm", false)
	nest("vgemm", true)
	w("gemmdone:")
	w("\tVZEROUPPER")
	w("\tRET")
	w("gemmoob:")
	w("\tVZEROUPPER")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return b.String()
}
