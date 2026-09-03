package gcasm

import (
	"fmt"
	"strings"
)

// x64SimdGemmF32Kernel emits C[M x N] += A[M x K] * B[K x N] (row-major
// f32, unit inner strides) under sym for amd64 — the AVX2 twin of
// a64SimdGemmF32Kernel (see there for the contract).
//
// Tiles: 4 rows x 16 columns (eight ymm accumulators, two B ymm per k
// shared by the rows, one VBROADCASTSS per row) for the bulk; 4 x 8
// (ymm), 4 x 4 (xmm) and 4 x 1 for the column tail; the same shapes
// one row at a time for the row tail. acc = acc + (b * a) in k order,
// no FMA, so the result matches the transformed body bit for bit.
//
// Register file after the prologue: CX C row base, SI A row base,
// BX B base (host pointers); R10 rows left, R9 K, R8 N*4 (B/C row
// stride), 8(SP) K*4 (A row stride); 0(SP) cols left, DI C column
// cursor, DX B column cursor; R13/R14/R15/AX A row cursors, R12 B k
// cursor, R11 k counter.
func x64SimdGemmF32Kernel(sym, trapSym string, offs *ModuleOffsets, wide bool) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	argOff, argBytes := simdGemmF32Args(wide)
	movPtr := "MOVL"
	if wide {
		movPtr = "MOVQ"
	}

	w("// %s: f32 GEMM C += A*B, 4x16 / 4x8 / 4x4 / 4x1 tiles (row tail 1xN).", sym)
	w("TEXT ·%s(SB), $16-%d", sym, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVQ\tm+0(FP), AX")
	w("\tMOVQ\t%d(AX), R15", offs.MemSize)
	w("\tMOVQ\t(R15), R15")
	w("\tMOVQ\t%d(AX), R14", offs.M)
	w("\tMOVLQSX\tl3+%d(FP), R10", argOff["l3"])
	w("\tMOVLQSX\tl4+%d(FP), R9", argOff["l4"])
	w("\tMOVLQSX\tl5+%d(FP), R8", argOff["l5"])
	w("\tTESTQ\tR10, R10")
	w("\tJLE\tsgdone")
	w("\tTESTQ\tR9, R9")
	w("\tJLE\tsgdone")
	w("\tTESTQ\tR8, R8")
	w("\tJLE\tsgdone")
	w("\t%s\tl0+%d(FP), CX", movPtr, argOff["l0"])
	w("\t%s\tl1+%d(FP), SI", movPtr, argOff["l1"])
	w("\t%s\tl2+%d(FP), BX", movPtr, argOff["l2"])
	// Spans: A M*K*4, B K*N*4, C M*N*4.
	w("\tMOVQ\tR10, R12")
	w("\tIMULQ\tR9, R12")
	w("\tSHLQ\t$2, R12")
	w("\tADDQ\tSI, R12")
	w("\tCMPQ\tR15, R12")
	w("\tJCS\tsgoob")
	w("\tMOVQ\tR9, R12")
	w("\tIMULQ\tR8, R12")
	w("\tSHLQ\t$2, R12")
	w("\tADDQ\tBX, R12")
	w("\tCMPQ\tR15, R12")
	w("\tJCS\tsgoob")
	w("\tMOVQ\tR10, R12")
	w("\tIMULQ\tR8, R12")
	w("\tSHLQ\t$2, R12")
	w("\tADDQ\tCX, R12")
	w("\tCMPQ\tR15, R12")
	w("\tJCS\tsgoob")
	w("\tADDQ\tR14, CX")
	w("\tADDQ\tR14, SI")
	w("\tADDQ\tR14, BX")
	w("\tSHLQ\t$2, R8") // N*4
	w("\tMOVQ\tR9, R12")
	w("\tSHLQ\t$2, R12")
	w("\tMOVQ\tR12, 8(SP)") // K*4

	// A row cursors for a 4-row tile: R13 row0, R14 row1, R15 row2, AX row3.
	aRows4 := func() {
		w("\tMOVQ\tSI, R13")
		w("\tMOVQ\tSI, R14")
		w("\tADDQ\t8(SP), R14")
		w("\tMOVQ\tR14, R15")
		w("\tADDQ\t8(SP), R15")
		w("\tMOVQ\tR15, AX")
		w("\tADDQ\t8(SP), AX")
	}
	aRegs := []string{"R13", "R14", "R15", "AX"}
	// kloop emits the k loop: rows (4 or 1) x vectors described by
	// width ("Y" 8 floats or "X" 4 floats) and count nv; accumulator
	// register for (row r, vector c) is r*nv+c.
	kloop := func(p string, rows int, width string, nv int) {
		if rows == 4 {
			aRows4()
		} else {
			w("\tMOVQ\tSI, R13")
		}
		w("\tMOVQ\tDX, R12")
		w("\tMOVQ\tR9, R11")
		w("%sk:", p)
		bReg := rows * nv // B vectors follow the accumulators
		bc := bReg + nv   // broadcast
		tmp := bc + 1     // product
		vsz := 32
		if width == "X" {
			vsz = 16
		}
		for c := 0; c < nv; c++ {
			w("\tVMOVUPS\t%d(R12), %s%d", vsz*c, width, bReg+c)
		}
		for r := 0; r < rows; r++ {
			w("\tVBROADCASTSS\t(%s), %s%d", aRegs[r], width, bc)
			w("\tADDQ\t$4, %s", aRegs[r])
			for c := 0; c < nv; c++ {
				w("\tVMULPS\t%s%d, %s%d, %s%d", width, bReg+c, width, bc, width, tmp)
				w("\tVADDPS\t%s%d, %s%d, %s%d", width, tmp, width, r*nv+c, width, r*nv+c)
			}
		}
		w("\tADDQ\tR8, R12")
		w("\tDECQ\tR11")
		w("\tJNZ\t%sk", p)
	}
	kscalar := func(p string, rows int) {
		if rows == 4 {
			aRows4()
		} else {
			w("\tMOVQ\tSI, R13")
		}
		w("\tMOVQ\tDX, R12")
		w("\tMOVQ\tR9, R11")
		w("%sk:", p)
		w("\tVMOVSS\t(R12), X8")
		for r := 0; r < rows; r++ {
			w("\tVMOVSS\t(%s), X9", aRegs[r])
			w("\tADDQ\t$4, %s", aRegs[r])
			w("\tVMULSS\tX8, X9, X9")
			w("\tVADDSS\tX9, X%d, X%d", r, r)
		}
		w("\tADDQ\tR8, R12")
		w("\tDECQ\tR11")
		w("\tJNZ\t%sk", p)
	}
	// C row pointers for a 4-row tile: DI row0, R12 row1 .. computed
	// on the fly from R8 (used only around loads/stores, where R12 is
	// free).
	cRow := func(r int) string {
		switch r {
		case 0:
			return "(DI)"
		case 1:
			return "(DI)(R8*1)"
		case 2:
			return "(DI)(R8*2)"
		}
		return "(R12)"
	}
	cRow3Setup := func() {
		w("\tLEAQ\t(DI)(R8*2), R12")
		w("\tADDQ\tR8, R12")
	}
	loadTile := func(rows int, width string, nv int) {
		vsz := 32
		if width == "X" {
			vsz = 16
		}
		if rows == 4 {
			cRow3Setup()
		}
		for r := 0; r < rows; r++ {
			for c := 0; c < nv; c++ {
				if vsz*c == 0 {
					w("\tVMOVUPS\t%s, %s%d", cRow(r), width, r*nv+c)
				} else {
					w("\tVMOVUPS\t%d%s, %s%d", vsz*c, cRow(r), width, r*nv+c)
				}
			}
		}
	}
	storeTile := func(rows int, width string, nv int) {
		vsz := 32
		if width == "X" {
			vsz = 16
		}
		if rows == 4 {
			cRow3Setup()
		}
		for r := 0; r < rows; r++ {
			for c := 0; c < nv; c++ {
				if vsz*c == 0 {
					w("\tVMOVUPS\t%s%d, %s", width, r*nv+c, cRow(r))
				} else {
					w("\tVMOVUPS\t%s%d, %d%s", width, r*nv+c, vsz*c, cRow(r))
				}
			}
		}
	}
	colBlock := func(p string, rows, cols int, width string, nv int, next string) {
		w("%s:", p)
		w("\tCMPQ\t0(SP), $%d", cols)
		w("\tJLT\t%s", next)
		loadTile(rows, width, nv)
		kloop(p, rows, width, nv)
		storeTile(rows, width, nv)
		w("\tADDQ\t$%d, DI", 4*cols)
		w("\tADDQ\t$%d, DX", 4*cols)
		w("\tSUBQ\t$%d, 0(SP)", cols)
		w("\tJMP\t%s", p)
	}
	scalarBlock := func(p string, rows int, next string) {
		w("%s:", p)
		w("\tCMPQ\t0(SP), $0")
		w("\tJEQ\t%s", next)
		if rows == 4 {
			cRow3Setup()
		}
		for r := 0; r < rows; r++ {
			w("\tVMOVSS\t%s, X%d", cRow(r), r)
		}
		kscalar(p, rows)
		if rows == 4 {
			cRow3Setup()
		}
		for r := 0; r < rows; r++ {
			w("\tVMOVSS\tX%d, %s", r, cRow(r))
		}
		w("\tADDQ\t$4, DI")
		w("\tADDQ\t$4, DX")
		w("\tSUBQ\t$1, 0(SP)")
		w("\tJMP\t%s", p)
	}

	// ---- 4-row blocks.
	w("sgrows4:")
	w("\tCMPQ\tR10, $4")
	w("\tJLT\tsgrows1")
	w("\tMOVQ\tR8, 0(SP)")
	w("\tSHRQ\t$2, 0(SP)") // cols left = N
	w("\tMOVQ\tCX, DI")
	w("\tMOVQ\tBX, DX")
	colBlock("sg4c16", 4, 16, "Y", 2, "sg4c8")
	colBlock("sg4c8", 4, 8, "Y", 1, "sg4c4")
	colBlock("sg4c4", 4, 4, "X", 1, "sg4c1")
	scalarBlock("sg4c1", 4, "sg4next")
	w("sg4next:")
	w("\tLEAQ\t(CX)(R8*4), CX")
	w("\tMOVQ\t8(SP), R12")
	w("\tLEAQ\t(SI)(R12*4), SI")
	w("\tSUBQ\t$4, R10")
	w("\tJMP\tsgrows4")

	// ---- row tail, one row at a time.
	w("sgrows1:")
	w("\tTESTQ\tR10, R10")
	w("\tJZ\tsgdone")
	w("\tMOVQ\tR8, 0(SP)")
	w("\tSHRQ\t$2, 0(SP)")
	w("\tMOVQ\tCX, DI")
	w("\tMOVQ\tBX, DX")
	colBlock("sg1c16", 1, 16, "Y", 2, "sg1c8")
	colBlock("sg1c8", 1, 8, "Y", 1, "sg1c4")
	colBlock("sg1c4", 1, 4, "X", 1, "sg1c1")
	scalarBlock("sg1c1", 1, "sg1next")
	w("sg1next:")
	w("\tADDQ\tR8, CX")
	w("\tADDQ\t8(SP), SI")
	w("\tSUBQ\t$1, R10")
	w("\tJMP\tsgrows1")
	w("sgdone:")
	w("\tVZEROUPPER")
	w("\tRET")
	w("sgoob:")
	w("\tVZEROUPPER")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return b.String()
}
