package gcasm

import (
	"fmt"
	"strings"
)

// x64VecDotF16Kernel emits *s = sum(x[i] * y[i]) over n f16 pairs under
// sym for amd64 (see a64VecDotF16Kernel): VCVTPH2PS widens eight halves
// at a time into four ymm accumulators (32 elements per step), then
// 16-, 8- and 4-wide tails and a scalar tail, then a tree reduce.
// Bounds: s + 4, x + 2n, y + 2n against memSize.
func x64VecDotF16Kernel(sym, trapSym string, offs *ModuleOffsets, _ *ConstPool, wide bool) string {
	var sb strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&sb, format+"\n", args...) }
	args, argBytes := vecDotF16Args(wide)
	movPtr := "MOVL"
	if wide {
		movPtr = "MOVQ"
	}
	w("// %s: f16 dot product, f32 accumulate.", sym)
	w("TEXT ·%s(SB), $16-%d", sym, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVQ\tm+0(FP), AX")
	w("\tMOVQ\t%d(AX), R11", offs.MemSize)
	w("\tMOVQ\t(R11), R11")
	w("\tMOVQ\t%d(AX), R10", offs.M)
	w("\tMOVLQSX\tl0+%d(FP), CX", args["l0"])
	w("\t%s\tl1+%d(FP), DI", movPtr, args["l1"])
	w("\t%s\tl3+%d(FP), SI", movPtr, args["l3"])
	w("\t%s\tl5+%d(FP), DX", movPtr, args["l5"])
	w("\tLEAQ\t4(DI), R8")
	w("\tCMPQ\tR11, R8")
	w("\tJCS\tvdoob")
	w("\tADDQ\tR10, DI")
	for _, r := range []string{"Y0", "Y1", "Y2", "Y3", "Y12", "Y13"} {
		w("\tVXORPS\t%s, %s, %s", r, r, r)
	}
	w("\tTESTQ\tCX, CX")
	w("\tJLE\tvdreduce")
	for _, reg := range []string{"SI", "DX"} {
		w("\tLEAQ\t(%s)(CX*2), R8", reg)
		w("\tCMPQ\tR11, R8")
		w("\tJCS\tvdoob")
	}
	w("\tADDQ\tR10, SI")
	w("\tADDQ\tR10, DX")
	// step: `cnt` ymm (8 elements each) per iteration into Y0..Y(cnt-1).
	step := func(lbl, next string, cnt int) {
		w("%s:", lbl)
		w("\tCMPQ\tCX, $%d", 8*cnt)
		w("\tJLT\t%s", next)
		for i := 0; i < cnt; i++ {
			w("\tVCVTPH2PS\t%d(SI), Y%d", 16*i, 4+i)
			w("\tVCVTPH2PS\t%d(DX), Y%d", 16*i, 8+i)
			w("\tVFMADD231PS\tY%d, Y%d, Y%d", 8+i, 4+i, i)
		}
		w("\tADDQ\t$%d, SI", 16*cnt)
		w("\tADDQ\t$%d, DX", 16*cnt)
		w("\tSUBQ\t$%d, CX", 8*cnt)
		w("\tJMP\t%s", lbl)
	}
	step("vdloop32", "vdloop16", 4)
	step("vdloop16", "vdloop8", 2)
	step("vdloop8", "vdtail4", 1)
	w("vdtail4:")
	w("\tCMPQ\tCX, $4")
	w("\tJLT\tvdtail1")
	w("\tVCVTPH2PS\t(SI), X4")
	w("\tVCVTPH2PS\t(DX), X8")
	w("\tVFMADD231PS\tX8, X4, X12")
	w("\tADDQ\t$8, SI")
	w("\tADDQ\t$8, DX")
	w("\tSUBQ\t$4, CX")
	w("\tJMP\tvdtail4")
	w("vdtail1:")
	w("\tTESTQ\tCX, CX")
	w("\tJZ\tvdreduce")
	w("\tMOVWLZX\t(SI), R8")
	w("\tVMOVD\tR8, X4")
	w("\tVCVTPH2PS\tX4, X4")
	w("\tMOVWLZX\t(DX), R8")
	w("\tVMOVD\tR8, X8")
	w("\tVCVTPH2PS\tX8, X8")
	w("\tVFMADD231SS\tX8, X4, X13")
	w("\tADDQ\t$2, SI")
	w("\tADDQ\t$2, DX")
	w("\tDECQ\tCX")
	w("\tJMP\tvdtail1")
	w("vdreduce:")
	w("\tVADDPS\tY1, Y0, Y0")
	w("\tVADDPS\tY3, Y2, Y2")
	w("\tVADDPS\tY2, Y0, Y0")
	w("\tVEXTRACTF128\t$1, Y0, X1")
	w("\tVADDPS\tX1, X0, X0")
	w("\tVADDPS\tX12, X0, X0")
	w("\tVHADDPS\tX0, X0, X0")
	w("\tVHADDPS\tX0, X0, X0")
	w("\tVADDSS\tX13, X0, X0")
	w("\tVMOVSS\tX0, (DI)")
	w("\tVZEROUPPER")
	w("\tRET")
	w("vdoob:")
	w("\tVZEROUPPER")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return sb.String()
}

// x64VecMadF16F32Kernel emits y[i] += v * x[i] (y f32, x f16) under sym
// for amd64: 32 elements per step, then 8-, 4-wide and scalar tails.
// Bounds: y + 4n, x + 2n against memSize.
func x64VecMadF16F32Kernel(sym, trapSym string, offs *ModuleOffsets, _ *ConstPool, wide bool) string {
	var sb strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&sb, format+"\n", args...) }
	args, argBytes := vecMadF16F32Args(wide)
	movPtr := "MOVL"
	if wide {
		movPtr = "MOVQ"
	}
	w("// %s: y += v * x (x f16, y f32).", sym)
	w("TEXT ·%s(SB), $16-%d", sym, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVLQSX\tl0+%d(FP), CX", args["l0"])
	w("\tTESTQ\tCX, CX")
	w("\tJLE\tvmdone")
	w("\tMOVQ\tm+0(FP), AX")
	w("\tMOVQ\t%d(AX), R11", offs.MemSize)
	w("\tMOVQ\t(R11), R11")
	w("\tMOVQ\t%d(AX), R10", offs.M)
	w("\t%s\tl1+%d(FP), DI", movPtr, args["l1"])
	w("\t%s\tl2+%d(FP), SI", movPtr, args["l2"])
	w("\tVBROADCASTSS\tl3+%d(FP), Y8", args["l3"])
	w("\tLEAQ\t(DI)(CX*4), R8")
	w("\tCMPQ\tR11, R8")
	w("\tJCS\tvmoob")
	w("\tLEAQ\t(SI)(CX*2), R8")
	w("\tCMPQ\tR11, R8")
	w("\tJCS\tvmoob")
	w("\tADDQ\tR10, DI")
	w("\tADDQ\tR10, SI")
	step := func(lbl, next string, cnt int) {
		w("%s:", lbl)
		w("\tCMPQ\tCX, $%d", 8*cnt)
		w("\tJLT\t%s", next)
		for i := 0; i < cnt; i++ {
			w("\tVCVTPH2PS\t%d(SI), Y%d", 16*i, 4+i)
			w("\tVMOVUPS\t%d(DI), Y%d", 32*i, 12+i)
			w("\tVFMADD231PS\tY8, Y%d, Y%d", 4+i, 12+i)
			w("\tVMOVUPS\tY%d, %d(DI)", 12+i, 32*i)
		}
		w("\tADDQ\t$%d, SI", 16*cnt)
		w("\tADDQ\t$%d, DI", 32*cnt)
		w("\tSUBQ\t$%d, CX", 8*cnt)
		w("\tJMP\t%s", lbl)
	}
	step("vmloop32", "vmloop8", 4)
	step("vmloop8", "vmtail4", 1)
	w("vmtail4:")
	w("\tCMPQ\tCX, $4")
	w("\tJLT\tvmtail1")
	w("\tVCVTPH2PS\t(SI), X4")
	w("\tVMOVUPS\t(DI), X12")
	w("\tVFMADD231PS\tX8, X4, X12")
	w("\tVMOVUPS\tX12, (DI)")
	w("\tADDQ\t$8, SI")
	w("\tADDQ\t$16, DI")
	w("\tSUBQ\t$4, CX")
	w("\tJMP\tvmtail4")
	w("vmtail1:")
	w("\tTESTQ\tCX, CX")
	w("\tJZ\tvmdone")
	w("\tMOVWLZX\t(SI), R8")
	w("\tVMOVD\tR8, X4")
	w("\tVCVTPH2PS\tX4, X4")
	w("\tVMOVSS\t(DI), X12")
	w("\tVFMADD231SS\tX8, X4, X12")
	w("\tVMOVSS\tX12, (DI)")
	w("\tADDQ\t$2, SI")
	w("\tADDQ\t$4, DI")
	w("\tDECQ\tCX")
	w("\tJMP\tvmtail1")
	w("vmdone:")
	w("\tVZEROUPPER")
	w("\tRET")
	w("vmoob:")
	w("\tVZEROUPPER")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return sb.String()
}
