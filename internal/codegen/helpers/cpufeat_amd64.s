//go:build amd64

#include "textflag.h"

// func cpuidAMD64(eax, ecx uint32) (a, b, c, d uint32)
TEXT ·cpuidAMD64(SB), NOSPLIT, $0-24
	MOVL eax+0(FP), AX
	MOVL ecx+4(FP), CX
	CPUID
	MOVL AX, a+8(FP)
	MOVL BX, b+12(FP)
	MOVL CX, c+16(FP)
	MOVL DX, d+20(FP)
	RET

// func xgetbvAMD64() (lo, hi uint32)
TEXT ·xgetbvAMD64(SB), NOSPLIT, $0-8
	MOVL $0, CX
	XGETBV
	MOVL AX, lo+0(FP)
	MOVL DX, hi+4(FP)
	RET
