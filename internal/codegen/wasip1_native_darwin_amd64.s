// The trampolines through which wasip1_native_darwin.go calls the C
// library's functions, as the syscall package calls them.

#include "textflag.h"

TEXT hostLibcPthreadSelfTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_pthread_self(SB)
GLOBL	·hostLibcPthreadSelf(SB), RODATA, $8
DATA	·hostLibcPthreadSelf(SB)/8, $hostLibcPthreadSelfTrampoline<>(SB)

TEXT hostLibcPthreadKillTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_pthread_kill(SB)
GLOBL	·hostLibcPthreadKill(SB), RODATA, $8
DATA	·hostLibcPthreadKill(SB)/8, $hostLibcPthreadKillTrampoline<>(SB)

TEXT hostLibcSigactionTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_sigaction(SB)
GLOBL	·hostLibcSigaction(SB), RODATA, $8
DATA	·hostLibcSigaction(SB)/8, $hostLibcSigactionTrampoline<>(SB)
