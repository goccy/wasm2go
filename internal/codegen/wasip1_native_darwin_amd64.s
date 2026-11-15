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

TEXT hostLibcGethostbyname2Trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_gethostbyname2(SB)
GLOBL	·hostLibcGethostbyname2(SB), RODATA, $8
DATA	·hostLibcGethostbyname2(SB)/8, $hostLibcGethostbyname2Trampoline<>(SB)

TEXT hostLibcFaccessatTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_faccessat(SB)
GLOBL	·hostLibcFaccessat(SB), RODATA, $8
DATA	·hostLibcFaccessat(SB)/8, $hostLibcFaccessatTrampoline<>(SB)
