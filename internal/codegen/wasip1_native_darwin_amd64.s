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

TEXT hostLibcMsggetTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_msgget(SB)
GLOBL	·hostLibcMsgget(SB), RODATA, $8
DATA	·hostLibcMsgget(SB)/8, $hostLibcMsggetTrampoline<>(SB)

TEXT hostLibcSemgetTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_semget(SB)
GLOBL	·hostLibcSemget(SB), RODATA, $8
DATA	·hostLibcSemget(SB)/8, $hostLibcSemgetTrampoline<>(SB)

TEXT hostLibcShmgetTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_shmget(SB)
GLOBL	·hostLibcShmget(SB), RODATA, $8
DATA	·hostLibcShmget(SB)/8, $hostLibcShmgetTrampoline<>(SB)

TEXT hostLibcMsgctlTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_msgctl(SB)
GLOBL	·hostLibcMsgctl(SB), RODATA, $8
DATA	·hostLibcMsgctl(SB)/8, $hostLibcMsgctlTrampoline<>(SB)

TEXT hostLibcSemctlTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc___semctl(SB)
GLOBL	·hostLibcSemctl(SB), RODATA, $8
DATA	·hostLibcSemctl(SB)/8, $hostLibcSemctlTrampoline<>(SB)

TEXT hostLibcShmctlTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_shmctl(SB)
GLOBL	·hostLibcShmctl(SB), RODATA, $8
DATA	·hostLibcShmctl(SB)/8, $hostLibcShmctlTrampoline<>(SB)

TEXT hostLibcSemopTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_semop(SB)
GLOBL	·hostLibcSemop(SB), RODATA, $8
DATA	·hostLibcSemop(SB)/8, $hostLibcSemopTrampoline<>(SB)

TEXT hostLibcMsgsndTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_msgsnd(SB)
GLOBL	·hostLibcMsgsnd(SB), RODATA, $8
DATA	·hostLibcMsgsnd(SB)/8, $hostLibcMsgsndTrampoline<>(SB)

TEXT hostLibcMsgrcvTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_msgrcv(SB)
GLOBL	·hostLibcMsgrcv(SB), RODATA, $8
DATA	·hostLibcMsgrcv(SB)/8, $hostLibcMsgrcvTrampoline<>(SB)

TEXT hostLibcShmatTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_shmat(SB)
GLOBL	·hostLibcShmat(SB), RODATA, $8
DATA	·hostLibcShmat(SB)/8, $hostLibcShmatTrampoline<>(SB)

TEXT hostLibcShmdtTrampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_shmdt(SB)
GLOBL	·hostLibcShmdt(SB), RODATA, $8
DATA	·hostLibcShmdt(SB)/8, $hostLibcShmdtTrampoline<>(SB)
