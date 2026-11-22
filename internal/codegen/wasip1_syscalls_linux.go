//go:build linux

package codegen

import "runtime"

// hostSyscallNumber returns the number the host has the guest's system call
// of the number under (HostSyscalls): the same on arm64, riscv64 and
// loong64, whose numbers are the Linux ABI's; x86-64's call of the same
// name on amd64 (hostSyscallNumbersAMD64), the numbers from
// linuxSysPidfdSendSignal on being every architecture's; none on any other
// architecture, of which a 32-bit one takes a 64-bit argument in two
// registers and has its calls of 64-bit times under other names, and a
// 64-bit one of numbers of its own has no table here.
func hostSyscallNumber(number int64) (uintptr, bool) {
	switch runtime.GOARCH {
	case "arm64", "riscv64", "loong64":
		return uintptr(number), true
	case "amd64":
		if number >= linuxSysPidfdSendSignal {
			return uintptr(number), true
		}
		n, ok := hostSyscallNumbersAMD64[number]
		return n, ok
	}
	return 0, false
}

// hostSyscallNumbersAMD64 maps the Linux ABI's number of each system call
// below linuxSysPidfdSendSignal (Linux 7.2's scripts/syscall.tbl, the
// "common" and "64" calls) to x86-64's (arch/x86/entry/syscalls/
// syscall_64.tbl). Both are written out: this file is built for every
// architecture of Linux, and package syscall's SYS_ constants are the
// numbers of the architecture it is built for, not x86-64's.
var hostSyscallNumbersAMD64 = map[int64]uintptr{
	0:   206, // io_setup
	1:   207, // io_destroy
	2:   209, // io_submit
	3:   210, // io_cancel
	4:   208, // io_getevents
	5:   188, // setxattr
	6:   189, // lsetxattr
	7:   190, // fsetxattr
	8:   191, // getxattr
	9:   192, // lgetxattr
	10:  193, // fgetxattr
	11:  194, // listxattr
	12:  195, // llistxattr
	13:  196, // flistxattr
	14:  197, // removexattr
	15:  198, // lremovexattr
	16:  199, // fremovexattr
	17:  79,  // getcwd
	18:  212, // lookup_dcookie
	19:  290, // eventfd2
	20:  291, // epoll_create1
	21:  233, // epoll_ctl
	22:  281, // epoll_pwait
	23:  32,  // dup
	24:  292, // dup3
	25:  72,  // fcntl
	26:  294, // inotify_init1
	27:  254, // inotify_add_watch
	28:  255, // inotify_rm_watch
	29:  16,  // ioctl
	30:  251, // ioprio_set
	31:  252, // ioprio_get
	32:  73,  // flock
	33:  259, // mknodat
	34:  258, // mkdirat
	35:  263, // unlinkat
	36:  266, // symlinkat
	37:  265, // linkat
	38:  264, // renameat
	39:  166, // umount2
	40:  165, // mount
	41:  155, // pivot_root
	42:  180, // nfsservctl
	43:  137, // statfs
	44:  138, // fstatfs
	45:  76,  // truncate
	46:  77,  // ftruncate
	47:  285, // fallocate
	48:  269, // faccessat
	49:  80,  // chdir
	50:  81,  // fchdir
	51:  161, // chroot
	52:  91,  // fchmod
	53:  268, // fchmodat
	54:  260, // fchownat
	55:  93,  // fchown
	56:  257, // openat
	57:  3,   // close
	58:  153, // vhangup
	59:  293, // pipe2
	60:  179, // quotactl
	61:  217, // getdents64
	62:  8,   // lseek
	63:  0,   // read
	64:  1,   // write
	65:  19,  // readv
	66:  20,  // writev
	67:  17,  // pread64
	68:  18,  // pwrite64
	69:  295, // preadv
	70:  296, // pwritev
	71:  40,  // sendfile
	72:  270, // pselect6
	73:  271, // ppoll
	74:  289, // signalfd4
	75:  278, // vmsplice
	76:  275, // splice
	77:  276, // tee
	78:  267, // readlinkat
	79:  262, // newfstatat
	80:  5,   // fstat
	81:  162, // sync
	82:  74,  // fsync
	83:  75,  // fdatasync
	84:  277, // sync_file_range
	85:  283, // timerfd_create
	86:  286, // timerfd_settime
	87:  287, // timerfd_gettime
	88:  280, // utimensat
	89:  163, // acct
	90:  125, // capget
	91:  126, // capset
	92:  135, // personality
	93:  60,  // exit
	94:  231, // exit_group
	95:  247, // waitid
	96:  218, // set_tid_address
	97:  272, // unshare
	98:  202, // futex
	99:  273, // set_robust_list
	100: 274, // get_robust_list
	101: 35,  // nanosleep
	102: 36,  // getitimer
	103: 38,  // setitimer
	104: 246, // kexec_load
	105: 175, // init_module
	106: 176, // delete_module
	107: 222, // timer_create
	108: 224, // timer_gettime
	109: 225, // timer_getoverrun
	110: 223, // timer_settime
	111: 226, // timer_delete
	112: 227, // clock_settime
	113: 228, // clock_gettime
	114: 229, // clock_getres
	115: 230, // clock_nanosleep
	116: 103, // syslog
	117: 101, // ptrace
	118: 142, // sched_setparam
	119: 144, // sched_setscheduler
	120: 145, // sched_getscheduler
	121: 143, // sched_getparam
	122: 203, // sched_setaffinity
	123: 204, // sched_getaffinity
	124: 24,  // sched_yield
	125: 146, // sched_get_priority_max
	126: 147, // sched_get_priority_min
	127: 148, // sched_rr_get_interval
	128: 219, // restart_syscall
	129: 62,  // kill
	130: 200, // tkill
	131: 234, // tgkill
	132: 131, // sigaltstack
	133: 130, // rt_sigsuspend
	134: 13,  // rt_sigaction
	135: 14,  // rt_sigprocmask
	136: 127, // rt_sigpending
	137: 128, // rt_sigtimedwait
	138: 129, // rt_sigqueueinfo
	139: 15,  // rt_sigreturn
	140: 141, // setpriority
	141: 140, // getpriority
	142: 169, // reboot
	143: 114, // setregid
	144: 106, // setgid
	145: 113, // setreuid
	146: 105, // setuid
	147: 117, // setresuid
	148: 118, // getresuid
	149: 119, // setresgid
	150: 120, // getresgid
	151: 122, // setfsuid
	152: 123, // setfsgid
	153: 100, // times
	154: 109, // setpgid
	155: 121, // getpgid
	156: 124, // getsid
	157: 112, // setsid
	158: 115, // getgroups
	159: 116, // setgroups
	160: 63,  // uname
	161: 170, // sethostname
	162: 171, // setdomainname
	163: 97,  // getrlimit
	164: 160, // setrlimit
	165: 98,  // getrusage
	166: 95,  // umask
	167: 157, // prctl
	168: 309, // getcpu
	169: 96,  // gettimeofday
	170: 164, // settimeofday
	171: 159, // adjtimex
	172: 39,  // getpid
	173: 110, // getppid
	174: 102, // getuid
	175: 107, // geteuid
	176: 104, // getgid
	177: 108, // getegid
	178: 186, // gettid
	179: 99,  // sysinfo
	180: 240, // mq_open
	181: 241, // mq_unlink
	182: 242, // mq_timedsend
	183: 243, // mq_timedreceive
	184: 244, // mq_notify
	185: 245, // mq_getsetattr
	186: 68,  // msgget
	187: 71,  // msgctl
	188: 70,  // msgrcv
	189: 69,  // msgsnd
	190: 64,  // semget
	191: 66,  // semctl
	192: 220, // semtimedop
	193: 65,  // semop
	194: 29,  // shmget
	195: 31,  // shmctl
	196: 30,  // shmat
	197: 67,  // shmdt
	198: 41,  // socket
	199: 53,  // socketpair
	200: 49,  // bind
	201: 50,  // listen
	202: 43,  // accept
	203: 42,  // connect
	204: 51,  // getsockname
	205: 52,  // getpeername
	206: 44,  // sendto
	207: 45,  // recvfrom
	208: 54,  // setsockopt
	209: 55,  // getsockopt
	210: 48,  // shutdown
	211: 46,  // sendmsg
	212: 47,  // recvmsg
	213: 187, // readahead
	214: 12,  // brk
	215: 11,  // munmap
	216: 25,  // mremap
	217: 248, // add_key
	218: 249, // request_key
	219: 250, // keyctl
	220: 56,  // clone
	221: 59,  // execve
	222: 9,   // mmap
	223: 221, // fadvise64
	224: 167, // swapon
	225: 168, // swapoff
	226: 10,  // mprotect
	227: 26,  // msync
	228: 149, // mlock
	229: 150, // munlock
	230: 151, // mlockall
	231: 152, // munlockall
	232: 27,  // mincore
	233: 28,  // madvise
	234: 216, // remap_file_pages
	235: 237, // mbind
	236: 239, // get_mempolicy
	237: 238, // set_mempolicy
	238: 256, // migrate_pages
	239: 279, // move_pages
	240: 297, // rt_tgsigqueueinfo
	241: 298, // perf_event_open
	242: 288, // accept4
	243: 299, // recvmmsg
	260: 61,  // wait4
	261: 302, // prlimit64
	262: 300, // fanotify_init
	263: 301, // fanotify_mark
	264: 303, // name_to_handle_at
	265: 304, // open_by_handle_at
	266: 305, // clock_adjtime
	267: 306, // syncfs
	268: 308, // setns
	269: 307, // sendmmsg
	270: 310, // process_vm_readv
	271: 311, // process_vm_writev
	272: 312, // kcmp
	273: 313, // finit_module
	274: 314, // sched_setattr
	275: 315, // sched_getattr
	276: 316, // renameat2
	277: 317, // seccomp
	278: 318, // getrandom
	279: 319, // memfd_create
	280: 321, // bpf
	281: 322, // execveat
	282: 323, // userfaultfd
	283: 324, // membarrier
	284: 325, // mlock2
	285: 326, // copy_file_range
	286: 327, // preadv2
	287: 328, // pwritev2
	288: 329, // pkey_mprotect
	289: 330, // pkey_alloc
	290: 331, // pkey_free
	291: 332, // statx
	292: 333, // io_pgetevents
	293: 334, // rseq
	294: 320, // kexec_file_load
}
