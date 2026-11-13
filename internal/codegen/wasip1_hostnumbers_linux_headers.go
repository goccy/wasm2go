//go:build linux && !(mips || mipsle || mips64 || mips64le)

package codegen

// Numbers of the operating system for a guest that shows its program the
// host's (see "the numbers of the operating system" in
// wasip1_native_posix.go). A family is a kind of number; its id is the one
// the guest asks by, and a name is the one the number has in C. A name is
// added to its family here, for every system that has it, and to the table
// of the guest that is to translate it.

// hostNumbersFromHeaders holds the numbers of linux that package syscall
// lacks, as the system's C headers define them, by family and name.
// They are the same on every architecture this file is built for.
var hostNumbersFromHeaders = map[int32][]hostNumber{
	1: { // errno
		{"EHWPOISON", 133},
	},
	2: { // signal
		{"SIGSTKFLT", 16},
	},
	4: { // poll
		{"POLLIN", 1},
		{"POLLPRI", 2},
		{"POLLOUT", 4},
		{"POLLERR", 8},
		{"POLLHUP", 16},
		{"POLLNVAL", 32},
		{"POLLRDNORM", 64},
		{"POLLRDBAND", 128},
		{"POLLWRNORM", 256},
		{"POLLWRBAND", 512},
	},
	9: { // so
		{"SO_REUSEPORT", 15},
	},
	10: { // ip
		{"IP_BIND_ADDRESS_NO_PORT", 24},
		{"IP_MULTICAST_ALL", 49},
		{"IP_NODEFRAG", 22},
	},
	12: { // tcp
		{"TCP_CC_INFO", 26},
		{"TCP_FASTOPEN", 23},
		{"TCP_FASTOPEN_CONNECT", 30},
		{"TCP_FASTOPEN_KEY", 33},
		{"TCP_FASTOPEN_NO_COOKIE", 34},
		{"TCP_MD5SIG_EXT", 32},
		{"TCP_NOTSENT_LOWAT", 25},
		{"TCP_TIMESTAMP", 24},
		{"TCP_TX_DELAY", 37},
		{"TCP_USER_TIMEOUT", 18},
	},
	14: { // ai
		{"AI_PASSIVE", 1},
		{"AI_CANONNAME", 2},
		{"AI_NUMERICHOST", 4},
		{"AI_V4MAPPED", 8},
		{"AI_ALL", 16},
		{"AI_ADDRCONFIG", 32},
		{"AI_NUMERICSERV", 1024},
	},
	15: { // ni
		{"NI_NUMERICHOST", 1},
		{"NI_NUMERICSERV", 2},
		{"NI_NOFQDN", 4},
		{"NI_NAMEREQD", 8},
		{"NI_DGRAM", 16},
	},
	16: { // eai
		{"EAI_AGAIN", -3},
		{"EAI_BADFLAGS", -1},
		{"EAI_FAIL", -4},
		{"EAI_FAMILY", -6},
		{"EAI_MEMORY", -10},
		{"EAI_NONAME", -2},
		{"EAI_SERVICE", -8},
		{"EAI_SOCKTYPE", -7},
		{"EAI_SYSTEM", -11},
		{"EAI_OVERFLOW", -12},
		{"EAI_NODATA", -5},
		{"EAI_ADDRFAMILY", -9},
	},
	17: { // lc
		{"LC_ALL", 6},
		{"LC_COLLATE", 3},
		{"LC_CTYPE", 0},
		{"LC_MESSAGES", 5},
		{"LC_MONETARY", 4},
		{"LC_NUMERIC", 1},
		{"LC_TIME", 2},
	},
	18: { // sighow
		{"SIG_BLOCK", 0},
		{"SIG_UNBLOCK", 1},
		{"SIG_SETMASK", 2},
	},
	19: { // sa
		{"SA_NOCLDSTOP", 1},
		{"SA_NOCLDWAIT", 2},
		{"SA_NODEFER", 1073741824},
		{"SA_RESETHAND", 2147483648},
		{"SA_RESTART", 268435456},
		{"SA_SIGINFO", 4},
		{"SA_ONSTACK", 134217728},
	},
}
