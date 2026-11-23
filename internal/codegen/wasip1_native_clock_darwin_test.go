package codegen

import "golang.org/x/sys/unix"

// hostMonotonicClockID is the host's clock that HostMonotonicClock reads.
const hostMonotonicClockID = unix.CLOCK_UPTIME_RAW
