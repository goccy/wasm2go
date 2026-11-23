// The host's monotonic clock is read through the Go runtime by a
// //go:linkname, which the declarations of wasip1_native.go spliced into
// the generated output do not keep: this file is emitted as it is.

package codegen

import _ "unsafe" // for go:linkname

// HostMonotonicClock returns a reader, for WASIConfig.MonotonicClock, of
// the clock the Go runtime's timers count (runtime.nanotime), in
// nanoseconds: the guest's waits, which those timers count, then end when
// this clock says. Which clock that is depends on the system:
//
//   - Linux, FreeBSD, NetBSD, OpenBSD, DragonFly BSD, Solaris and illumos:
//     CLOCK_MONOTONIC.
//   - macOS: mach_absolute_time, which is CLOCK_UPTIME_RAW and not
//     CLOCK_MONOTONIC: it stands still while the system sleeps, and
//     CLOCK_MONOTONIC does not, so the readings of the two part by the
//     time the system has slept. An embedder whose guest is to read
//     macOS's CLOCK_MONOTONIC supplies a MonotonicClock of its own that
//     reads it.
//   - Windows: the interrupt time (QueryInterruptTime).
//   - AIX: CLOCK_REALTIME, the one the Go runtime counts by there.
func HostMonotonicClock() func() uint64 {
	return func() uint64 { return uint64(runtimeNanotime()) }
}

// runtimeNanotime is the Go runtime's reading of the clock its timers
// count, which package time keeps to itself (a time.Time carries it only as
// an offset from the start of the process).
//
//go:linkname runtimeNanotime runtime.nanotime
func runtimeNanotime() int64
