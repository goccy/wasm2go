//go:build darwin

package codegen

import (
	"syscall"
	"time"
)

// statTimes returns the access and status-change times of a stat result.
func statTimes(st *syscall.Stat_t) (atime, ctime time.Time) {
	return time.Unix(st.Atimespec.Unix()), time.Unix(st.Ctimespec.Unix())
}
