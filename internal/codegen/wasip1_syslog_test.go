package codegen

import (
	"errors"
	"syscall"
	"testing"
)

// recordingSyslogger keeps what a guest sent to the system logger.
type recordingSyslogger struct {
	opened   []string
	messages []SyslogMessage
	closed   int
	fail     error
}

func (r *recordingSyslogger) Open(ident string, options, facility int32) error {
	if r.fail != nil {
		return r.fail
	}
	r.opened = append(r.opened, ident)
	return nil
}

func (r *recordingSyslogger) Log(msg SyslogMessage) error {
	if r.fail != nil {
		return r.fail
	}
	r.messages = append(r.messages, msg)
	return nil
}

func (r *recordingSyslogger) Close() error {
	r.closed++
	return nil
}

func TestSyslog_NoLoggerUnlessTheEmbedderGivesOne(t *testing.T) {
	w, m := newProcTestStubs(t)
	off, n := putPath(m, 0, "ident")
	if rc := w.Proc_syslog_open(m, off, n, 0, 1); rc != -_wasiENOSYS {
		t.Fatalf("open without a logger rc=%d, want -ENOSYS", rc)
	}
	if rc := w.Proc_syslog(m, 6, 1, 0, off, n, off, n); rc != -_wasiENOSYS {
		t.Fatalf("log without a logger rc=%d, want -ENOSYS", rc)
	}
	if rc := w.Proc_syslog_close(m); rc != -_wasiENOSYS {
		t.Fatalf("close without a logger rc=%d, want -ENOSYS", rc)
	}
}

func TestSyslog_MessagesReachTheLoggerAsTypedValues(t *testing.T) {
	w, m := newProcTestStubs(t)
	rec := &recordingSyslogger{}
	w.SetSyslogger(rec)
	identOff, identLen := putPath(m, 0, "my-daemon")
	msgOff, msgLen := putPath(m, 256, "disk 93% full")
	if rc := w.Proc_syslog_open(m, identOff, identLen, SyslogOptPID|SyslogOptNDelay, 3); rc != 0 {
		t.Fatalf("open rc=%d", rc)
	}
	if rc := w.Proc_syslog(m, 4, 3, SyslogOptPID|SyslogOptNDelay, identOff, identLen, msgOff, msgLen); rc != 0 {
		t.Fatalf("log rc=%d", rc)
	}
	if rc := w.Proc_syslog(m, 7, 16, 0, 0, 0, msgOff, msgLen); rc != 0 {
		t.Fatalf("log without ident rc=%d", rc)
	}
	if rc := w.Proc_syslog_close(m); rc != 0 {
		t.Fatalf("close rc=%d", rc)
	}
	want := []SyslogMessage{
		{Severity: 4, Facility: 3, Options: SyslogOptPID | SyslogOptNDelay, Ident: "my-daemon", Message: "disk 93% full"},
		{Severity: 7, Facility: 16, Message: "disk 93% full"},
	}
	if len(rec.opened) != 1 || rec.opened[0] != "my-daemon" || rec.closed != 1 || len(rec.messages) != len(want) {
		t.Fatalf("opened=%q closed=%d messages=%+v", rec.opened, rec.closed, rec.messages)
	}
	for i := range want {
		if rec.messages[i] != want[i] {
			t.Errorf("message %d = %+v, want %+v", i, rec.messages[i], want[i])
		}
	}

	// A forked instance logs to the same logger.
	child := w.Fork()
	defer child.CloseAll()
	if rc := child.Proc_syslog(m, 6, 1, 0, identOff, identLen, msgOff, msgLen); rc != 0 || len(rec.messages) != 3 {
		t.Fatalf("log from a forked instance rc=%d, %d messages", rc, len(rec.messages))
	}
}

func TestSyslog_RejectsValuesOutOfRangeAndReportsFailures(t *testing.T) {
	w, m := newProcTestStubs(t)
	rec := &recordingSyslogger{}
	w.SetSyslogger(rec)
	off, n := putPath(m, 0, "text")
	for _, c := range [][2]int32{{8, 1}, {-1, 1}, {6, 24}, {6, -1}} {
		if rc := w.Proc_syslog(m, c[0], c[1], 0, off, n, off, n); rc != -_wasiEINVAL {
			t.Errorf("severity %d facility %d rc=%d, want -EINVAL", c[0], c[1], rc)
		}
	}
	if len(rec.messages) != 0 {
		t.Fatalf("out-of-range messages were delivered: %+v", rec.messages)
	}
	rec.fail = syscall.ECONNREFUSED
	if rc := w.Proc_syslog_open(m, off, n, 0, 1); rc != -_wasiECONNREFUSED {
		t.Fatalf("open with a refusing logger rc=%d, want -ECONNREFUSED", rc)
	}
	rec.fail = errors.ErrUnsupported
	if rc := w.Proc_syslog(m, 6, 1, 0, off, n, off, n); rc != -_wasiENOTSUP {
		t.Fatalf("log with an unsupported logger rc=%d, want -ENOTSUP", rc)
	}
	w.SetSyslogger(nil)
	if rc := w.Proc_syslog(m, 6, 1, 0, off, n, off, n); rc != -_wasiENOSYS {
		t.Fatalf("log after the logger was taken away rc=%d, want -ENOSYS", rc)
	}
}
