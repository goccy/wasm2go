package codegen

import (
	"encoding/binary"
	"testing"
	"time"
)

const (
	zoneNameOff int32 = 22000
	zoneOutOff  int32 = 22200
)

type zoneAnswer struct {
	offset, other, stdOffset int32
	dst                      bool
	name, stdName, dstName   string
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// zoneAt asks Clock_zone about tz (nil: the guest names none) at t.
func zoneAt(t *testing.T, w *WasiStubs, m *Module, tz *string, at time.Time, local bool) zoneAnswer {
	t.Helper()
	var hasTZ, tzLen, isLocal int32
	if tz != nil {
		hasTZ = 1
		_, tzLen = putPath(m, zoneNameOff, *tz)
	}
	if local {
		isLocal = 1
	}
	if rc := w.Clock_zone(m, zoneNameOff, tzLen, hasTZ, at.Unix(), isLocal, zoneOutOff); rc != 0 {
		t.Fatalf("Clock_zone rc=%d", rc)
	}
	out := m.memory[zoneOutOff:]
	return zoneAnswer{
		offset:    int32(binary.LittleEndian.Uint32(out[0:])),
		dst:       binary.LittleEndian.Uint32(out[4:]) != 0,
		other:     int32(binary.LittleEndian.Uint32(out[8:])),
		stdOffset: int32(binary.LittleEndian.Uint32(out[12:])),
		name:      cString(out[16:32]),
		stdName:   cString(out[32:48]),
		dstName:   cString(out[48:64]),
	}
}

func TestZone_PosixStrings(t *testing.T) {
	w, m := newProcTestStubs(t)
	winter := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	summer := time.Date(2024, 7, 15, 12, 0, 0, 0, time.UTC)
	tz := func(s string) *string { return &s }

	if got, want := zoneAt(t, w, m, tz("JST-9"), winter, false), (zoneAnswer{offset: 32400, other: 32400, stdOffset: 32400, name: "JST", stdName: "JST"}); got != want {
		t.Errorf("JST-9 = %+v, want %+v", got, want)
	}
	east := "EST5EDT,M3.2.0,M11.1.0"
	if got, want := zoneAt(t, w, m, &east, winter, false), (zoneAnswer{offset: -18000, other: -14400, stdOffset: -18000, name: "EST", stdName: "EST", dstName: "EDT"}); got != want {
		t.Errorf("%s in winter = %+v, want %+v", east, got, want)
	}
	if got, want := zoneAt(t, w, m, &east, summer, false), (zoneAnswer{offset: -14400, other: -18000, stdOffset: -18000, dst: true, name: "EDT", stdName: "EST", dstName: "EDT"}); got != want {
		t.Errorf("%s in summer = %+v, want %+v", east, got, want)
	}
	// The change is on the second Sunday of March at 02:00 standard time:
	// 2024-03-10 07:00 UTC.
	change := time.Date(2024, 3, 10, 7, 0, 0, 0, time.UTC)
	if got := zoneAt(t, w, m, &east, change.Add(-time.Second), false); got.dst {
		t.Errorf("a second before the change: %+v", got)
	}
	if got := zoneAt(t, w, m, &east, change, false); !got.dst {
		t.Errorf("at the change: %+v", got)
	}
	// and back on the first Sunday of November at 02:00 daylight time:
	// 2024-11-03 06:00 UTC.
	back := time.Date(2024, 11, 3, 6, 0, 0, 0, time.UTC)
	if got := zoneAt(t, w, m, &east, back.Add(-time.Second), false); !got.dst {
		t.Errorf("a second before the change back: %+v", got)
	}
	if got := zoneAt(t, w, m, &east, back, false); got.dst {
		t.Errorf("at the change back: %+v", got)
	}
	// Without rules, the rules of the United States apply.
	if got := zoneAt(t, w, m, tz("PST8PDT"), summer, false); !got.dst || got.offset != -25200 || got.name != "PDT" {
		t.Errorf("PST8PDT in summer = %+v", got)
	}
	// The southern hemisphere, a quoted name, minutes, an explicit
	// daylight offset and times of day.
	south := "<+1030>-10:30<+11>-11,M10.1.0,M4.1.0/2"
	if got := zoneAt(t, w, m, &south, winter, false); !got.dst || got.offset != 39600 || got.name != "+11" || got.stdName != "+1030" {
		t.Errorf("%s in January = %+v", south, got)
	}
	if got := zoneAt(t, w, m, &south, summer, false); got.dst || got.offset != 37800 {
		t.Errorf("%s in July = %+v", south, got)
	}
	// A clock reading of the zone (what mktime starts from).
	if got := zoneAt(t, w, m, &east, time.Date(2024, 7, 15, 8, 0, 0, 0, time.UTC), true); !got.dst || got.offset != -14400 {
		t.Errorf("a summer clock reading = %+v", got)
	}
	if got := zoneAt(t, w, m, &east, time.Date(2024, 1, 15, 8, 0, 0, 0, time.UTC), true); got.dst || got.offset != -18000 {
		t.Errorf("a winter clock reading = %+v", got)
	}
	// What is neither a zone of the database nor a POSIX string is UTC.
	for _, bad := range []string{"", "No/Such_Zone", "AB3", "EST5EDT,M3.2.0", "EST5EDT,M13.1.0,M11.1.0", "EST5x"} {
		if got := zoneAt(t, w, m, &bad, summer, false); got.offset != 0 || got.dst || got.name != "UTC" {
			t.Errorf("TZ=%q = %+v, want UTC", bad, got)
		}
	}
}

func TestZone_NamesOfTheHostDatabase(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skipf("the host has no zone database: %v", err)
	}
	w, m := newProcTestStubs(t)
	winter := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	summer := time.Date(2024, 7, 15, 12, 0, 0, 0, time.UTC)
	for _, name := range []string{"Europe/Berlin", ":Europe/Berlin"} {
		name := name
		if got, want := zoneAt(t, w, m, &name, winter, false), (zoneAnswer{offset: 3600, other: 7200, stdOffset: 3600, name: "CET", stdName: "CET", dstName: "CEST"}); got != want {
			t.Errorf("%s in winter = %+v, want %+v", name, got, want)
		}
		if got, want := zoneAt(t, w, m, &name, summer, false), (zoneAnswer{offset: 7200, other: 3600, stdOffset: 3600, dst: true, name: "CEST", stdName: "CET", dstName: "CEST"}); got != want {
			t.Errorf("%s in summer = %+v, want %+v", name, got, want)
		}
	}
	name := "Europe/Berlin"
	if got := zoneAt(t, w, m, &name, time.Date(2024, 7, 15, 14, 0, 0, 0, time.UTC), true); !got.dst || got.offset != 7200 {
		t.Errorf("a summer clock reading = %+v", got)
	}
	tokyo := "Asia/Tokyo"
	if got, want := zoneAt(t, w, m, &tokyo, summer, false), (zoneAnswer{offset: 32400, other: 32400, stdOffset: 32400, name: "JST", stdName: "JST"}); got != want {
		t.Errorf("Asia/Tokyo = %+v, want %+v", got, want)
	}

	// A guest that names no zone is in UTC unless the embedder says where.
	if got := zoneAt(t, w, m, nil, summer, false); got.offset != 0 || got.name != "UTC" {
		t.Errorf("no TZ, no local zone = %+v, want UTC", got)
	}
	w.SetLocalZone(berlin)
	if got := zoneAt(t, w, m, nil, summer, false); got.offset != 7200 || got.name != "CEST" {
		t.Errorf("no TZ, local zone Berlin = %+v", got)
	}
	// A forked guest is in the same zone; a named zone wins over it.
	child := w.Fork()
	defer child.CloseAll()
	if got := zoneAt(t, child, m, nil, summer, false); got.offset != 7200 {
		t.Errorf("forked guest = %+v", got)
	}
	utc := "UTC"
	if got := zoneAt(t, w, m, &utc, summer, false); got.offset != 0 {
		t.Errorf("TZ=UTC with a local zone = %+v", got)
	}
}
