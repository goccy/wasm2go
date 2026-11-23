package codegen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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
	s, _, _ := bytes.Cut(b, []byte{0})
	return string(s)
}

// zoneCall calls Clock_zone about tz (nil: the guest names none) at t and
// returns its result.
func zoneCall(w *WasiStubs, m *Module, tz *string, at time.Time, local bool) int32 {
	var hasTZ, tzLen, isLocal int32
	if tz != nil {
		hasTZ = 1
		_, tzLen = putPath(m, zoneNameOff, *tz)
	}
	if local {
		isLocal = 1
	}
	return w.Clock_zone(m, zoneNameOff, tzLen, hasTZ, at.Unix(), isLocal, zoneOutOff)
}

// zoneAt asks Clock_zone about tz (nil: the guest names none) at t.
func zoneAt(t *testing.T, w *WasiStubs, m *Module, tz *string, at time.Time, local bool) zoneAnswer {
	t.Helper()
	if rc := zoneCall(w, m, tz, at, local); rc != 0 {
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

// hostZone loads a zone of the host's zone database, and skips the test
// when the host has none of that name.
func hostZone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skipf("the host's zone database has no %s: %v", name, err)
	}
	return loc
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
	if got := zoneAt(t, w, m, tz("AAA8BBB"), summer, false); !got.dst || got.offset != -25200 || got.name != "BBB" {
		t.Errorf("AAA8BBB in summer = %+v", got)
	}
	// Rules that start and end daylight saving time at the same instant
	// leave it out all year.
	if got := zoneAt(t, w, m, tz("EST5EDT,M3.2.0/2,M3.2.0/3"), summer, false); got.dst || got.offset != -18000 {
		t.Errorf("daylight saving time starting and ending at once, in summer = %+v", got)
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
	// Jn never counts February 29; n does: in 2024 J60 is March 1 and 59
	// is February 29.
	for _, tc := range []struct {
		zone   string
		change time.Time
	}{
		{"EST5EDT,J60,J300", time.Date(2024, 3, 1, 7, 0, 0, 0, time.UTC)},
		{"EST5EDT,J60,J300", time.Date(2023, 3, 1, 7, 0, 0, 0, time.UTC)},
		{"EST5EDT,59,299", time.Date(2024, 2, 29, 7, 0, 0, 0, time.UTC)},
	} {
		zone := tc.zone
		if got := zoneAt(t, w, m, &zone, tc.change.Add(-time.Second), false); got.dst {
			t.Errorf("%s a second before %s: %+v", zone, tc.change, got)
		}
		if got := zoneAt(t, w, m, &zone, tc.change, false); !got.dst {
			t.Errorf("%s at %s: %+v", zone, tc.change, got)
		}
	}
	// A clock reading of the zone (what mktime starts from).
	if got := zoneAt(t, w, m, &east, time.Date(2024, 7, 15, 8, 0, 0, 0, time.UTC), true); !got.dst || got.offset != -14400 {
		t.Errorf("a summer clock reading = %+v", got)
	}
	if got := zoneAt(t, w, m, &east, time.Date(2024, 1, 15, 8, 0, 0, 0, time.UTC), true); got.dst || got.offset != -18000 {
		t.Errorf("a winter clock reading = %+v", got)
	}
	// What is neither a zone of the database nor a POSIX string is UTC.
	for _, bad := range []string{"", "No/Such_Zone", "AB3", "EST5EDT,M3.2.0", "EST5EDT,M13.1.0,M11.1.0", "EST5x", "Local", "../UTC", "<AB>5", "<A/B>5", "<ABC5"} {
		if got := zoneAt(t, w, m, &bad, summer, false); got.offset != 0 || got.dst || got.name != "UTC" {
			t.Errorf("TZ=%q = %+v, want UTC", bad, got)
		}
	}
}

func TestZone_NamesOfTheHostDatabase(t *testing.T) {
	winter := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	summer := time.Date(2024, 7, 15, 12, 0, 0, 0, time.UTC)
	t.Run("Europe/Berlin", func(t *testing.T) {
		berlin := hostZone(t, "Europe/Berlin")
		w, m := newProcTestStubs(t)
		for _, name := range []string{"Europe/Berlin", ":Europe/Berlin"} {
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

		// A guest that names no zone is in UTC unless the configuration
		// says where.
		if got := zoneAt(t, w, m, nil, summer, false); got.offset != 0 || got.name != "UTC" {
			t.Errorf("no TZ, no local zone = %+v, want UTC", got)
		}
		w = NewWASI(WASIConfig{LocalZone: berlin})
		if got := zoneAt(t, w, m, nil, summer, false); got.offset != 7200 || got.name != "CEST" {
			t.Errorf("no TZ, local zone Berlin = %+v", got)
		}
		// A forked guest is in the same zone; a named zone wins over it.
		child := w.Fork()
		defer func() {
			if err := child.CloseAll(); err != nil {
				t.Error(err)
			}
		}()
		if got := zoneAt(t, child, m, nil, summer, false); got.offset != 7200 {
			t.Errorf("forked guest = %+v", got)
		}
		utc := "UTC"
		if got := zoneAt(t, w, m, &utc, summer, false); got.offset != 0 {
			t.Errorf("TZ=UTC with a local zone = %+v", got)
		}
	})
	t.Run("Asia/Tokyo", func(t *testing.T) {
		hostZone(t, "Asia/Tokyo")
		w, m := newProcTestStubs(t)
		tokyo := "Asia/Tokyo"
		if got, want := zoneAt(t, w, m, &tokyo, summer, false), (zoneAnswer{offset: 32400, other: 32400, stdOffset: 32400, name: "JST", stdName: "JST"}); got != want {
			t.Errorf("Asia/Tokyo = %+v, want %+v", got, want)
		}
	})
}

// A clock reading in the hour skipped when daylight saving time starts, or
// in the hour repeated when it ends, is standard time, for a zone of the
// host's database as for the POSIX string of its rules.
func TestZone_ReadingsInAGapOrAnOverlap(t *testing.T) {
	for _, tc := range []struct {
		zone, posix string
		reading     time.Time
		std         int32
	}{
		{"Europe/Berlin", "CET-1CEST,M3.5.0,M10.5.0/3", time.Date(2024, 3, 31, 2, 30, 0, 0, time.UTC), 3600},
		{"America/New_York", "EST5EDT,M3.2.0,M11.1.0", time.Date(2024, 11, 3, 1, 30, 0, 0, time.UTC), -18000},
	} {
		t.Run(tc.zone, func(t *testing.T) {
			hostZone(t, tc.zone)
			w, m := newProcTestStubs(t)
			got := zoneAt(t, w, m, &tc.zone, tc.reading, true)
			want := zoneAt(t, w, m, &tc.posix, tc.reading, true)
			if got != want || got.dst || got.offset != tc.std {
				t.Errorf("%s at %s = %+v, %s = %+v; want standard time (%d) for both", tc.zone, tc.reading.Format("2006-01-02 15:04"), got, tc.posix, want, tc.std)
			}
			// An hour later the reading is plain again, and daylight
			// saving time is in effect on one side of the change only.
			later := tc.reading.Add(time.Hour)
			if got, want := zoneAt(t, w, m, &tc.zone, later, true), zoneAt(t, w, m, &tc.posix, later, true); got != want {
				t.Errorf("%s at %s = %+v, %s = %+v", tc.zone, later.Format("2006-01-02 15:04"), got, tc.posix, want)
			}
		})
	}
}

// A reading in a day a change skipped, with daylight saving time on both
// sides of it, is taken as the time before the change: Samoa went from
// -10 to +14 at the end of 2011-12-29, both daylight saving time.
func TestZone_ReadingInASkippedDay(t *testing.T) {
	hostZone(t, "Pacific/Apia")
	w, m := newProcTestStubs(t)
	apia := "Pacific/Apia"
	if got := zoneAt(t, w, m, &apia, time.Date(2011, 12, 30, 12, 0, 0, 0, time.UTC), true); got.offset != -36000 || !got.dst {
		t.Errorf("Pacific/Apia at 2011-12-30 12:00 = %+v, want the -10 of before the change", got)
	}
}

// Errors is told the error of a name that loads no zone and is no POSIX TZ
// string, once for each time the name is resolved; the guest gets UTC. A
// POSIX TZ string, and a name that loads a zone, tell it nothing.
func TestZone_ErrorsOfLoadingAName(t *testing.T) {
	var ops []string
	var errs []error
	w := NewWASI(WASIConfig{
		FS: newHostFS(t, t.TempDir()),
		Errors: func(op string, err error) {
			ops = append(ops, op)
			errs = append(errs, err)
		},
	})
	m := newGuestModule(1 << 16)
	summer := time.Date(2024, 7, 15, 12, 0, 0, 0, time.UTC)
	missing, posix, utc := "/zoneinfo/none", "JST-9", "UTC"
	if got := zoneAt(t, w, m, &missing, summer, false); got.name != "UTC" {
		t.Errorf("TZ=%s = %+v, want UTC", missing, got)
	}
	zoneAt(t, w, m, &missing, summer, false)
	if got := zoneAt(t, w, m, &posix, summer, false); got.name != "JST" {
		t.Errorf("TZ=%s = %+v, want JST", posix, got)
	}
	zoneAt(t, w, m, &utc, summer, false)
	if len(errs) != 1 || ops[0] != "clock_zone" || !errors.Is(errs[0], fs.ErrNotExist) {
		t.Errorf("Errors was told %q %v; want clock_zone with the not-exist error of %s alone", ops, errs, missing)
	}
}

// A name that starts with '/' is the zone file of that path in the guest's
// filesystem.
func TestZone_FilesOfTheGuestFilesystem(t *testing.T) {
	var data []byte
	var err error
	for _, p := range []string{"/usr/share/zoneinfo/Europe/Paris", "/var/db/timezone/zoneinfo/Europe/Paris"} {
		if data, err = os.ReadFile(p); err == nil {
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
	}
	if err != nil {
		t.Skipf("the host has no zone file of Europe/Paris: %v", err)
	}
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	zoneinfo := filepath.Join(dir, "zoneinfo")
	if err := os.MkdirAll(filepath.Join(zoneinfo, "Europe"), 0o755); err != nil {
		t.Fatal(err)
	}
	paris := filepath.Join(zoneinfo, "Europe", "Paris")
	if err := os.WriteFile(paris, data, 0o644); err != nil {
		t.Fatal(err)
	}
	winter := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	summer := time.Date(2024, 7, 15, 12, 0, 0, 0, time.UTC)
	for _, name := range []string{"/zoneinfo/Europe/Paris", ":/zoneinfo/Europe/Paris"} {
		if got, want := zoneAt(t, w, m, &name, winter, false), (zoneAnswer{offset: 3600, other: 7200, stdOffset: 3600, name: "CET", stdName: "CET", dstName: "CEST"}); got != want {
			t.Errorf("%s in winter = %+v, want %+v", name, got, want)
		}
		if got := zoneAt(t, w, m, &name, summer, false); !got.dst || got.offset != 7200 || got.name != "CEST" {
			t.Errorf("%s in summer = %+v", name, got)
		}
	}

	// What is not a regular file of a zone's size is no zone: UTC.
	big := filepath.Join(zoneinfo, "big")
	if err := os.WriteFile(big, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big, wasiZoneFileMax+1); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"/zoneinfo/none", "/zoneinfo/Europe", "/zoneinfo/Europe/Paris/x", "/zoneinfo/big", "/"} {
		if got := zoneAt(t, w, m, &name, summer, false); got.offset != 0 || got.name != "UTC" {
			t.Errorf("TZ=%s = %+v, want UTC", name, got)
		}
	}

	// A file that cannot be read as a zone, and one the access policy
	// refuses, are no zone either.
	bad := "/zoneinfo/bad"
	if err := os.WriteFile(filepath.Join(zoneinfo, "bad"), []byte("not a zone"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := zoneAt(t, w, m, &bad, summer, false); got.offset != 0 || got.name != "UTC" {
		t.Errorf("TZ=%s = %+v, want UTC", bad, got)
	}
	denied := "/zoneinfo/Europe/./Paris"
	var seen []string
	policed := NewWASI(WASIConfig{FS: policyFS{
		FS:    newHostFS(t, dir),
		allow: func(path string, write bool) bool { return path != "zoneinfo/Europe/Paris" },
		seen:  &seen,
	}})
	if got := zoneAt(t, policed, m, &denied, summer, false); got.offset != 0 || got.name != "UTC" {
		t.Errorf("TZ=%s refused by the access policy = %+v, want UTC", denied, got)
	}

	// The zone of the last name stays while the guest names it again, and
	// a name is read again once the guest has named another.
	name := "/zoneinfo/Europe/Paris"
	if got := zoneAt(t, w, m, &name, summer, false); got.offset != 7200 {
		t.Errorf("TZ=%s = %+v", name, got)
	}
	if err := os.Remove(paris); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(zoneinfo, "bad"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := zoneAt(t, w, m, &name, summer, false); got.offset != 7200 {
		t.Errorf("TZ=%s again after the file is gone = %+v", name, got)
	}
	if got := zoneAt(t, w, m, nil, summer, false); got.offset != 0 {
		t.Errorf("no TZ = %+v", got)
	}
	if got := zoneAt(t, w, m, &name, summer, false); got.offset != 7200 {
		t.Errorf("TZ=%s after a guest naming none = %+v", name, got)
	}
	// A forked guest keeps the zone of the last name.
	child := w.Fork()
	defer func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	}()
	if got := zoneAt(t, child, m, &name, summer, false); got.offset != 7200 {
		t.Errorf("forked guest, TZ=%s without the file = %+v", name, got)
	}
	if got := zoneAt(t, w, m, &bad, summer, false); got.offset != 7200 {
		t.Errorf("TZ=%s once it is a zone file = %+v", bad, got)
	}
	if got := zoneAt(t, w, m, &name, summer, false); got.offset != 0 || got.name != "UTC" {
		t.Errorf("TZ=%s after TZ=%s, without the file = %+v, want UTC", name, bad, got)
	}
}
