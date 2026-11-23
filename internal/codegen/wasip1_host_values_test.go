package codegen

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// recordReader reads the fields of a record a host import hands back.
type recordReader struct {
	t   *testing.T
	rec []byte
}

func (r *recordReader) u32() uint32 {
	r.t.Helper()
	if len(r.rec) < 4 {
		r.t.Fatalf("record ends before a u32: % x", r.rec)
	}
	v := binary.LittleEndian.Uint32(r.rec)
	r.rec = r.rec[4:]
	return v
}

func (r *recordReader) str() string {
	r.t.Helper()
	n := int(r.u32())
	if len(r.rec) < n {
		r.t.Fatalf("record ends before a string of %d bytes", n)
	}
	s := string(r.rec[:n])
	r.rec = r.rec[n:]
	return s
}

// record returns a reader of the record a call wrote at bufPtr, of the size
// it wrote at neededPtr.
func record(t *testing.T, m *Module, bufPtr, neededPtr int) *recordReader {
	return &recordReader{t: t, rec: m.memory[bufPtr : bufPtr+int(readU32(m.memory, neededPtr))]}
}

// idsProcess is a testProcess with groups and a priority.
type idsProcess struct {
	testProcess
	groups   []int32
	groupErr error
	nice     int32
	err      error
}

func (p idsProcess) Groups() ([]int32, error)                 { return p.groups, p.groupErr }
func (p idsProcess) Priority(which, who int32) (int32, error) { return p.nice + who, p.err }

func newIDsProcess() idsProcess {
	return idsProcess{testProcess: testProcess{ids: ProcessIDs{PID: 7}}}
}

// recordedChanges is a ProcessChanges that records the changes it is asked
// for and fails them with err.
type recordedChanges struct {
	err     error
	changes []IDChange
	set     [][]int32
	prios   [][3]int32
	umasks  []os.FileMode
}

func (c *recordedChanges) SetIDs(change IDChange) error {
	c.changes = append(c.changes, change)
	return c.err
}
func (c *recordedChanges) SetGroups(groups []int32) error {
	c.set = append(c.set, groups)
	return c.err
}
func (c *recordedChanges) SetPriority(which, who, prio int32) error {
	c.prios = append(c.prios, [3]int32{which, who, prio})
	return c.err
}
func (c *recordedChanges) SetUmask(mask os.FileMode) (os.FileMode, error) {
	c.umasks = append(c.umasks, mask)
	return 0, c.err
}
func (c *recordedChanges) Pgid(pid int32) (int32, error) { return 0, errors.ErrUnsupported }
func (c *recordedChanges) Setpgid(pid, pgid int32) error { return errors.ErrUnsupported }
func (c *recordedChanges) Setsid() (int32, error)        { return 0, errors.ErrUnsupported }

func TestProcGroupsOfTheProcess(t *testing.T) {
	const bufPtr, countPtr = 256, 64
	w, m := newProcTestStubs(t)
	if rc := w.Proc_groups(m, bufPtr, 16, countPtr); rc != _wasiESUCCESS || readU32(m.memory, countPtr) != 0 {
		t.Fatalf("isolated Proc_groups rc=%d count=%d, want no groups", rc, readU32(m.memory, countPtr))
	}
	p := newIDsProcess()
	p.groups = []int32{20, 12, 61}
	w.cfg.Process = p
	if rc := w.Proc_groups(m, bufPtr, 0, countPtr); rc != _wasiESUCCESS || readU32(m.memory, countPtr) != 3 {
		t.Fatalf("Proc_groups(count) rc=%d count=%d", rc, readU32(m.memory, countPtr))
	}
	if rc := w.Proc_groups(m, bufPtr, 2, countPtr); rc != -_wasiERANGE {
		t.Fatalf("Proc_groups into a short buffer rc=%d, want -ERANGE", rc)
	}
	if rc := w.Proc_groups(m, bufPtr, 3, countPtr); rc != _wasiESUCCESS {
		t.Fatalf("Proc_groups rc=%d", rc)
	}
	for i, gid := range p.groups {
		if got := readU32(m.memory, bufPtr+i*4); got != uint32(gid) {
			t.Fatalf("group %d = %d, want %d", i, got, gid)
		}
	}
	if rc := w.Proc_groups(m, 1<<16-4, 3, countPtr); rc != -_wasiEFAULT {
		t.Fatalf("Proc_groups past the memory rc=%d, want -EFAULT", rc)
	}
	if rc := w.Proc_groups(m, bufPtr, -1, countPtr); rc != -_wasiEINVAL {
		t.Fatalf("Proc_groups of a negative capacity rc=%d, want -EINVAL", rc)
	}
	p.groupErr = syscall.EPERM
	w.cfg.Process = p
	if rc := w.Proc_groups(m, bufPtr, 3, countPtr); rc != -_wasiEPERM {
		t.Fatalf("Proc_groups failing with EPERM rc=%d", rc)
	}
}

// proc_setids hands the ProcessChanges the call and its ids, -1 past those
// the call takes; without one none is changed (ENOSYS).
func TestProcSetidsGoesToTheProcess(t *testing.T) {
	w, m := newProcTestStubs(t)
	if rc := w.Proc_setids(m, int32(IDSetuid), 0, -1, -1); rc != -_wasiENOSYS {
		t.Fatalf("Proc_setids of an isolated guest rc=%d, want -ENOSYS", rc)
	}
	if rc := w.Proc_setgroups(m, 64, 0); rc != -_wasiENOSYS {
		t.Fatalf("Proc_setgroups of an isolated guest rc=%d, want -ENOSYS", rc)
	}
	p := &recordedChanges{}
	w.cfg.ProcessChanges = p
	for call := IDSetuid; call <= IDSetresgid; call++ {
		if rc := w.Proc_setids(m, int32(call), 1, 2, 3); rc != _wasiESUCCESS {
			t.Fatalf("Proc_setids(%d) rc=%d", call, rc)
		}
	}
	want := []IDChange{
		{IDSetuid, [3]int32{1, -1, -1}}, {IDSeteuid, [3]int32{1, -1, -1}},
		{IDSetreuid, [3]int32{1, 2, -1}}, {IDSetresuid, [3]int32{1, 2, 3}},
		{IDSetgid, [3]int32{1, -1, -1}}, {IDSetegid, [3]int32{1, -1, -1}},
		{IDSetregid, [3]int32{1, 2, -1}}, {IDSetresgid, [3]int32{1, 2, 3}},
	}
	if !slices.Equal(p.changes, want) {
		t.Fatalf("changes = %v, want %v", p.changes, want)
	}
	for _, request := range []int32{-1, int32(IDSetresgid) + 1} {
		if rc := w.Proc_setids(m, request, 1, 2, 3); rc != -_wasiEINVAL {
			t.Fatalf("Proc_setids of request %d rc=%d, want -EINVAL", request, rc)
		}
	}
	binary.LittleEndian.PutUint32(m.memory[64:], 5)
	binary.LittleEndian.PutUint32(m.memory[68:], 6)
	if rc := w.Proc_setgroups(m, 64, 2); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setgroups rc=%d", rc)
	}
	if got := p.set; len(got) != 1 || !slices.Equal(got[0], []int32{5, 6}) {
		t.Fatalf("groups set = %v, want [[5 6]]", got)
	}
	for _, count := range []int32{-1, 65537} {
		if rc := w.Proc_setgroups(m, 64, count); rc != -_wasiEINVAL {
			t.Fatalf("Proc_setgroups of %d groups rc=%d, want -EINVAL", count, rc)
		}
	}
	if rc := w.Proc_setgroups(m, 1<<16-4, 2); rc != -_wasiEFAULT {
		t.Fatalf("Proc_setgroups past the memory rc=%d, want -EFAULT", rc)
	}
	for _, c := range []struct {
		err  error
		want int32
	}{
		{syscall.EPERM, _wasiEPERM},
		{syscall.EINVAL, _wasiEINVAL},
		{errors.ErrUnsupported, _wasiENOSYS},
	} {
		p.err = c.err
		if rc := w.Proc_setids(m, int32(IDSetuid), 1, -1, -1); rc != -c.want {
			t.Errorf("Proc_setids failing with %v rc=%d, want %d", c.err, rc, -c.want)
		}
		if rc := w.Proc_setgroups(m, 64, 2); rc != -c.want {
			t.Errorf("Proc_setgroups failing with %v rc=%d, want %d", c.err, rc, -c.want)
		}
	}
}

// proc_priority reads the nice value from the Process, after setting it
// through the ProcessChanges when asked; the guest's own pid is 0 to them.
func TestProcPriorityGoesToTheProcess(t *testing.T) {
	const out = 64
	w, m := newProcTestStubs(t)
	if rc := w.Proc_priority(m, 0, 0, 0, 0, out); rc != _wasiESUCCESS || readU32(m.memory, out) != 0 {
		t.Fatalf("Proc_priority of an isolated guest rc=%d nice=%d, want 0", rc, readU32(m.memory, out))
	}
	if rc := w.Proc_priority(m, 0, 0, 1, 5, out); rc != -_wasiENOSYS {
		t.Fatalf("setting the priority of an isolated guest rc=%d, want -ENOSYS", rc)
	}
	p := newIDsProcess()
	p.nice = 3
	w.cfg.Process = p
	changes := &recordedChanges{}
	w.cfg.ProcessChanges = changes
	if rc := w.Proc_priority(m, 0, 7, 1, 5, out); rc != _wasiESUCCESS || readU32(m.memory, out) != 3 {
		t.Fatalf("Proc_priority of the own pid rc=%d nice=%d, want 3", rc, readU32(m.memory, out))
	}
	if rc := w.Proc_priority(m, 2, 7, 0, 0, out); rc != _wasiESUCCESS || readU32(m.memory, out) != 10 {
		t.Fatalf("Proc_priority of user 7 rc=%d nice=%d, want 10", rc, readU32(m.memory, out))
	}
	if got := changes.prios; !slices.Equal(got, [][3]int32{{0, 0, 5}}) {
		t.Fatalf("priorities set = %v, want [[0 0 5]]", got)
	}
	token, _ := w.NewProc(nil)
	if rc := w.Proc_priority(m, 0, token, 0, 0, out); rc != -_wasiESRCH {
		t.Fatalf("Proc_priority of a process the guest runs rc=%d, want -ESRCH", rc)
	}
	if rc := w.Proc_priority(m, 0, token, 1, 5, out); rc != -_wasiESRCH {
		t.Fatalf("setting the priority of a process the guest runs rc=%d, want -ESRCH", rc)
	}
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	// A Fork copy has the pid of its Process: its own.
	if rc := child.Proc_priority(newForkTestModule(), 0, 7, 0, 0, out); rc != _wasiESUCCESS {
		t.Fatalf("Proc_priority of its own pid by a Fork copy rc=%d", rc)
	}
	if rc := w.Proc_priority(m, 0, 0, 0, 0, 1<<16-2); rc != -_wasiEFAULT {
		t.Fatalf("Proc_priority past the memory rc=%d, want -EFAULT", rc)
	}
	changes.err = syscall.EACCES
	if rc := w.Proc_priority(m, 0, 0, 1, 5, out); rc != -_wasiEACCES {
		t.Fatalf("setting a priority failing with EACCES rc=%d", rc)
	}
	p.err = syscall.EACCES
	w.cfg.Process = p
	if rc := w.Proc_priority(m, 0, 0, 0, 0, out); rc != -_wasiEACCES {
		t.Fatalf("reading a priority failing with EACCES rc=%d", rc)
	}
}

// HostProcess reports the host process's groups and priority, and
// HostProcessChanges changes its ids and priority by the host's calls.
func TestHostProcessGroupsIDsAndPriority(t *testing.T) {
	p := HostProcessUmask(0o022)
	pc := HostProcessChanges()
	groups, err := p.Groups()
	want, wantErr := os.Getgroups()
	if (err == nil) != (wantErr == nil) {
		t.Fatalf("Groups error %v, os.Getgroups error %v", err, wantErr)
	}
	for i, gid := range want {
		if groups[i] != int32(gid) {
			t.Fatalf("Groups = %v, want %v", groups, want)
		}
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		for _, err := range []error{
			pc.SetIDs(IDChange{Call: IDSetuid, IDs: [3]int32{0, -1, -1}}),
			pc.SetGroups(nil),
			pc.SetPriority(0, 0, 0),
		} {
			if !errors.Is(err, errors.ErrUnsupported) {
				t.Fatalf("a change on %s: %v, want ErrUnsupported", runtime.GOOS, err)
			}
		}
		return
	}
	nice, err := p.Priority(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := pc.SetPriority(0, 0, nice); err != nil {
		t.Fatalf("SetPriority to the nice value in effect: %v", err)
	}
	uid, gid := int32(os.Getuid()), int32(os.Getgid())
	for _, c := range []IDChange{
		{IDSetuid, [3]int32{uid, -1, -1}}, {IDSeteuid, [3]int32{uid, -1, -1}},
		{IDSetreuid, [3]int32{-1, -1, -1}}, {IDSetresuid, [3]int32{-1, -1, -1}},
		{IDSetgid, [3]int32{gid, -1, -1}}, {IDSetegid, [3]int32{gid, -1, -1}},
		{IDSetregid, [3]int32{-1, -1, -1}}, {IDSetresgid, [3]int32{-1, -1, -1}},
	} {
		if err := pc.SetIDs(c); err != nil {
			t.Errorf("SetIDs(%v) to the ids in effect: %v", c, err)
		}
	}
	if err := pc.SetIDs(IDChange{Call: IDSetresgid + 1}); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("SetIDs of an unknown call: %v, want EINVAL", err)
	}
	if os.Getuid() != 0 {
		if err := pc.SetIDs(IDChange{Call: IDSetuid, IDs: [3]int32{uid + 1, -1, -1}}); !errors.Is(err, syscall.EPERM) {
			t.Errorf("setuid to another user: %v, want EPERM", err)
		}
		if err := pc.SetGroups([]int32{gid}); !errors.Is(err, syscall.EPERM) {
			t.Errorf("setgroups of a user who is not the superuser: %v, want EPERM", err)
		}
	}
}

// fakeUsers is a Users of one user and one group.
type fakeUsers struct {
	user  User
	group Group
	err   error
}

func (u fakeUsers) find(found bool) error {
	if u.err != nil {
		return u.err
	}
	if !found {
		return fs.ErrNotExist
	}
	return nil
}
func (u fakeUsers) UserByID(uid int32) (User, error) { return u.user, u.find(uid == u.user.UID) }
func (u fakeUsers) UserByName(name string) (User, error) {
	return u.user, u.find(name == u.user.Name)
}
func (u fakeUsers) ListUsers() ([]User, error)         { return []User{u.user}, u.err }
func (u fakeUsers) GroupByID(gid int32) (Group, error) { return u.group, u.find(gid == u.group.GID) }
func (u fakeUsers) GroupByName(name string) (Group, error) {
	return u.group, u.find(name == u.group.Name)
}
func (u fakeUsers) ListGroups() ([]Group, error) { return []Group{u.group}, u.err }

// listedUsers is a Users whose lists are users and groups as they are at
// the call, and which counts the calls.
type listedUsers struct {
	noUsers
	users       []User
	groups      []Group
	usersLists  int
	groupsLists int
}

func (u *listedUsers) ListUsers() ([]User, error) {
	u.usersLists++
	return slices.Clone(u.users), nil
}

func (u *listedUsers) ListGroups() ([]Group, error) {
	u.groupsLists++
	return slices.Clone(u.groups), nil
}

// A walk of the user or group database is the list the Users gave when the
// guest asked for the first entry: a change of the database meanwhile is
// not seen until the guest starts again, and a forked instance goes on with
// the walk it was forked in.
func TestUserWalksAreListsOfTheirStart(t *testing.T) {
	const bufPtr, neededPtr = 1024, 512
	w, m := newProcTestStubs(t)
	alice, bob, carol := User{Name: "alice", UID: 1}, User{Name: "bob", UID: 2}, User{Name: "carol", UID: 3}
	staff, wheel := Group{Name: "staff", GID: 20}, Group{Name: "wheel", GID: 0}
	db := &listedUsers{users: []User{alice, bob}, groups: []Group{staff}}
	w.cfg.Users = db
	userAt := func(w *WasiStubs, i int32) (User, int32) {
		rc := w.Proc_user_at(m, i, bufPtr, 4096, neededPtr)
		if rc != _wasiESUCCESS {
			return User{}, rc
		}
		return readUser(t, m, bufPtr, neededPtr), rc
	}
	// An instance without a walk starts one at any index.
	if u, rc := userAt(w, 1); rc != _wasiESUCCESS || u != bob {
		t.Fatalf("entry 1 of no walk = %+v rc=%d, want bob", u, rc)
	}
	if u, rc := userAt(w, 0); rc != _wasiESUCCESS || u != alice {
		t.Fatalf("entry 0 = %+v rc=%d, want alice", u, rc)
	}
	db.users = []User{carol, alice, bob}
	if u, rc := userAt(w, 1); rc != _wasiESUCCESS || u != bob {
		t.Fatalf("entry 1 after a change = %+v rc=%d, want the bob of the walk's start", u, rc)
	}
	if _, rc := userAt(w, 2); rc != -_wasiENOENT {
		t.Fatalf("entry 2 of a walk of two rc=%d, want -ENOENT", rc)
	}
	if db.usersLists != 2 {
		t.Fatalf("ListUsers called %d times, want 2 (one for each walk)", db.usersLists)
	}
	child := w.Fork()
	defer func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	}()
	if u, rc := userAt(child, 1); rc != _wasiESUCCESS || u != bob || db.usersLists != 2 {
		t.Fatalf("a forked instance's entry 1 = %+v rc=%d after %d lists, want the bob of its parent's walk", u, rc, db.usersLists)
	}
	if u, rc := userAt(w, 0); rc != _wasiESUCCESS || u != carol || db.usersLists != 3 {
		t.Fatalf("entry 0 of a new walk = %+v rc=%d after %d lists, want carol of a third list", u, rc, db.usersLists)
	}

	groupAt := func(i int32) (Group, int32) {
		rc := w.Proc_group_at(m, i, bufPtr, 4096, neededPtr)
		if rc != _wasiESUCCESS {
			return Group{}, rc
		}
		return readGroup(t, m, bufPtr, neededPtr), rc
	}
	if g, rc := groupAt(0); rc != _wasiESUCCESS || g != staff {
		t.Fatalf("group 0 = %+v rc=%d, want staff", g, rc)
	}
	db.groups = []Group{wheel, staff}
	if _, rc := groupAt(1); rc != -_wasiENOENT {
		t.Fatalf("group 1 of a walk of one rc=%d, want -ENOENT", rc)
	}
	if g, rc := groupAt(0); rc != _wasiESUCCESS || g != wheel || db.groupsLists != 2 {
		t.Fatalf("group 0 of a new walk = %+v rc=%d after %d lists, want wheel of a second list", g, rc, db.groupsLists)
	}
}

// readUser decodes the user record a lookup wrote.
func readUser(t *testing.T, m *Module, bufPtr, neededPtr int) User {
	t.Helper()
	r := record(t, m, bufPtr, neededPtr)
	u := User{UID: int32(r.u32()), GID: int32(r.u32())}
	u.Name, u.RealName, u.Home, u.Shell = r.str(), r.str(), r.str(), r.str()
	if len(r.rec) != 0 {
		t.Fatalf("%d bytes left after the user record", len(r.rec))
	}
	return u
}

// readGroup decodes the group record a lookup wrote.
func readGroup(t *testing.T, m *Module, bufPtr, neededPtr int) Group {
	t.Helper()
	r := record(t, m, bufPtr, neededPtr)
	g := Group{GID: int32(r.u32())}
	g.Name = r.str()
	if len(r.rec) != 0 {
		t.Fatalf("%d bytes left after the group record", len(r.rec))
	}
	return g
}

// The user and group lookups answer from the Users; without one, nothing
// is found.
func TestUserAndGroupLookups(t *testing.T) {
	const namePtr, bufPtr, neededPtr = 64, 1024, 512
	w, m := newProcTestStubs(t)
	lookups := func() []int32 {
		copy(m.memory[namePtr:], "alice")
		copy(m.memory[namePtr+16:], "staff")
		return []int32{
			w.Proc_user_by_id(m, 501, bufPtr, 4096, neededPtr),
			w.Proc_user_by_name(m, namePtr, 5, bufPtr, 4096, neededPtr),
			w.Proc_user_at(m, 0, bufPtr, 4096, neededPtr),
			w.Proc_group_by_id(m, 20, bufPtr, 4096, neededPtr),
			w.Proc_group_by_name(m, namePtr+16, 5, bufPtr, 4096, neededPtr),
			w.Proc_group_at(m, 0, bufPtr, 4096, neededPtr),
		}
	}
	for i, rc := range lookups() {
		if rc != -_wasiENOENT {
			t.Fatalf("lookup %d without Users rc=%d, want -ENOENT", i, rc)
		}
	}
	alice := User{Name: "alice", UID: 501, GID: 20, RealName: "Alice", Home: "/home/alice", Shell: "/bin/sh"}
	staff := Group{Name: "staff", GID: 20}
	w.cfg.Users = fakeUsers{user: alice, group: staff}
	if rc := w.Proc_user_by_id(m, 501, bufPtr, 4, neededPtr); rc != -_wasiERANGE {
		t.Fatalf("short buffer rc=%d, want -ERANGE", rc)
	}
	for i, rc := range lookups() {
		if rc != _wasiESUCCESS {
			t.Fatalf("lookup %d rc=%d", i, rc)
		}
	}
	if rc := w.Proc_user_by_name(m, namePtr, 5, bufPtr, 4096, neededPtr); rc != _wasiESUCCESS || readUser(t, m, bufPtr, neededPtr) != alice {
		t.Fatalf("user by name rc=%d record %+v, want %+v", rc, readUser(t, m, bufPtr, neededPtr), alice)
	}
	if rc := w.Proc_group_at(m, 0, bufPtr, 4096, neededPtr); rc != _wasiESUCCESS || readGroup(t, m, bufPtr, neededPtr) != staff {
		t.Fatalf("group 0 rc=%d record %+v, want %+v", rc, readGroup(t, m, bufPtr, neededPtr), staff)
	}
	for _, rc := range []int32{
		w.Proc_user_by_id(m, 502, bufPtr, 4096, neededPtr),
		w.Proc_user_at(m, 1, bufPtr, 4096, neededPtr),
		w.Proc_user_at(m, -1, bufPtr, 4096, neededPtr),
		w.Proc_group_at(m, -1, bufPtr, 4096, neededPtr),
		w.Proc_group_by_id(m, 21, bufPtr, 4096, neededPtr),
	} {
		if rc != -_wasiENOENT {
			t.Fatalf("a lookup that finds nothing rc=%d, want -ENOENT", rc)
		}
	}
	if rc := w.Proc_user_by_name(m, 1<<16-2, 5, bufPtr, 4096, neededPtr); rc != -_wasiEFAULT {
		t.Fatalf("a name past the memory rc=%d, want -EFAULT", rc)
	}
	if rc := w.Proc_group_by_name(m, 1<<16-2, 5, bufPtr, 4096, neededPtr); rc != -_wasiEFAULT {
		t.Fatalf("a group name past the memory rc=%d, want -EFAULT", rc)
	}
	w.cfg.Users = fakeUsers{err: syscall.EIO}
	for i, rc := range lookups() {
		if rc != -_wasiEIO {
			t.Fatalf("lookup %d of failing Users rc=%d, want -EIO", i, rc)
		}
	}
	// An error without an errno is told Errors under the lookup's import.
	var told []string
	w.cfg.Errors = func(op string, err error) { told = append(told, op) }
	w.cfg.Users = fakeUsers{err: errors.New("no database")}
	for i, rc := range lookups() {
		if rc != -_wasiEIO {
			t.Fatalf("lookup %d of Users failing without an errno rc=%d, want -EIO", i, rc)
		}
	}
	want := []string{"proc_user_by_id", "proc_user_by_name", "proc_user_at", "proc_group_by_id", "proc_group_by_name", "proc_group_at"}
	if !slices.Equal(told, want) {
		t.Fatalf("Errors was told %q, want %q", told, want)
	}
}

// HostUsers finds what os/user finds of a user the files do not have, and
// lists the entries of /etc/passwd and /etc/group.
func TestHostUsers(t *testing.T) {
	users := HostUsers(nil)
	if _, err := users.UserByName("no-such-user-in-any-database"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lookup of a missing user: %v, want fs.ErrNotExist", err)
	}
	if _, err := users.GroupByName("no-such-group-in-any-database"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lookup of a missing group: %v, want fs.ErrNotExist", err)
	}
	host, err := user.Current()
	if err != nil {
		t.Skipf("the host has no entry for the current user: %v", err)
	}
	uid, err := strconv.ParseInt(host.Uid, 10, 32)
	if err != nil {
		t.Skipf("the host's user ids are not numbers: %v", err)
	}
	u, err := users.UserByID(int32(uid))
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != host.Username || strconv.Itoa(int(u.GID)) != host.Gid || u.Home != host.HomeDir {
		t.Fatalf("UserByID = %+v, want %+v", u, host)
	}
	if byName, err := users.UserByName(host.Username); err != nil || byName != u {
		t.Fatalf("UserByName = %+v, %v; want %+v", byName, err, u)
	}
	g, err := users.GroupByID(u.GID)
	if err != nil {
		t.Skipf("the host has no entry for the current group: %v", err)
	}
	if byName, err := users.GroupByName(g.Name); err != nil || byName != g {
		t.Fatalf("GroupByName = %+v, %v; want %+v", byName, err, g)
	}
	list, err := users.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/etc/passwd"); err != nil {
		if len(list) != 0 {
			t.Fatalf("ListUsers without /etc/passwd = %+v", list)
		}
		return
	}
	if len(list) == 0 || list[0].Name == "" {
		t.Fatalf("ListUsers = %+v", list)
	}
	if groups, err := users.ListGroups(); err != nil || len(groups) == 0 {
		t.Fatalf("ListGroups = %+v, %v", groups, err)
	}
}

// The host's database is its files, then os/user: an entry of a file is
// found by a lookup as it is listed, the shell and the whole GECOS field
// included, and a lookup the files have no entry for goes to os/user. The
// lines skipped are told the report with the method's name.
func TestHostUsersFilesFirst(t *testing.T) {
	dir := t.TempDir()
	passwd, group := filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	if err := os.WriteFile(passwd, []byte("short:x\nbob:x:7:8:Bob,Room 1:/home/bob:/bin/zsh\nroot:x:0:0:root:/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(group, []byte("bad:x:abc\nstaff:x:8:bob\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	type told struct{ op, line string }
	var reports []told
	users := hostUsers{passwd: passwd, group: group, report: func(op string, err error) {
		reports = append(reports, told{op, err.Error()})
	}}
	bob := User{Name: "bob", UID: 7, GID: 8, RealName: "Bob,Room 1", Home: "/home/bob", Shell: "/bin/zsh"}
	for _, c := range []struct {
		op   string
		find func() (User, error)
	}{
		{"UserByName", func() (User, error) { return users.UserByName("bob") }},
		{"UserByID", func() (User, error) { return users.UserByID(7) }},
	} {
		reports = nil
		if got, err := c.find(); err != nil || got != bob {
			t.Fatalf("%s = %+v, %v; want %+v", c.op, got, err, bob)
		}
		if len(reports) != 1 || reports[0].op != c.op || !strings.HasPrefix(reports[0].line, passwd+":1: ") {
			t.Fatalf("%s told %+v, want line 1 under %s", c.op, reports, c.op)
		}
	}
	reports = nil
	list, err := users.ListUsers()
	if err != nil || len(list) != 2 || list[0] != bob || list[1].Name != "root" {
		t.Fatalf("ListUsers = %+v, %v; want bob and root", list, err)
	}
	if len(reports) != 1 || reports[0].op != "ListUsers" {
		t.Fatalf("ListUsers told %+v", reports)
	}
	staff := Group{Name: "staff", GID: 8}
	reports = nil
	if got, err := users.GroupByName("staff"); err != nil || got != staff {
		t.Fatalf("GroupByName = %+v, %v; want %+v", got, err, staff)
	}
	if got, err := users.GroupByID(8); err != nil || got != staff {
		t.Fatalf("GroupByID = %+v, %v; want %+v", got, err, staff)
	}
	if groups, err := users.ListGroups(); err != nil || !slices.Equal(groups, []Group{staff}) {
		t.Fatalf("ListGroups = %+v, %v", groups, err)
	}
	if ops := []string{"GroupByName", "GroupByID", "ListGroups"}; len(reports) != len(ops) || reports[0].op != ops[0] || reports[1].op != ops[1] || reports[2].op != ops[2] || !strings.HasPrefix(reports[0].line, group+":1: ") {
		t.Fatalf("the group lookups told %+v, want line 1 under %q", reports, ops)
	}
	// What the files do not have is os/user's.
	host, err := user.Current()
	if err != nil {
		t.Skipf("the host has no entry for the current user: %v", err)
	}
	if host.Username == "bob" || host.Username == "root" {
		t.Skipf("the current user %s is one of the test's file", host.Username)
	}
	got, err := users.UserByName(host.Username)
	if err != nil || got.Name != host.Username || got.Home != host.HomeDir || got.Shell != "" {
		t.Fatalf("UserByName(%s) = %+v, %v; want os/user's %+v", host.Username, got, err, host)
	}
	if _, err := users.UserByName("no-such-user-in-any-database"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lookup of a missing user: %v, want fs.ErrNotExist", err)
	}
	// Files the host does not have have no entries, and no report drops
	// what is skipped.
	missing := hostUsers{passwd: filepath.Join(dir, "none"), group: group}
	if list, err := missing.ListUsers(); err != nil || len(list) != 0 {
		t.Fatalf("ListUsers of a missing file = %+v, %v", list, err)
	}
	if groups, err := missing.ListGroups(); err != nil || !slices.Equal(groups, []Group{staff}) {
		t.Fatalf("ListGroups without a report = %+v, %v", groups, err)
	}
	// An error reading a file is the call's.
	unreadable := hostUsers{passwd: dir}
	if _, err := unreadable.UserByName("bob"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("UserByName of a passwd that is a directory: %v, want its read error", err)
	}
}

// A user database that wraps the host's still has the host's report told
// the lines skipped, through the runtime's lookups.
func TestHostUsersReportThroughAWrapper(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("short:x\nbob:x:7:8:Bob:/home/bob:/bin/zsh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var ops []string
	host := hostUsers{passwd: passwd, group: filepath.Join(dir, "group"), report: func(op string, err error) { ops = append(ops, op) }}
	w, m := newProcTestStubs(t)
	w.cfg.Users = struct{ Users }{host}
	if rc := w.Proc_user_at(m, 0, 1024, 4096, 512); rc != _wasiESUCCESS {
		t.Fatalf("Proc_user_at rc=%d", rc)
	}
	if !slices.Equal(ops, []string{"ListUsers"}) {
		t.Fatalf("the wrapped host's report was told %q, want ListUsers", ops)
	}
}

// A database file of the host has an entry a line, without the lines of
// the NIS compatibility syntax, comments, short lines and entries whose
// ids are not numbers.
func TestHostDatabaseEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	data := "# comment\n\n+nis\nshort:x\nbad:x:abc:1:Bad:/:/bin/sh\nroot:x:0:0:root:/root:/bin/sh\nbob:x:7:8:Bob:/home/bob:/bin/zsh\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	var skipped []string
	entries, err := hostDatabaseEntries(path, func(err error) { skipped = append(skipped, err.Error()) }, 7, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].fields[0] != "root" || entries[1].fields[0] != "bob" || !slices.Equal(entries[1].ids, []int32{7, 8}) {
		t.Fatalf("entries = %+v, want root and bob 7 8", entries)
	}
	if len(skipped) != 2 || !strings.HasPrefix(skipped[0], path+":4: ") || !strings.HasPrefix(skipped[1], path+":5: ") {
		t.Fatalf("skipped lines told %q, want lines 4 and 5", skipped)
	}
	if entries, err := hostDatabaseEntries(filepath.Join(t.TempDir(), "none"), nil, 7, 2, 3); err != nil || entries != nil {
		t.Fatalf("a missing file: %+v, %v; want no entries", entries, err)
	}
}

// skippedLine tells the report of a host database the line skipped with
// the method's name, and nobody without a report.
func TestSkippedLine(t *testing.T) {
	var got []string
	skippedLine(func(op string, err error) { got = append(got, op+": "+err.Error()) }, "ListUsers")(errors.New("line 1"))
	if !slices.Equal(got, []string{"ListUsers: line 1"}) {
		t.Fatalf("report told %q", got)
	}
	skippedLine(nil, "ListUsers")(errors.New("dropped"))
}

// The ids of the host's databases are 32-bit ones, unsigned or signed.
func TestParseHostID(t *testing.T) {
	for _, c := range []struct {
		text string
		want int32
		ok   bool
	}{{"0", 0, true}, {"501", 501, true}, {"-2", -2, true}, {"4294967294", -2, true}, {"4294967296", 0, false}, {"-2147483649", 0, false}, {"x", 0, false}} {
		got, err := parseHostID(c.text)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("parseHostID(%q) = %d, %v; want %d, ok %v", c.text, got, err, c.want, c.ok)
		}
	}
}

// fakeSystem is a System with a fixed answer.
type fakeSystem struct {
	name Uname
	err  error
}

func (s fakeSystem) Uname() (Uname, error) { return s.name, s.err }

func TestProcUnameIsTheSystems(t *testing.T) {
	const bufPtr, neededPtr = 1024, 64
	w, m := newProcTestStubs(t)
	if rc := w.Proc_uname(m, bufPtr, 1024, neededPtr); rc != -_wasiENOSYS {
		t.Fatalf("Proc_uname without System rc=%d, want -ENOSYS", rc)
	}
	want := Uname{Sysname: "Plan", Nodename: "node", Release: "1", Version: "v", Machine: "m"}
	w.cfg.System = fakeSystem{name: want}
	if rc := w.Proc_uname(m, bufPtr, 1024, neededPtr); rc != _wasiESUCCESS {
		t.Fatalf("Proc_uname rc=%d", rc)
	}
	r := record(t, m, bufPtr, neededPtr)
	if got := (Uname{r.str(), r.str(), r.str(), r.str(), r.str()}); got != want || len(r.rec) != 0 {
		t.Fatalf("record = %+v + %d bytes, want %+v", got, len(r.rec), want)
	}
	w.cfg.System = fakeSystem{err: errors.ErrUnsupported}
	if rc := w.Proc_uname(m, bufPtr, 1024, neededPtr); rc != -_wasiENOSYS {
		t.Fatalf("Proc_uname of a System that cannot say rc=%d, want -ENOSYS", rc)
	}

	name, err := HostSystem().Uname()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("HostSystem().Uname() on %s: %v, want ErrUnsupported", runtime.GOOS, err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if name.Sysname != map[string]string{"darwin": "Darwin", "linux": "Linux"}[runtime.GOOS] || name.Nodename != host || name.Release == "" || name.Machine == "" {
		t.Fatalf("HostSystem().Uname() = %+v, want this %s host %q", name, runtime.GOOS, host)
	}
}

// fakeServices is a Services of one service.
type fakeServices struct{ service Service }

func (s fakeServices) ServiceByName(name, proto string) (Service, error) {
	if name != s.service.Name || (proto != "" && proto != s.service.Proto) {
		return Service{}, fs.ErrNotExist
	}
	return s.service, nil
}

func (s fakeServices) ServiceByPort(port int, proto string) (Service, error) {
	if port != s.service.Port || (proto != "" && proto != s.service.Proto) {
		return Service{}, fs.ErrNotExist
	}
	return s.service, nil
}

func TestSockServiceIsTheServicesDatabases(t *testing.T) {
	const namePtr, protoPtr, bufPtr, neededPtr = 64, 128, 1024, 512
	w, m := newProcTestStubs(t)
	copy(m.memory[namePtr:], "http")
	copy(m.memory[protoPtr:], "tcp")
	if rc := w.Sock_service(m, namePtr, 4, 0, 0, protoPtr, 3, bufPtr, 1024, neededPtr); rc != -_wasiENOENT {
		t.Fatalf("Sock_service without Services rc=%d, want -ENOENT", rc)
	}
	http := Service{Name: "http", Aliases: []string{"www"}, Port: 80, Proto: "tcp"}
	w.cfg.Services = fakeServices{http}
	read := func() Service {
		r := record(t, m, bufPtr, neededPtr)
		s := Service{Port: int(r.u32()), Name: r.str(), Proto: r.str()}
		for n := r.u32(); n > 0; n-- {
			s.Aliases = append(s.Aliases, r.str())
		}
		return s
	}
	same := func(a, b Service) bool {
		return a.Name == b.Name && a.Port == b.Port && a.Proto == b.Proto && slices.Equal(a.Aliases, b.Aliases)
	}
	if rc := w.Sock_service(m, namePtr, 4, 0, 0, protoPtr, 3, bufPtr, 1024, neededPtr); rc != _wasiESUCCESS || !same(read(), http) {
		t.Fatalf("by name rc=%d", rc)
	}
	if rc := w.Sock_service(m, namePtr, 0, 80, 1, protoPtr, 0, bufPtr, 1024, neededPtr); rc != _wasiESUCCESS || !same(read(), http) {
		t.Fatalf("by port rc=%d", rc)
	}
	if rc := w.Sock_service(m, namePtr, 0, 81, 1, protoPtr, 3, bufPtr, 1024, neededPtr); rc != -_wasiENOENT {
		t.Fatalf("a port without a service rc=%d, want -ENOENT", rc)
	}
	if rc := w.Sock_service(m, 1<<16-2, 4, 0, 0, protoPtr, 3, bufPtr, 1024, neededPtr); rc != -_wasiEFAULT {
		t.Fatalf("a name past the memory rc=%d, want -EFAULT", rc)
	}
}

// The host's services database is read in its order, by name, alias or
// port, for a protocol or any.
func TestHostServices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "services")
	data := "# services\nbroken\nnoport x/tcp\necho 7/tcp\necho 7/udp\nhttp 80/tcp www # web\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		match func(Service) bool
		want  Service
	}{
		{func(s Service) bool { return s.Name == "echo" && s.Proto == "udp" }, Service{Name: "echo", Port: 7, Proto: "udp", Aliases: []string{}}},
		{func(s Service) bool { return slices.Contains(s.Aliases, "www") }, Service{Name: "http", Port: 80, Proto: "tcp", Aliases: []string{"www"}}},
	} {
		got, err := findHostService(path, func(error) {}, c.match)
		if err != nil || got.Name != c.want.Name || got.Port != c.want.Port || got.Proto != c.want.Proto || !slices.Equal(got.Aliases, c.want.Aliases) {
			t.Fatalf("findHostService = %+v, %v; want %+v", got, err, c.want)
		}
	}
	var skipped []string
	if _, err := findHostService(path, func(err error) { skipped = append(skipped, err.Error()) }, func(Service) bool { return false }); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no match: %v, want fs.ErrNotExist", err)
	}
	if len(skipped) != 2 || !strings.HasPrefix(skipped[0], path+":2: ") || !strings.HasPrefix(skipped[1], path+":3: ") {
		t.Fatalf("skipped lines told %q, want lines 2 and 3", skipped)
	}
	var ops []string
	file := hostServices{path: path, report: func(op string, err error) { ops = append(ops, op) }}
	if s, err := file.ServiceByName("www", "tcp"); err != nil || s.Port != 80 {
		t.Fatalf("ServiceByName(www) = %+v, %v", s, err)
	}
	if s, err := file.ServiceByPort(7, "udp"); err != nil || s.Proto != "udp" {
		t.Fatalf("ServiceByPort(7, udp) = %+v, %v", s, err)
	}
	if want := []string{"ServiceByName", "ServiceByName", "ServiceByPort", "ServiceByPort"}; !slices.Equal(ops, want) {
		t.Fatalf("the report was told %q, want %q", ops, want)
	}
	if _, err := parseHostService([]string{"x", "80"}); err == nil {
		t.Fatal("a port without a protocol parsed")
	}
	if _, err := findHostService(filepath.Join(t.TempDir(), "none"), nil, func(Service) bool { return true }); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing file: %v, want fs.ErrNotExist", err)
	}
	w, m := newProcTestStubs(t)
	w.cfg.Services = HostServices(nil)
	copy(m.memory[64:], "no-such-service")
	if rc := w.Sock_service(m, 64, 15, 0, 0, 64, 0, 1024, 1024, 512); rc != -_wasiENOENT {
		t.Fatalf("Sock_service of a missing service rc=%d, want -ENOENT", rc)
	}
	services := HostServices(func(op string, err error) {
		if op != "ServiceByName" && op != "ServiceByPort" {
			t.Errorf("a skipped line of %s told under %q", hostServicesFile, op)
		}
	})
	if _, err := os.Stat(hostServicesFile); err != nil {
		if _, err := services.ServiceByName("echo", ""); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("ServiceByName without %s: %v", hostServicesFile, err)
		}
		return
	}
	byName, err := services.ServiceByName("echo", "tcp")
	if err != nil {
		t.Skipf("the host has no echo service: %v", err)
	}
	byPort, err := services.ServiceByPort(byName.Port, "tcp")
	if err != nil || byPort.Port != byName.Port {
		t.Fatalf("ServiceByPort(%d) = %+v, %v", byName.Port, byPort, err)
	}
}

// fakeNumbering numbers family 1 with two numbers.
type fakeNumbering struct{}

func (fakeNumbering) NumberAt(family, index int32) (string, int64, bool) {
	numbers := []struct {
		name  string
		value int64
	}{{"EPERM", 1}, {"ELONGNAMEOFANERROR", 1 << 40}}
	if family != 1 || index < 0 || int(index) >= len(numbers) {
		return "", 0, false
	}
	return numbers[index].name, numbers[index].value, true
}

func TestHostNumberingIsTheNumberings(t *testing.T) {
	const namePtr, nameLenPtr, valuePtr = 64, 128, 136
	w, m := newProcTestStubs(t)
	if n := w.Host_numbering(m); n != 0 {
		t.Fatalf("Host_numbering without Numbering = %d, want 0", n)
	}
	if rc := w.Host_number_at(m, 1, 0, namePtr, 32, nameLenPtr, valuePtr); rc != -_wasiENOENT {
		t.Fatalf("Host_number_at without Numbering rc=%d, want -ENOENT", rc)
	}
	w.cfg.Numbering = fakeNumbering{}
	if n := w.Host_numbering64(m); n != 1 {
		t.Fatalf("Host_numbering = %d, want 1", n)
	}
	if rc := w.Host_number_at(m, 1, 1, namePtr, 32, nameLenPtr, valuePtr); rc != _wasiESUCCESS {
		t.Fatalf("Host_number_at rc=%d", rc)
	}
	if n := readU32(m.memory, nameLenPtr); string(m.memory[namePtr:namePtr+n]) != "ELONGNAMEOFANERROR" || readU64(m.memory, valuePtr) != 1<<40 {
		t.Fatalf("number 1 = %q %d", m.memory[namePtr:namePtr+n], readU64(m.memory, valuePtr))
	}
	if rc := w.Host_number_at(m, 1, 1, namePtr, 4, nameLenPtr, valuePtr); rc != -_wasiERANGE {
		t.Fatalf("a name longer than its room rc=%d, want -ERANGE", rc)
	}
	if rc := w.Host_number_at(m, 1, 2, namePtr, 32, nameLenPtr, valuePtr); rc != -_wasiENOENT {
		t.Fatalf("past the last number rc=%d, want -ENOENT", rc)
	}
	if rc := w.Host_number_at(m, 1, 0, namePtr, 32, nameLenPtr, 1<<16-4); rc != -_wasiEFAULT {
		t.Fatalf("a value past the memory rc=%d, want -EFAULT", rc)
	}
}

// recordingSyslog is a Syslogger that keeps what it is given.
type recordingSyslog struct {
	opens    []string
	messages []SyslogMessage
	closes   int
	err      error
}

func (l *recordingSyslog) Open(ident string, options, facility int32) error {
	l.opens = append(l.opens, ident)
	return l.err
}

func (l *recordingSyslog) Log(msg SyslogMessage) error {
	l.messages = append(l.messages, msg)
	return l.err
}

func (l *recordingSyslog) Close() error {
	l.closes++
	return l.err
}

func TestSyslogGoesToTheSyslogger(t *testing.T) {
	const identPtr, msgPtr = 64, 128
	w, m := newProcTestStubs(t)
	copy(m.memory[identPtr:], "prog")
	copy(m.memory[msgPtr:], "hello")
	if rc := w.Proc_syslog_open(m, identPtr, 4, SyslogOptPID, 1); rc != -_wasiENOSYS {
		t.Fatalf("openlog without a logger rc=%d, want -ENOSYS", rc)
	}
	if rc := w.Proc_syslog(m, 6, 1, 0, identPtr, 4, msgPtr, 5); rc != -_wasiENOSYS {
		t.Fatalf("syslog without a logger rc=%d, want -ENOSYS", rc)
	}
	if rc := w.Proc_syslog_close(m); rc != -_wasiENOSYS {
		t.Fatalf("closelog without a logger rc=%d, want -ENOSYS", rc)
	}
	l := &recordingSyslog{}
	w.cfg.Syslog = l
	if rc := w.Proc_syslog_open64(m, identPtr, 4, SyslogOptPID, 1); rc != _wasiESUCCESS {
		t.Fatalf("openlog rc=%d", rc)
	}
	if rc := w.Proc_syslog64(m, 6, 1, SyslogOptPID, identPtr, 4, msgPtr, 5); rc != _wasiESUCCESS {
		t.Fatalf("syslog rc=%d", rc)
	}
	if rc := w.Proc_syslog_close64(m); rc != _wasiESUCCESS {
		t.Fatalf("closelog rc=%d", rc)
	}
	want := SyslogMessage{Severity: 6, Facility: 1, Options: SyslogOptPID, Ident: "prog", PID: 42, Message: "hello"}
	if !slices.Equal(l.opens, []string{"prog"}) || !slices.Equal(l.messages, []SyslogMessage{want}) || l.closes != 1 {
		t.Fatalf("logger got opens %v messages %+v closes %d", l.opens, l.messages, l.closes)
	}
	for _, c := range [][2]int32{{8, 1}, {-1, 1}, {6, 24}, {6, -1}} {
		if rc := w.Proc_syslog(m, c[0], c[1], 0, identPtr, 4, msgPtr, 5); rc != -_wasiEINVAL {
			t.Fatalf("severity %d facility %d rc=%d, want -EINVAL", c[0], c[1], rc)
		}
	}
	if rc := w.Proc_syslog(m, 6, 1, 0, identPtr, 4, 1<<16-2, 5); rc != -_wasiEFAULT {
		t.Fatalf("a message past the memory rc=%d, want -EFAULT", rc)
	}
	for _, facility := range []int32{-1, 24} {
		if rc := w.Proc_syslog_open(m, identPtr, 4, 0, facility); rc != -_wasiEINVAL {
			t.Fatalf("openlog of facility %d rc=%d, want -EINVAL", facility, rc)
		}
	}
	if rc := w.Proc_syslog_open(m, 1<<16-2, 4, 0, 1); rc != -_wasiEFAULT {
		t.Fatalf("an ident past the memory rc=%d, want -EFAULT", rc)
	}
	var told []string
	w.cfg.Errors = func(op string, err error) {
		if errors.Is(err, syscall.ECONNREFUSED) {
			told = append(told, op)
		}
	}
	l.err = syscall.ECONNREFUSED
	for i, rc := range []int32{
		w.Proc_syslog_open(m, identPtr, 4, 0, 1),
		w.Proc_syslog(m, 6, 1, 0, identPtr, 4, msgPtr, 5),
		w.Proc_syslog_close(m),
	} {
		if rc != -_wasiECONNREFUSED {
			t.Fatalf("call %d of a failing logger rc=%d, want -ECONNREFUSED", i, rc)
		}
	}
	if want := []string{"proc_syslog_open", "proc_syslog", "proc_syslog_close"}; !slices.Equal(told, want) {
		t.Fatalf("Errors was told %q, want %q", told, want)
	}
}

// The Syslogger is closed when no instance of the fork family uses it any
// longer: an instance uses it from its first openlog or syslog to its
// closelog or CloseAll.
func TestSyslogClosesWithTheLastInstance(t *testing.T) {
	const identPtr, msgPtr = 64, 128
	w, m := newProcTestStubs(t)
	copy(m.memory[identPtr:], "prog")
	copy(m.memory[msgPtr:], "hello")
	l := &recordingSyslog{}
	w.cfg.Syslog = l
	idle := w.Fork()
	if err := idle.CloseAll(); err != nil || l.closes != 0 {
		t.Fatalf("CloseAll of an instance that never logged: %v, %d closes", err, l.closes)
	}
	// An openlog starts the use, and a syslog after it is the same use.
	alone := w.Fork()
	for i, logs := range []bool{false, true} {
		if rc := alone.Proc_syslog_open(m, identPtr, 4, 0, 1); rc != _wasiESUCCESS {
			t.Fatalf("openlog rc=%d", rc)
		}
		if logs {
			if rc := alone.Proc_syslog(m, 6, 1, 0, identPtr, 4, msgPtr, 5); rc != _wasiESUCCESS {
				t.Fatalf("syslog rc=%d", rc)
			}
		}
		if rc := alone.Proc_syslog_close(m); rc != _wasiESUCCESS || l.closes != i+1 {
			t.Fatalf("the closelog of the only instance that uses it (syslog %v) rc=%d, %d closes; want %d", logs, rc, l.closes, i+1)
		}
	}
	if err := alone.CloseAll(); err != nil || l.closes != 2 {
		t.Fatalf("CloseAll after closelog: %v, %d closes; want 2", err, l.closes)
	}
	l.closes = 0
	if rc := w.Proc_syslog_open(m, identPtr, 4, 0, 1); rc != _wasiESUCCESS {
		t.Fatalf("openlog rc=%d", rc)
	}
	child := w.Fork()
	if rc := child.Proc_syslog(m, 6, 1, 0, identPtr, 4, msgPtr, 5); rc != _wasiESUCCESS {
		t.Fatalf("the child's syslog rc=%d", rc)
	}
	if rc := w.Proc_syslog_close(m); rc != _wasiESUCCESS || l.closes != 0 {
		t.Fatalf("the parent's closelog rc=%d, %d closes; want none while the child logs", rc, l.closes)
	}
	if rc := w.Proc_syslog_close(m); rc != _wasiESUCCESS || l.closes != 0 {
		t.Fatalf("a second closelog rc=%d, %d closes; want none", rc, l.closes)
	}
	if rc := child.Proc_syslog_close(m); rc != _wasiESUCCESS || l.closes != 1 {
		t.Fatalf("the last closelog rc=%d, %d closes; want 1", rc, l.closes)
	}
	if rc := child.Proc_syslog(m, 6, 1, 0, identPtr, 4, msgPtr, 5); rc != _wasiESUCCESS {
		t.Fatalf("a syslog after the close rc=%d", rc)
	}
	if err := child.CloseAll(); err != nil || l.closes != 2 {
		t.Fatalf("CloseAll of the last instance that logs: %v, %d closes; want 2", err, l.closes)
	}
	if err := child.CloseAll(); err != nil || l.closes != 2 {
		t.Fatalf("a second CloseAll: %v, %d closes; want 2", err, l.closes)
	}
}

// The line of a message for the local syslog daemon has the message's own
// facility, severity, ident and process id, the last only with LOG_PID.
func TestHostSyslogLine(t *testing.T) {
	at := time.Date(2024, 7, 5, 9, 8, 7, 0, time.Local)
	for _, c := range []struct {
		msg  SyslogMessage
		want string
	}{
		{SyslogMessage{Severity: 6, Facility: 1, Options: SyslogOptPID, Ident: "prog", PID: 7, Message: "hello"}, "<14>Jul  5 09:08:07 prog[7]: hello\n"},
		{SyslogMessage{Severity: 3, Facility: 16, Ident: "other", PID: 7, Message: "done\n"}, "<131>Jul  5 09:08:07 other: done\n"},
		{SyslogMessage{Severity: 7, Facility: 1, Message: "x"}, "<15>Jul  5 09:08:07 " + os.Args[0] + ": x\n"},
	} {
		if got := hostSyslogLine(c.msg, at); got != c.want {
			t.Errorf("hostSyslogLine(%+v) = %q, want %q", c.msg, got, c.want)
		}
	}
}

// HostSyslog connects to the local syslog daemon, where there is one, at
// the first message.
func TestHostSyslog(t *testing.T) {
	l := HostSyslog()
	if err := l.Open("wasm2go-test", SyslogOptPID, 1); err != nil {
		t.Fatal(err)
	}
	if l.(*hostSyslogger).conn != nil {
		t.Fatal("an openlog without LOG_NDELAY connected")
	}
	err := l.Log(SyslogMessage{Severity: 7, Facility: 1, Ident: "wasm2go-test", Message: "a debug message of a test"})
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("Log on %s: %v, want ErrUnsupported", runtime.GOOS, err)
		}
		return
	}
	if err != nil {
		// A socket of a daemon that is not running refuses the connection;
		// any other error with a socket there is the logger's.
		for _, path := range []string{"/dev/log", "/var/run/syslog", "/var/run/log"} {
			fi, statErr := os.Stat(path)
			if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
				t.Fatal(statErr)
			}
			if statErr == nil && fi.Mode().Type() == fs.ModeSocket && !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatalf("Log with the daemon's socket %s there: %v", path, err)
			}
		}
		t.Skipf("no syslog daemon to connect to: %v", err)
	}
	if err := l.Log(SyslogMessage{Severity: 8, Facility: 1}); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Log of severity 8: %v, want EINVAL", err)
	}
	if err := l.Open("x", 0, 24); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Open of facility 24: %v, want EINVAL", err)
	}

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

// modeBitsFS is an FS that is no AccessFS.
type modeBitsFS struct{ FS }

// access by the mode bits of a file of an FS that is no AccessFS, for the
// ids of the Process: the owner's bits for the owner, the group's for a
// member, the others' for the rest, and anything but running a file
// without an x bit for user 0.
func TestPathAccessByTheModeBits(t *testing.T) {
	w, m, fsys := memTestStubs(t)
	w.cfg.FS = modeBitsFS{fsys}
	if err := fsys.WriteFile("f", nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := fsys.MkdirAll("d", 0o700); err != nil {
		t.Fatal(err)
	}
	path, pathLen := putPath(m, 900, "f")
	const fOK, xOK, wOK, rOK = 0, 1, 2, 4
	// An isolated process is user 0, and a MemFS file is owned by 0.
	for _, c := range []struct {
		amode, want int32
	}{{fOK, 0}, {rOK | wOK, 0}, {xOK, -_wasiEACCES}} {
		if rc := w.Path_access(m, path, pathLen, c.amode, 0); rc != c.want {
			t.Errorf("access(f, %d) of user 0 rc=%d, want %d", c.amode, rc, c.want)
		}
	}
	dir, dirLen := putPath(m, 950, "d")
	if rc := w.Path_access(m, dir, dirLen, xOK, 0); rc != _wasiESUCCESS {
		t.Errorf("search of a directory by user 0 rc=%d", rc)
	}
	p := newIDsProcess()
	p.ids = ProcessIDs{UID: 501, EUID: 0, GID: 20, EGID: 0}
	w.cfg.Process = p
	if rc := w.Path_access(m, path, pathLen, rOK, 0); rc != -_wasiEACCES {
		t.Errorf("read by another user rc=%d, want -EACCES", rc)
	}
	if rc := w.Path_access(m, path, pathLen, rOK|wOK, 1 /* AT_EACCESS */); rc != _wasiESUCCESS {
		t.Errorf("read and write by the effective user 0 rc=%d", rc)
	}
	p.groups = []int32{0}
	w.cfg.Process = p
	if rc := w.Path_access(m, path, pathLen, rOK, 0); rc != _wasiESUCCESS {
		t.Errorf("read by a member of the file's group rc=%d", rc)
	}
	if rc := w.Path_access(m, path, pathLen, wOK, 0); rc != -_wasiEACCES {
		t.Errorf("write by a member of the file's group rc=%d, want -EACCES", rc)
	}
	p.groupErr = syscall.EIO
	w.cfg.Process = p
	if rc := w.Path_access(m, path, pathLen, rOK, 0); rc != -_wasiEIO {
		t.Errorf("access with groups that cannot be read rc=%d, want -EIO", rc)
	}
	missing, missingLen := putPath(m, 990, "none")
	if rc := w.Path_access(m, missing, missingLen, fOK, 0); rc != -_wasiENOENT {
		t.Errorf("access of a missing file rc=%d, want -ENOENT", rc)
	}
	if rc := w.Path_access(m, path, pathLen, 8, 0); rc != -_wasiEINVAL {
		t.Errorf("an unknown amode rc=%d, want -EINVAL", rc)
	}
	if rc := w.Path_access(m, path, pathLen, rOK, 2); rc != -_wasiEINVAL {
		t.Errorf("unknown flags rc=%d, want -EINVAL", rc)
	}
	if rc := w.Path_access64(m, 1<<16, pathLen, rOK, 0); rc != -_wasiEFAULT {
		t.Errorf("a path past the memory rc=%d, want -EFAULT", rc)
	}
	var seen []string
	w.cfg.FS = policyFS{FS: fsys, allow: func(string, bool) bool { return false }, seen: &seen}
	if rc := w.Path_access(m, path, pathLen, rOK, 0); rc != -_wasiEACCES {
		t.Errorf("access of a file a policy refuses rc=%d, want -EACCES", rc)
	}
}

// A file of the whole host filesystem is asked about by the host.
func TestPathAccessAsksTheHost(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	w.cfg.FS = osFS{}
	path, pathLen := putPath(m, 900, hostRelative(t, filepath.Join(dir, "f")))
	if rc := w.Path_access(m, path, pathLen, 4|2, 0); rc != _wasiESUCCESS {
		t.Fatalf("read and write of an own file rc=%d", rc)
	}
	if rc := w.Path_access(m, path, pathLen, 4|2, 1); rc != _wasiESUCCESS {
		t.Fatalf("read and write of an own file by the effective ids rc=%d", rc)
	}
	if os.Getuid() != 0 {
		if rc := w.Path_access(m, path, pathLen, 1, 0); rc != -_wasiEACCES {
			t.Fatalf("run of a file without an x bit rc=%d, want -EACCES", rc)
		}
	}
	missing, missingLen := putPath(m, 1000, hostRelative(t, filepath.Join(dir, "none")))
	if rc := w.Path_access(m, missing, missingLen, 0, 0); rc != -_wasiENOENT {
		t.Fatalf("access of a missing file rc=%d, want -ENOENT", rc)
	}
}

// flock of a file of an FS, by its LockFS.
func exerciseFlock(t *testing.T, w *WasiStubs, m *Module) {
	t.Helper()
	first := openTestFile(t, w, "lock")
	second := openTestFile(t, w, "lock")
	for _, c := range []struct {
		name     string
		fd, lock int32
		want     int32
	}{
		{"shared", first, 1, 0},
		{"shared beside a shared one", second, 1, 0},
		{"exclusive beside a shared one", second, 2, -_wasiEAGAIN},
		{"unlock", first, 0, 0},
		{"exclusive alone", second, 2, 0},
		{"shared beside an exclusive one", first, 1, -_wasiEAGAIN},
		{"downgrade", second, 1, 0},
		{"shared beside the downgraded one", first, 1, 0},
	} {
		if rc := w.Fd_flock(m, c.fd, c.lock, 0); rc != c.want {
			t.Fatalf("%s: rc=%d, want %d", c.name, rc, c.want)
		}
	}
	// Closing a descriptor removes its lock.
	closeTestFd(t, w, m, first)
	closeTestFd(t, w, m, second)
	third := openTestFile(t, w, "lock")
	if rc := w.Fd_flock(m, third, 2, 0); rc != 0 {
		t.Fatalf("exclusive lock after the others closed rc=%d", rc)
	}
	if rc := w.Fd_flock(m, 99, 1, 0); rc != -_wasiEBADF {
		t.Fatalf("lock of a closed fd rc=%d, want -EBADF", rc)
	}
	if rc := w.Fd_flock64(m, third, 7, 0); rc != -_wasiEINVAL {
		t.Fatalf("unknown lock kind rc=%d, want -EINVAL", rc)
	}
	closeTestFd(t, w, m, third)
}

func TestFlockOnMemFS(t *testing.T) {
	w, m, fsys := memTestStubs(t)
	if err := fsys.WriteFile("lock", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	exerciseFlock(t, w, m)
	// A conversion removes the lock held first, as flock(2) does: one
	// that may not wait and fails leaves the file without a lock, and
	// two shared locks that both convert to exclusive ones do not wait
	// for each other.
	first := openTestFile(t, w, "lock")
	second := openTestFile(t, w, "lock")
	for _, c := range []struct {
		name     string
		fd, lock int32
		want     int32
	}{
		{"shared", first, 1, 0},
		{"shared beside it", second, 1, 0},
		{"shared again", second, 1, 0},
		{"exclusive beside a shared one", first, 2, -_wasiEAGAIN},
		{"exclusive once the failed conversion removed the first lock", second, 2, 0},
	} {
		if rc := w.Fd_flock(m, c.fd, c.lock, 0); rc != c.want {
			t.Fatalf("%s: rc=%d, want %d", c.name, rc, c.want)
		}
	}
	closeTestFd(t, w, m, first)
	closeTestFd(t, w, m, second)
	if err := fsys.Flock(&memFile{fsys: NewMemFS()}, flockShared); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("Flock of another MemFS's file: %v, want EBADF", err)
	}
	f, err := fsys.OpenFile("lock", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := fsys.Flock(f, 3); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Flock of an unknown operation: %v, want EINVAL", err)
	}
}

// withoutLocks is an FS that is no LockFS.
type withoutLocks struct{ FS }

// A waiting flock is granted once the lock is free; a signal ends the
// wait with EINTR, and the lock the call takes later is removed before
// the descriptor takes one again.
func TestFlockWaits(t *testing.T) {
	w, m, fsys := memTestStubs(t)
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d", rc)
	}
	setDispositions(t, w, m, signalMask(wasiSIGUSR1), 0, 0)
	if err := fsys.WriteFile("lock", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	holder := openTestFile(t, w, "lock")
	waiter := openTestFile(t, w, "lock")
	if rc := w.Fd_flock(m, holder, 2, 0); rc != _wasiESUCCESS {
		t.Fatalf("exclusive lock rc=%d", rc)
	}
	postWhenBlocked(w, wasiSIGUSR1)
	if rc := w.Fd_flock(m, waiter, 2, 1); rc != -_wasiEINTR {
		t.Fatalf("waiting lock rc=%d, want -EINTR", rc)
	}
	takeSignals(t, w, m)
	// The interrupted call took nothing: the holder's lock is in the way.
	if rc := w.Fd_flock(m, waiter, 1, 0); rc != -_wasiEAGAIN {
		t.Fatalf("lock that may not wait beside the holder's rc=%d, want -EAGAIN", rc)
	}
	released := whenBlocked(w, func() { w.Fd_flock(newForkTestModule(), holder, 0, 0) })
	if rc := w.Fd_flock(m, waiter, 2, 1); rc != _wasiESUCCESS {
		t.Fatalf("waiting lock after release rc=%d", rc)
	}
	<-released
	// The lock is the waiter's, not one removed with the late one.
	if rc := w.Fd_flock(m, holder, 1, 0); rc != -_wasiEAGAIN {
		t.Fatalf("lock beside the granted one rc=%d, want -EAGAIN", rc)
	}
	if rc := w.Fd_flock(m, waiter, 0, 1); rc != _wasiESUCCESS {
		t.Fatalf("unlock rc=%d", rc)
	}

	// A standard stream that is not a file has no other opener.
	if rc := w.Fd_flock(m, 1, 2, 0); rc != _wasiESUCCESS {
		t.Fatalf("lock of a buffer-backed stdout rc=%d", rc)
	}
	// A socket has no file to lock.
	w.mu.Lock()
	sock := addTestFD(w, &wasiOpen{isSocket: true})
	w.mu.Unlock()
	if rc := w.Fd_flock(m, sock, 2, 0); rc != -_wasiEINVAL {
		t.Fatalf("lock of a socket rc=%d, want -EINVAL", rc)
	}
	// An FS that is no LockFS has no locks.
	w.cfg.FS = withoutLocks{fsys}
	if rc := w.Fd_flock(m, waiter, 2, 0); rc != -_wasiENOSYS {
		t.Fatalf("lock of a file of an FS without locks rc=%d, want -ENOSYS", rc)
	}
}

// A guest ended by SIGKILL while it waits for a lock of a MemFS file
// leaves nothing behind: the wait ended with the guest's, and took
// nothing.
func TestFlockOfAGuestEndedWhileItWaits(t *testing.T) {
	w, m, fsys := memTestStubs(t)
	if err := fsys.WriteFile("lock", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	holder := openTestFile(t, w, "lock")
	waiter := openTestFile(t, w, "lock")
	if rc := w.Fd_flock(m, holder, 2, 0); rc != _wasiESUCCESS {
		t.Fatalf("exclusive lock rc=%d", rc)
	}
	w.PostSignal(wasiSIGKILL)
	func() {
		defer func() {
			var sigErr *WasiSignalError
			if err, _ := recover().(error); !errors.As(err, &sigErr) || sigErr.Signal != wasiSIGKILL {
				t.Fatalf("the waiting lock ended with %v, want a WasiSignalError for SIGKILL", err)
			}
		}()
		w.Fd_flock(m, waiter, 2, 1)
	}()
	w.mu.Lock()
	op := w.openLocked(waiter)
	w.mu.Unlock()
	op.mu.Lock()
	pending := op.lockPending
	op.mu.Unlock()
	if pending != nil {
		t.Fatal("the wait goes on after the guest ended")
	}
	if rc := w.Fd_flock(m, holder, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("unlock rc=%d", rc)
	}
	if rc := w.Fd_flock(m, waiter, 2, 0); rc != _wasiESUCCESS {
		t.Fatalf("exclusive lock of the waiter's descriptor after the unlock rc=%d", rc)
	}
}

// Two sharers of a descriptor wait for the same lock; a signal ends one
// wait. The lock it is granted later is not removed: the other wait has
// it.
func TestFlockOfASharedDescriptorWaitedForTwice(t *testing.T) {
	w, m, fsys := memTestStubs(t)
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d", rc)
	}
	// The thread that registered first blocks the signal: it goes to a
	// thread that waits.
	setDispositions(t, w, m, signalMask(wasiSIGUSR1), 0, signalMask(wasiSIGUSR1))
	if err := fsys.WriteFile("lock", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	holder := openTestFile(t, w, "lock")
	waiter := openTestFile(t, w, "lock")
	if rc := w.Fd_dup(m, waiter, 900); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup rc=%d", rc)
	}
	sharer := int32(readU32(m.memory, 900))
	if rc := w.Fd_flock(m, holder, 2, 0); rc != _wasiESUCCESS {
		t.Fatalf("exclusive lock rc=%d", rc)
	}
	results := make(chan int32, 2)
	for _, fd := range []int32{waiter, sharer} {
		thread := signalWaiter(t, w)
		go func() { results <- w.Fd_flock(thread, fd, 2, 1) }()
	}
	awaitBlockedCalls(w, 2)
	w.PostSignal(wasiSIGUSR1)
	if rc := <-results; rc != -_wasiEINTR {
		t.Fatalf("the first wait to end rc=%d, want -EINTR", rc)
	}
	if rc := w.Fd_flock(m, holder, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("unlock rc=%d", rc)
	}
	if rc := <-results; rc != _wasiESUCCESS {
		t.Fatalf("the other wait rc=%d", rc)
	}
	w.mu.Lock()
	op := w.openLocked(waiter)
	w.mu.Unlock()
	op.mu.Lock()
	released := op.lockPending
	op.mu.Unlock()
	if released != nil {
		<-released
	}
	if rc := w.Fd_flock(m, holder, 1, 0); rc != -_wasiEAGAIN {
		t.Fatalf("lock beside the granted one rc=%d, want -EAGAIN: the late grant removed it", rc)
	}
}

// A call the waiter took the result of is not undone; one the waiter left
// is, by whichever of the two comes last.
func TestDetachedCall(t *testing.T) {
	var undone []error
	call := newDetachedCall(func(err error) { undone = append(undone, err) })
	call.finish(nil)
	if err := call.take(); err != nil {
		t.Fatal(err)
	}
	call.leave()
	if len(undone) != 0 {
		t.Fatalf("a taken call was undone: %v", undone)
	}
	call = newDetachedCall(func(err error) { undone = append(undone, err) })
	call.leave()
	call.finish(syscall.EIO)
	call = newDetachedCall(func(err error) { undone = append(undone, err) })
	call.finish(nil)
	call.leave()
	call.leave()
	if !slices.Equal(undone, []error{syscall.EIO, nil}) {
		t.Fatalf("undone = %v, want [EIO <nil>]", undone)
	}
}

// fd_lock is the host's record locks: a descriptor of no file of the host
// has none.
func TestFdLockArguments(t *testing.T) {
	w, m, fsys := memTestStubs(t)
	if err := fsys.WriteFile("f", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fd := openTestFile(t, w, "f")
	const lockOff = 200
	put := func(typ, whence int32) {
		clear(m.memory[lockOff : lockOff+32])
		binary.LittleEndian.PutUint32(m.memory[lockOff:], uint32(typ))
		binary.LittleEndian.PutUint32(m.memory[lockOff+4:], uint32(whence))
	}
	put(1, 0)
	if rc := w.Fd_lock(m, fd, recordLockSet, lockOff); rc != -_wasiENOTSUP {
		t.Fatalf("record lock of a MemFS file rc=%d, want -ENOTSUP", rc)
	}
	for _, c := range [][3]int32{{3, 0, recordLockSet}, {1, 3, recordLockSet}, {1, 0, 3}, {-1, 0, recordLockGet}} {
		put(c[0], c[1])
		if rc := w.Fd_lock(m, fd, c[2], lockOff); rc != -_wasiEINVAL {
			t.Fatalf("type %d whence %d cmd %d rc=%d, want -EINVAL", c[0], c[1], c[2], rc)
		}
	}
	put(1, 0)
	if rc := w.Fd_lock(m, 99, recordLockSet, lockOff); rc != -_wasiEBADF {
		t.Fatalf("a closed number rc=%d, want -EBADF", rc)
	}
	if rc := w.Fd_lock64(m, fd, recordLockSet, 1<<16-8); rc != -_wasiEFAULT {
		t.Fatalf("a record past the memory rc=%d, want -EFAULT", rc)
	}
}

// path_mkfifo needs an FS that makes FIFOs.
func TestPathMkfifoWithoutFIFOs(t *testing.T) {
	w, m, _ := memTestStubs(t)
	path, pathLen := putPath(m, 900, "q")
	if rc := w.Path_mkfifo(m, path, pathLen, 0o600); rc != -_wasiENOSYS {
		t.Fatalf("Path_mkfifo in memory rc=%d, want -ENOSYS", rc)
	}
	if rc := w.Path_mkfifo64(m, 1<<16, pathLen, 0o600); rc != -_wasiEFAULT {
		t.Fatalf("a path past the memory rc=%d, want -EFAULT", rc)
	}
}

// The errno of an error of a configured value is that of the syscall.Errno
// it carries; errors.ErrUnsupported without one is ENOSYS.
func TestConfiguredValueErrno(t *testing.T) {
	for _, c := range []struct {
		err  error
		want int32
	}{
		{errors.ErrUnsupported, _wasiENOSYS},
		{fmt.Errorf("no: %w", errors.ErrUnsupported), _wasiENOSYS},
		{syscall.ENOTSUP, _wasiENOTSUP},
		{&os.SyscallError{Syscall: "setuid", Err: syscall.EPERM}, _wasiEPERM},
		{fs.ErrNotExist, _wasiENOENT},
	} {
		if got := errnoOfError(c.err); got != c.want {
			t.Errorf("errnoOfError(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

// An error no caller can be given goes to WASIConfig.Errors, and is
// dropped without one.
func TestReportErrorGoesToErrors(t *testing.T) {
	w, _ := newProcTestStubs(t)
	w.reportError("close", syscall.EBADF)
	var got []string
	w.cfg.Errors = func(op string, err error) { got = append(got, op+": "+err.Error()) }
	w.reportError("close", syscall.EBADF)
	if want := []string{"close: " + syscall.EBADF.Error()}; !slices.Equal(got, want) {
		t.Fatalf("Errors was told %q, want %q", got, want)
	}
}

// A forked instance's guest changes its own nice value, as Linux's calls
// change a process's, and keeps its ids and groups, whatever the
// ProcessChanges is: a change of them that leaves them as they are
// succeeds, any other gets EPERM. The ProcessChanges is not reached and the
// root's guest reads what it read.
func TestForkedInstanceChangesItsOwnProcess(t *testing.T) {
	const out = 64
	w, m := newProcTestStubs(t)
	p := newIDsProcess()
	p.ids = ProcessIDs{PID: 7, UID: 1000, EUID: 1000, GID: 100, EGID: 100}
	p.groups = []int32{100}
	p.nice = 0
	w.cfg.Process = p
	changes := &recordedChanges{}
	w.cfg.ProcessChanges = changes
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	cm := newForkTestModule()
	for _, c := range []struct {
		call    IDCall
		a, b, c int32
		want    int32
	}{
		{IDSetuid, 0, -1, -1, -_wasiEPERM},
		{IDSeteuid, 0, -1, -1, -_wasiEPERM},
		{IDSetreuid, 2000, -1, -1, -_wasiEPERM},
		{IDSetresuid, -1, 1000, -1, _wasiESUCCESS},
		{IDSetgid, 100, -1, -1, _wasiESUCCESS},
		{IDSetgid, -1, -1, -1, -_wasiEINVAL},
		{IDSeteuid, 1000, -1, -1, _wasiESUCCESS},
		{IDSetreuid, 1000, 1000, -1, _wasiESUCCESS},
		{IDSetresuid, 0, -1, -1, -_wasiEPERM},
		{IDSetregid, -1, 100, -1, _wasiESUCCESS},
	} {
		if rc := child.Proc_setids(cm, int32(c.call), c.a, c.b, c.c); rc != c.want {
			t.Fatalf("copy's Proc_setids(%d, %d, %d, %d) rc=%d, want %d", c.call, c.a, c.b, c.c, rc, c.want)
		}
	}
	if rc := child.Proc_setgroups(cm, 64, 0); rc != -_wasiEPERM {
		t.Fatalf("an unprivileged copy's setgroups rc=%d, want -EPERM", rc)
	}
	if rc := child.Proc_priority(cm, 0, 0, 1, 5, out); rc != _wasiESUCCESS || readU32(cm.memory, out) != 5 {
		t.Fatalf("copy's nice(5) rc=%d nice=%d, want 5", rc, readU32(cm.memory, out))
	}
	if rc := child.Proc_priority(cm, 0, 0, 1, 3, out); rc != -_wasiEACCES {
		t.Fatalf("an unprivileged copy lowering its nice value rc=%d, want -EACCES", rc)
	}
	if rc := child.Proc_priority(cm, 2, 1000, 1, 5, out); rc != -_wasiEPERM {
		t.Fatalf("a copy setting a user's priority rc=%d, want -EPERM", rc)
	}
	if rc := w.Proc_priority(m, 0, 0, 0, 0, out); rc != _wasiESUCCESS || readU32(m.memory, out) != 0 {
		t.Fatalf("the root's nice value rc=%d nice=%d, want the Process's 0", rc, readU32(m.memory, out))
	}
	if len(changes.changes)+len(changes.set)+len(changes.prios) != 0 {
		t.Fatalf("the ProcessChanges was reached by a copy: %+v", changes)
	}
	// A copy of the copy starts with what it changed.
	grand := child.Fork()
	t.Cleanup(func() {
		if err := grand.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	gm := newForkTestModule()
	if rc := grand.Proc_priority(gm, 0, 0, 0, 0, out); rc != _wasiESUCCESS || readU32(gm.memory, out) != 5 {
		t.Fatalf("the nice value of the copy's copy rc=%d nice=%d, want the copy's 5", rc, readU32(gm.memory, out))
	}
	if got, want := procIDs(t, grand), procIDs(t, child); got != want {
		t.Fatalf("the copy's copy's ids = %v, want the copy's %v", got, want)
	}

	// A privileged copy keeps its ids and groups too.
	p.ids = ProcessIDs{PID: 7}
	p.groups = []int32{100, 5}
	w.cfg.Process = p
	root := w.Fork()
	t.Cleanup(func() {
		if err := root.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	rm := newForkTestModule()
	binary.LittleEndian.PutUint32(rm.memory[64:], 5)
	if rc := root.Proc_setgroups(rm, 64, 1); rc != -_wasiEPERM {
		t.Fatalf("a privileged copy's setgroups of other groups rc=%d, want -EPERM", rc)
	}
	binary.LittleEndian.PutUint32(rm.memory[68:], 100)
	if rc := root.Proc_setgroups(rm, 64, 2); rc != _wasiESUCCESS {
		t.Fatalf("a privileged copy's setgroups of its groups rc=%d", rc)
	}
	if rc := root.Proc_setids(rm, int32(IDSetuid), 5, -1, -1); rc != -_wasiEPERM {
		t.Fatalf("a privileged copy's setuid(5) rc=%d, want -EPERM", rc)
	}
	if rc := root.Proc_setids(rm, int32(IDSetuid), 0, -1, -1); rc != _wasiESUCCESS {
		t.Fatalf("a privileged copy's setuid(0) rc=%d", rc)
	}
	if got := procIDs(t, root); got != [6]uint32{7, 0, 0, 0, 0, 0} {
		t.Fatalf("the copy's ids = %v, want the Process's", got)
	}
	if rc := root.Proc_groups(rm, 256, 4, 128); rc != _wasiESUCCESS || readU32(rm.memory, 128) != 2 || readU32(rm.memory, 256) != 100 || readU32(rm.memory, 260) != 5 {
		t.Fatalf("the copy's groups rc=%d, want the Process's [100 5]", rc)
	}
	if len(changes.changes)+len(changes.set)+len(changes.prios) != 0 {
		t.Fatalf("the ProcessChanges was reached by a copy: %+v", changes)
	}
}

// NewWASI refuses a ProcessChanges without a Process, which would read none
// of its changes.
func TestNewWASIRefusesProcessChangesWithoutProcess(t *testing.T) {
	defer func() {
		err, isErr := recover().(error)
		if !isErr || !strings.Contains(err.Error(), "WASIConfig.ProcessChanges") || !strings.Contains(err.Error(), "WASIConfig.Process") {
			t.Fatalf("NewWASI panicked with %v, want an error naming both fields", err)
		}
	}()
	NewWASI(WASIConfig{ProcessChanges: &recordedChanges{}})
	t.Fatal("NewWASI returned")
}

// HostProcessChanges's SetUmask is umask(2): set to the umask in effect, it
// returns that umask.
func TestHostProcessChangesSetUmask(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		if _, err := HostProcessChanges().SetUmask(0o022); !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("SetUmask on %s: %v, want ErrUnsupported", runtime.GOOS, err)
		}
		return
	}
	current := hostUmask(t)
	prev, err := HostProcessChanges().SetUmask(current)
	if err != nil || prev != current {
		t.Fatalf("SetUmask(%o) = %o, %v, want %o", current, prev, err, current)
	}
}

// sharedProcess is a Process whose values are those of state, shared by
// every copy of it, as the host process's are by the instances of a fork
// family. lock, when it is set, is called by IDs.
type sharedProcess struct {
	isolatedProcess
	state *sharedState
}

type sharedState struct {
	ids    ProcessIDs
	groups []int32
	nice   int32
	lock   func()
}

func (p sharedProcess) IDs() ProcessIDs {
	if p.state.lock != nil {
		p.state.lock()
	}
	return p.state.ids
}
func (p sharedProcess) Groups() ([]int32, error)                 { return p.state.groups, nil }
func (p sharedProcess) Priority(which, who int32) (int32, error) { return p.state.nice, nil }

// A copy starts with the ids, groups and nice value its parent's guest had:
// a later change of the root's, which reaches the host process, is not the
// copy's. The Process is asked without the instance's lock held.
func TestForkedInstanceStartsWithTheParentsValues(t *testing.T) {
	const out = 64
	w, _ := newProcTestStubs(t)
	state := &sharedState{ids: ProcessIDs{PID: 7, UID: 1000, EUID: 1000, GID: 100, EGID: 100}, groups: []int32{100}, nice: 2}
	w.cfg.Process = sharedProcess{state: state}
	w.cfg.ProcessChanges = &recordedChanges{}
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	cm := newForkTestModule()
	// The root's change reaches the host process.
	state.ids.UID, state.ids.EUID, state.groups, state.nice = 2000, 2000, []int32{200}, 9
	if got := procIDs(t, child); got[2] != 1000 || got[3] != 1000 {
		t.Fatalf("the copy's uid and euid = %d, %d, want its parent's 1000", got[2], got[3])
	}
	if rc := child.Proc_groups(cm, 256, 4, 128); rc != _wasiESUCCESS || readU32(cm.memory, 128) != 1 || readU32(cm.memory, 256) != 100 {
		t.Fatalf("the copy's groups rc=%d, want its parent's [100]", rc)
	}
	if rc := child.Proc_priority(cm, 0, 0, 0, 0, out); rc != _wasiESUCCESS || readU32(cm.memory, out) != 2 {
		t.Fatalf("the copy's nice value rc=%d nice=%d, want its parent's 2", rc, readU32(cm.memory, out))
	}
	if got := procIDs(t, w); got[2] != 2000 {
		t.Fatalf("the root's uid = %d, want the host process's 2000", got[2])
	}
	state.lock = func() {
		if !child.mu.TryLock() {
			t.Error("the Process is asked with the instance's lock held")
			return
		}
		child.mu.Unlock()
	}
	if rc := child.Proc_setids(cm, int32(IDSeteuid), 1000, -1, -1); rc != _wasiESUCCESS {
		t.Fatalf("the copy's seteuid rc=%d", rc)
	}
}

// With the host's ProcessChanges, whose credentials the kernel checks for
// every instance of the family, a copy keeps the host process's ids and
// groups: EPERM for a change of them.
func TestForkedInstanceChangesNoHostCredentials(t *testing.T) {
	w, _ := newProcTestStubs(t)
	w.cfg.Process = HostProcessUmask(0o022)
	w.cfg.ProcessChanges = HostProcessChanges()
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	cm := newForkTestModule()
	uid := int32(os.Getuid())
	if rc := child.Proc_setids(cm, int32(IDSetuid), uid, -1, -1); rc != _wasiESUCCESS {
		t.Fatalf("a copy's setuid to its own uid rc=%d", rc)
	}
	if rc := child.Proc_setids(cm, int32(IDSetuid), uid+1, -1, -1); rc != -_wasiEPERM {
		t.Fatalf("a copy's setuid to another uid rc=%d, want -EPERM", rc)
	}
	// Windows has no groups (os.Getgroups fails): any group is another.
	groups, err := os.Getgroups()
	if err != nil && runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	other := int32(1)
	for _, gid := range groups {
		other = max(other, int32(gid)+1)
	}
	binary.LittleEndian.PutUint32(cm.memory[64:], uint32(other))
	if rc := child.Proc_setgroups(cm, 64, 1); rc != -_wasiEPERM {
		t.Fatalf("a copy's setgroups of a group it is not in rc=%d, want -EPERM", rc)
	}
}
