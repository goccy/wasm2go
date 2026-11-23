# wasm2go

`wasm2go` is an ahead-of-time compiler that translates a WebAssembly
binary into **standalone Go source code**. The generated package runs
the module natively — no interpreter and no embedded wasm runtime — so
it builds and links like any other Go code.

It is useful when you want to ship a wasm-compiled library (for
example a large C/C++ codebase built with the WASI SDK) inside a Go
program without paying the startup and memory cost of a wasm engine.

The generated output is dual-arch: every function ships an `amd64.s`
and an `arm64.s` body produced by an SSA-based register allocator
(block-local regalloc + cross-block stack allocation + m-pointer
caching + slot reuse + peephole + branch-fusion), with a pure-Go
fallback selected by build constraint on any other GOOS/GOARCH. The asm and pure-Go paths share
the same `New()` / exported-method API, so callers never see the
distinction.

## Install

```sh
go install github.com/goccy/wasm2go/cmd/wasm2go@latest
```

Prebuilt binaries for each release are published on the
[releases page](https://github.com/goccy/wasm2go/releases).

## CLI usage

Translate a wasm binary to a single Go file:

```sh
wasm2go -i module.wasm -o module.go -pkg mymodule
```

By default the input is read from stdin and the output is written to
stdout, so `wasm2go < module.wasm > module.go` also works.

Inspect a module without generating code:

```sh
wasm2go -dump -i module.wasm
```

### Flags

| Flag                  | Description |
|-----------------------|-------------|
| `-i`                  | Input wasm file (default: stdin). |
| `-o`                  | Output Go file (default: stdout). Single-file mode only. |
| `-pkg`                | Go package name in the output (default: `wasm2go`). |
| `-import`             | Go import path of the generated package (required). |
| `-out-dir`            | Output directory; required when the wasm exceeds the internal multi-file threshold. |
| `-dump`               | Print a summary of the parsed module instead of generating code. |
| `-bulk-export-prefix` | Treat exports matching `<prefix><svc>_<mt>` as bulk-dispatch entries (one standalone `Inv_<svc>_<mt>` per match so the linker can drop unused ones). |
| `-keep-dead-funcs`    | Disable whole-function dead-code elimination (useful for diffing). |
| `-entry-exports`      | Comma-separated list of export names that are DCE roots; the literal value `NONE` means no export is a root. |
| `-promotion-report`   | Write the memory-promotion report (JSON: per-function frame/rodata/slab classification) to this path. |

The translator's output shape (SSA pipeline, data-sidecar layout,
native `wasi_snapshot_preview1`, multi-package + linkname-split for
large modules) is auto-derived from the input. There is no caller-
visible knob for any of those decisions.

### WASI support

When the input wasm imports `wasi_snapshot_preview1`, `wasm2go` emits
a native Go implementation of every preview1 call alongside the
translated module. The implementation only uses Go's standard
library (`os`, `time`, `syscall`, `net`) — there is no third-party
dependency. Its per-platform parts are emitted as auxiliary files
with build constraints (`wasip1_native_*.go`,
`wasip1_hostnumbers_*.go`) that must be written next to the main
file: the `wasm2go` command writes them when given `-o`, a library
caller writes `Result.AuxFiles` (multi-package output carries them in
`Result.Files`). Generated output builds for every `GOOS` Go
supports (linux, darwin, freebsd, netbsd, openbsd, dragonfly,
solaris, illumos, aix, windows).

The runtime is built from a `WASIConfig` with `NewWASI(cfg)` and
passed to `NewWithWASI`. The guest gets only what the configuration
names: the zero `WASIConfig{}`, which `New()` uses, gives it no
arguments, no environment, an empty stdin, a stdout and stderr that
discard what is written, no filesystem (nothing is preopened: every
call on fd 3 fails with `EBADF`, fd 3 is an ordinary free number, and
the guest's C library fails every path with `ENOENT`), no process
spawn, and none of the socket operations the hooks gate: `NetAccess`
gates the accepts, receives and sends of sockets (`sock_accept`,
`sock_recv`, `sock_send`, and `fd_read` and `fd_write` of a socket),
`Dial` gates `sock_connect` and `sock_connect_addr` and every send of
a datagram to an address, `Listen` gates a socket's taking an address
others reach it at (`sock_bind_addr`, the `sock_listen` of an unbound
socket, and the first send to an address of an unbound datagram
socket), `Resolve` gates the name lookups (`sock_getaddrinfo`,
`sock_resolve`, `sock_host_by_name`, with the name) and
`sock_reverse_addr` (with the address in text) — an address written
in numbers, and the empty host of `sock_getaddrinfo` (`INADDR_ANY`),
are no lookup and are not asked about; a signal ends a lookup with
`EINTR` — and `Exec` gates `proc_spawn` and `proc_exec` with the
`ExecRequest` the command is started from (its executable, a name
without a `/` looked up in the guest's `FS` as musl's `execvp` does, but
in the `PATH` of the envp the guest passes, not of the caller's
`environ` (the two differ only when `posix_spawnp` is given an envp with
another `PATH`), its arguments, its whole environment and its working
directory, the root of the `FS` for an empty one); a nil
one denies. A command is a process of the host: it sees the host's
filesystem, not the `FS`, and is started only with an `FS` that is a
`HostRootFS` (`HostFS("/")`), by the host's paths of its names
(`ENOSYS` with any other `FS`). A socket (`sock_open`, `sock_socketpair`, `sock_socket`)
is one socket of the host's from its making to its close; a
Unix-domain socket's path is a file of the host only with an `FS` that
is a `HostRootFS` (`HostFS("/")`), and `ENOTSUP` with any other `FS`. `sock_shutdown`, the
socket options and timeouts (`sock_setopt`, `sock_getopt`,
`sock_timeout`) and `pipe` consult no hook. The `FS` is given every
guest path in one form, the one `io/fs.ValidPath` accepts (`.` for the
root), with a trailing `/` when the guest asks for a directory: the
runtime resolves `..` itself, after the symbolic links before it as the
system does (`..` of the root is the root). A policy on files is an
`FS` that wraps another and refuses what the policy refuses with
`fs.ErrPermission`, which the guest sees as `EACCES` (an example
follows). A path call takes any directory descriptor: of an `FS` that
is an `OpenRootFS`, a directory the guest opens is also opened as an `FS` of
its own (`OpenRoot`), and a name relative to its descriptor without
`..` is given to that `FS`, which finds the directory wherever it is
now; a name with `..`, and every name of an `FS` that is no `OpenRootFS` or
whose `OpenRoot` is `errors.ErrUnsupported`, is found from the path the
directory was opened under, and given to the `FS` itself. A wrapper is a
`OpenRootFS` only by implementing `OpenRoot` and wrapping the `FS` it
returns, as the example below does: one that does not still sees every
name. A wrapper that is no `AccessFS` has `access` answered by the mode
bits its `Stat` reports (`W_OK` of a file a policy refuses to write may
be allowed), and one that is no `HostRootFS` has no Unix-domain socket
paths. The
names of the guest's own descriptors (`/dev/fd/N`, `/proc/self/fd/N`,
`/dev/stdin`, ...) are resolved without the `FS` by every path
operation, and by those that take no directory descriptor even when
there is no `FS`. `FS` has the methods of `*os.Root`, with the names
and signatures `os.Root` gives them (`OpenFile`, `Mkdir`, `Chmod`,
`Chown`, `Lchown`, `Chtimes`, `Rename`, `Stat`, `Lstat`,
`Readlink`, `Link`, `Symlink`, `Close`), and `File` those of `*os.File`;
where WASI needs what `os.Root` has no method for, `FS` has one more:
`Unlink` and `Rmdir` in place of `Remove` (each refuses the other kind
of file), `Lchtimes`, and an `OpenFile` that honours `syscall.O_NOFOLLOW`
as `os.OpenFile` does. What an `FS` can do beyond `FS`'s methods it says
by the optional interfaces it implements, which the runtime asks for
and nothing else: `OpenRootFS` (`OpenRoot`, as `os.Root`'s: a directory
as an `FS` of its own, which finds the directory wherever it is now;
`HostFS`'s and `NewMemFS`'s are; the whole host filesystem's
`OpenRoot` is `errors.ErrUnsupported` but on Linux and darwin),
`MkfifoFS`, `LockFS`, `AccessFS` (`access`:
`HostFS`'s ask the host, for the host process's ids, but for a
`HostFS` of a directory on darwin and a name that is a symbolic link of
one on Linux, answered by the mode bits; `NewMemFS`'s allows what its
`open` allows; any other `FS` is answered by the mode bits, for the ids
of `Process`) and `HostRootFS`, and of its files `ChtimesFile`; an
`FS` that wraps another keeps what the other does by calling its
methods, and what it can do beyond them by implementing the same
interfaces. `Errors` is told the errors the guest cannot be given (nil drops them). Host
access is opt-in: `HostFS(root)`, `AllowAllNetAccess`, `AllowAllDial`,
`AllowAllListen`, `AllowAllResolve`, `AllowAllExec`, or `HostWASIConfig()` for what the
host process has and cannot fail to give (its args, environment,
stdio, the whole host filesystem, its local time zone, its user,
group and services databases and its `uname`, with every hook
allowing).
`HostFS("")` is an error. `HostFS` of a directory other than `/` is
built on `os.Root`, which refuses a symbolic link that leads out of it
with `EACCES`; a name with a trailing `/` is refused so only by the
`os.Root` of Go 1.25.12 or later in the 1.25 series, 1.26.5 or later in
the 1.26 series, and any later release, so the module the runtime is
generated into must be built with one of those. The symbolic links the
guest creates may still point anywhere for a reader on the host. The directory must be one that may
be searched, and it is held open until the FS's `Close` method is
called.

`Process` supplies the values the guest reads of its process: what
`getpid`, `getppid`, the `getuid` family, `getgroups`, `getpriority`
and `times()` report, the pid whose `/proc/PID/fd` lists the guest's
descriptors, and the umask the guest starts with. A nil one is an
isolated process (pid 42, ppid 1, every user and group id 0, no CPU
time, umask 022). `HostProcess()` returns the host process's, or an
error where its umask cannot be read without changing it;
`HostProcessUmask(umask)` is the same with the umask given.
`HostWASIConfig()` leaves `Process` nil.

`Process` only reads; `ProcessChanges` makes the changes: the
`setuid` family, `setgroups`, `setpriority`, `umask`, `setpgid` and
`setsid` of the guest of the fork family's root instance, and tells
the process group the family starts in and that of a process outside
the family (`Pgid`). `Process` reads what they change,
so a `ProcessChanges` needs a `Process` (`NewWASI` panics without one).
A forked instance's guest changes its nice value and umask alone, and
keeps the ids and groups of the process the `ProcessChanges` changes:
a change of them fails with `EPERM`, but for one that leaves them as
they are (`setuid(getuid())`). A guest drops privileges before it
forks. A nil `ProcessChanges` changes nothing (`ENOSYS`, and a `umask`
of the instance's alone). `HostProcessChanges()` makes the changes the
host process's. A program that used `HostProcess()` for the changes as
well sets both:

```go
proc, err := mymodule.HostProcess()
// ...
cfg := mymodule.WASIConfig{Process: proc, ProcessChanges: mymodule.HostProcessChanges()}
```

Each instance's umask is its own. On Linux the files, directories and
FIFOs an instance makes on the host's filesystem, and the commands it
starts, are made on an OS thread of the instance's whose umask is the
instance's (`unshare(CLONE_FS)`), so that the kernel takes it out.
Where `unshare(2)` is refused (Docker's default seccomp profile), and
on other systems, the runtime takes the instance's umask out of the
mode of what it makes, and the host process's umask applies as well
(on darwin the runtime puts back what that takes out); a command the
instance starts gets the host process's umask only. The
thread ends with `CloseAll`, or when the garbage collector collects an
instance dropped without it.

`Signals` connects the guest's signals with what is outside it: its
`Kill` is given the guest's `kill` of a process that is not the
guest's own (not the guest, not a child or fork it made) or of a
process group that is none of the family's (`kill(-1)` reaches the
family but the guest), and its
`Dispositions` is told the signals the guest handles, ignores and
blocks whenever they change, with the reporting instance as the
`SignalTarget` to post that guest's signals to (a forked instance shares
its parent's `Signals`). Signal numbers are the guest's (Linux
numbering); a raise of a WASI signal is turned into it. A nil one is an
isolated guest: such a `kill` fails with `ESRCH`. Signals reach the
guest through `PostSignal`, which delivers them as `kill` does to the
guest's process (the command the guest has become after `exec`), or
through `DeliverSignal` with a `SignalReach`: `ReachProcess` as
`PostSignal`, `ReachGuest` to the guest alone, dropped once it has
become a command, for a signal the command gets where the host process
got it too (a terminal's interrupt). `TakeSignal` is offered the
signals the runtime raises for a guest itself (the interval timer's
`SIGALRM`, a child's `SIGCHLD` once its status can be waited for, a
`kill` of its own pid, a raise, the `SIGPIPE` of a write that fails
with `EPIPE`) before the guest is given them; one it takes is not the
guest's. `SignalIgnored` is asked of a signal the guest leaves at its
default action whether the process the guest runs as ignores it by an
action the guest did not set (inherited when the process started, or
set by code outside the guest); the guest then takes `SIG_IGN` as its
own action. A nil one is an isolated guest, which starts with every
signal at its default action. `ForkProc` forks an instance that its
parent waits for, under a pid token the fork knows as its own. The
pid tokens of the forks and the commands a guest starts are numbers
from 4194304 up, above every pid Linux and darwin hand out, so a token
passed outside the guest names no process of the host.

`Fork` makes the instance the child of the guest's `fork`
(`proc_fork`) runs in; a nil one fails it with `ENOSYS`. `CopyForker`
copies the forking instance: its memory (into the Go heap, the whole
memory at each fork), its globals, its memory's ceiling, its dropped
data segments and the end of its data, with the parent's other
imports. The child is
a pseudo-process: its host state comes from `ForkProc` (the
descriptors share their open file descriptions with the parent's), it
runs on a goroutine of its own through the module's export
`__wasip1_posix_extension_fork_child`, whose result is its exit
status, and it has only the forking thread: as in a POSIX fork, a
lock another thread held stays held in the child. A trap ends it as
`SIGABRT` does and is told `Errors`. The parent waits for it, signals
it and gets `SIGCHLD` as for any child. An embedder that wraps a
`Forker` is called back with each child's status when it ends (every
process of the fork family forks through the same `Forker`).

The fork family keeps its process groups and sessions (`getpgid`,
`setpgid`, `setsid`): a process starts in its parent's group and
session, and the root instance in the group its `ProcessChanges`
tells (its own pid without one) and in the host process's session.
The root's guest changes its own group and session through its
`ProcessChanges`, every other process through the family. A command
the guest starts is put in a group of the host's for its group: the
host process's for the group the host process is in, and otherwise a
group of the host's that the group's first command leads and the
later ones join; a command of a session that is not the host
process's leads a session of the host's of its own. A `kill` of a
group reaches the family's processes in it and, through the host's
group, the processes the commands started in it. The first command of
a group stays unreaped while the group has other members, so that the
group's number stays its own. Where the host has no process groups
(Windows), every command is in the host process's.

The controlling terminal of the host process's session is the host
process's: `fd_ioctl`'s `TIOCGPGRP` and `TIOCSPGRP` (`tcgetpgrp`,
`tcsetpgrp`) read and set its foreground group as the family's, the
host process's own group standing for the group the host process is
in, and a group of the host's for another. A group that has no command
yet becomes the foreground one when its first command starts. The
runtime changes the foreground group with `SIGTTOU` blocked, as a job
control shell ignores it. Another session of the family has no
controlling terminal.

`exec` is emulated, as Cygwin does: the guest starts the command with
its descriptors 0, 1 and 2 (in the group and session its process is
in), and once it has started, the process keeps its pid, its
descriptors are closed, and the guest waits for the command and ends
as it ended (`WasiExitError` or `WasiSignalError`, as an exit or a
kill of its own). A signal for the process from then on is the
command's, and so is a signal pending for the process or the exec'ing
thread that this thread does not block; `KillCommands` kills it as well. The `Signals` is told then that
the process handles every signal but the ones of no effect and the ones
the guest ignored, which stay ignored across the exec, so that a relay
of the host process's signals sends them on to the command.

`Process` also answers `getgroups` and makes the guest's `setuid`
family, `setgroups` and `setpriority` changes; an isolated process is
in no supplementary group, has the nice value 0 and changes nothing
(`ENOSYS`). `Users` is the user and group database (`getpwnam`,
`getgrgid`, `getpwent`, ...), `System` what `uname` and `gethostname`
report, `Services` the services database (`getservbyname`,
`getservbyport`), `Syslog` the system logger of `openlog` and
`syslog`, and `Numbering` gives the guest the numbers of another system
in place of those of its own C library. A nil one is none: a lookup
finds nothing (`ENOENT`), `uname` and `syslog` fail with `ENOSYS`, and
the guest keeps its own numbers. `HostUsers(report)`, `HostSystem()`,
`HostServices(report)`, `HostSyslog()` and `HostNumbering()` (the host's
error numbers, signals, flags and socket options, ... on Linux and
darwin) give the host's. The guest's
`flock` locks a file of an `FS` that is a `LockFS` (what `HostFS` and
`NewMemFS` return); `fcntl`'s record locks are the host's, and `mkfifo`
makes a FIFO of an `FS` that is a `MkfifoFS` (`HostFS("/")`).
A record lock is the instance's, as a process's: a forked copy does not
inherit it, the instances of a generated package exclude each other, and
the instance's close of any descriptor of the file releases it. The
host's locks exclude the other processes: on Linux those of one open
file description of the file the runtime opens again, elsewhere the host
process's, which a close of any descriptor of the file in the host
process releases (see `Fd_lock`). A lock or an open of a FIFO that waits
ends with `EINTR` when a signal is posted to the guest; an open of a FIFO
with `O_NONBLOCK` does not wait. A blocked `F_SETLKW` for another
process's lock cannot be called off: when it is granted after the guest
was told `EINTR`, the host's locks of its range are brought back to the
instances' locks.

```go
fsys, err := mymodule.HostFS("/srv/data")
if err != nil {
	return err
}
defer func() {
	if err := fsys.Close(); err != nil {
		log.Print(err)
	}
}()
m := mymodule.NewWithWASI(mymodule.NewWASI(mymodule.WASIConfig{
	Args:   []string{"prog"},
	Stdout: os.Stdout,
	FS:     fsys,
}))
```

A policy is an `FS` that wraps another, as one wraps an `*os.Root`:
this one lets the guest change nothing, in the directories it opens too
(it is an `OpenRootFS` that wraps the `FS` of each of them). A call on a
descriptor (`fd_filestat_set_times`, `fd_chmod`, `fd_chown`, ...) goes to
the `File` the `FS` returned, so it wraps those too.

```go
type readOnly struct{ mymodule.FS }

func (r readOnly) OpenFile(name string, flag int, perm os.FileMode) (mymodule.File, error) {
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0 {
		return nil, fs.ErrPermission
	}
	f, err := r.FS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return readOnlyFile{f}, nil
}
func (r readOnly) OpenRoot(name string) (mymodule.FS, error) {
	inner, ok := r.FS.(mymodule.OpenRootFS)
	if !ok {
		return nil, errors.ErrUnsupported
	}
	dir, err := inner.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return readOnly{dir}, nil
}
func (readOnly) Mkdir(string, os.FileMode) error              { return fs.ErrPermission }
func (readOnly) Chmod(string, os.FileMode) error              { return fs.ErrPermission }
func (readOnly) Chown(string, int, int) error                 { return fs.ErrPermission }
func (readOnly) Lchown(string, int, int) error                { return fs.ErrPermission }
func (readOnly) Chtimes(string, time.Time, time.Time) error   { return fs.ErrPermission }
func (readOnly) Lchtimes(string, time.Time, time.Time) error  { return fs.ErrPermission }
func (readOnly) Unlink(string) error                          { return fs.ErrPermission }
func (readOnly) Rmdir(string) error                           { return fs.ErrPermission }
func (readOnly) Rename(string, string) error                  { return fs.ErrPermission }
func (readOnly) Symlink(string, string) error                 { return fs.ErrPermission }
func (readOnly) Link(string, string) error                    { return fs.ErrPermission }

type readOnlyFile struct{ mymodule.File }

func (readOnlyFile) Chmod(os.FileMode) error { return fs.ErrPermission }
func (readOnlyFile) Chown(int, int) error    { return fs.ErrPermission }
```

For multi-package output these names live in the `base` package
(`base.NewWASI`, `base.WASIConfig`, `base.HostFS`, ...), and
`NewWithWASI` stays in the module's package.

## Library usage

The translator is also importable as a library via the
`github.com/goccy/wasm2go/transpile` package:

```go
package main

import (
	"os"

	"github.com/goccy/wasm2go/transpile"
)

func main() {
	in, _ := os.Open("module.wasm")
	defer in.Close()
	out, _ := os.Create("module.go")
	defer out.Close()

	if _, err := transpile.Transpile(in, out, transpile.Options{
		Package:          "mymodule",
		OutputImportPath: "example.com/myproj/mymodule",
	}); err != nil {
		panic(err)
	}
}
```

`Transpile` is a one-shot wrapper around `Parse` followed by
`Translate`; call `Parse` and `Translate` directly when you need to
inspect the parsed `Module` between the two steps. See the
`transpile.Options` documentation for the full set of knobs; they
mirror the CLI flags above.

## Performance

Generated Go runs natively, so there is no wasm interpreter on the
hot path. The win shows up most in two places:

- **Cold start** — no JIT / AOT compilation step at program startup.
- **Per-call overhead** — calls into the module are ordinary Go
  function calls; no host-↔-guest boundary crossing.

A representative measurement against an equivalent wazero-driven
build of the same wasm module (a ~13 MB SQL parser/analyzer wasm,
22 SQL benchmark queries; macOS / Apple Silicon;
`go test -bench=. -benchtime=200ms`):

| Workload | wazero | wasm2go | Speedup |
|---|---:|---:|---:|
| One-time wasm cold compile | 4.67 s | **0.56 s** | **8.4×** |
| `select_constant` (trivial scalar) | 49.3 µs | **2.7 µs** | **18×** |
| `rank_dense_rank` (window) | 220 ms | **8.4 ms** | **26×** |
| `lag_lead` (window) | 229 ms | **10.0 ms** | **23×** |
| `json_extract_pipeline` | 878 ms | **10.8 ms** | **81×** |
| `q1_lineitem_pricing_summary` (TPC-H, ~64 ms scan) | **64.2 ms** | 68.2 ms | 0.94× |
| `q3_shipping_priority` (TPC-H, ~34 s scan) | **33.9 s** | 37.3 s | 0.91× |

wasm2go wins by large factors on short queries (call-boundary
overhead dominates the wazero path), and is within ±10% on the
long scan-heavy TPC-H queries where the inner loop work dominates
the boundary.

Memory allocations per call drop in proportion (e.g. `select_constant`:
76 → 41 allocs/op, 2.2 KB → 1.3 KB per query).

## Development

```sh
make install/wat2wasm  # install the wat2wasm CLI the test suite needs
make build             # build the CLI into ./bin
make test              # run the test suite with the race detector
make test-cover        # run with coverage and enforce the threshold
make lint              # run golangci-lint as linux and as darwin
make release/check     # validate the GoReleaser config + dry-run a build
```

`make install/wat2wasm` dispatches to Homebrew on macOS and to
apt/dnf/pacman/apk on Linux (whichever is available); it is a no-op
if `wat2wasm` is already on `PATH`.

## License

MIT — see [LICENSE](LICENSE).
