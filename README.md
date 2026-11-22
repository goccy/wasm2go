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
`EINTR` — and `Exec` gates `proc_spawn`; a nil
one denies. A socket (`sock_open`, `sock_socketpair`, `sock_socket`)
is one socket of the host's from its making to its close; a
Unix-domain socket's path is a file of the host only with
`HostFS("/")`, and `ENOTSUP` with any other `FS`. `sock_shutdown`, the
socket options and timeouts (`sock_setopt`, `sock_getopt`,
`sock_timeout`) and `pipe` consult no hook. `FSAccess` is consulted on every path operation with the path
cleaned as `chroot(2)` sees it (`..` of the root is the root; a
symbolic link's target too) and the `FS` is given that approved path
(`FSAccess` is a policy on path names); a nil one allows every access
to the configured `FS`, which is then given the path as the guest wrote
it. `Errors` is told the errors the guest cannot be given (nil drops them). Host
access is opt-in: `HostFS(root)`, `AllowAllNetAccess`, `AllowAllDial`,
`AllowAllListen`, `AllowAllResolve`, `AllowAllExec`, or `HostWASIConfig()` for what the
host process has (its args, environment, stdio, the whole host
filesystem and its local time zone, with every hook allowing).
`HostFS` of a directory other than `/` is built on `os.Root`, which
refuses every path the guest names that escapes it (through `..` or a
symbolic link) with `EACCES`; the symbolic links the guest creates may
still point anywhere for a reader on the host. The directory must be
one that may be searched, and it is held open until the FS's `Close`
method is called.

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
`setuid` family, `setgroups`, `setpriority` and `umask` of the guest
of the fork family's root instance. `Process` reads what they change,
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
mode of what it makes, and the host process's umask applies as well;
a command the instance starts gets the host process's umask only. The
thread ends with `CloseAll`, or when the garbage collector collects an
instance dropped without it.

`Signals` connects the guest's signals with what is outside it: its
`Kill` is given the guest's `kill` of a process that is not the
guest's own (not the guest, not a child or fork it made) or of a
process group that is not the guest's (the guest and its forks are one
group; `kill(-1)` reaches them but the guest), and its
`Dispositions` is told the signals the guest handles, ignores and
blocks whenever they change, with the reporting instance as the
`SignalTarget` to post that guest's signals to (a forked instance shares
its parent's `Signals`). Signal numbers are the guest's (Linux
numbering); a raise of a WASI signal is turned into it. A nil one is an
isolated guest: such a `kill` fails with `ESRCH`. Signals reach the
guest through `PostSignal`. `ForkProc` forks an instance that its
parent waits for, under a pid token the fork knows as its own.

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
the guest keeps its own numbers. `HostUsers()`, `HostSystem()`,
`HostServices()` and `HostSyslog()` give the host's. The guest's
`flock` locks a file of an `FS` that is a `LockFS` (what `HostFS` and
`NewMemFS` return); `fcntl`'s record locks and `mkfifo` are the host's.
On Linux a record lock is the open file description's (`F_OFD_SETLK`),
so instances of one host process exclude each other; elsewhere it is the
host process's, shared by all its instances and released by closing any
descriptor of the file. A lock or an open of a FIFO that waits ends with
`EINTR` when a signal is posted to the guest; an open of a FIFO with
`O_NONBLOCK` does not wait. A blocked `F_SETLKW` cannot be called off:
when it is granted after the guest was told `EINTR`, the range it asked
for is unlocked again, which also removes a lock the guest held in that
range before it waited.

```go
fsys, err := mymodule.HostFS("/srv/data")
if err != nil {
	return err
}
defer func() {
	if err := fsys.(io.Closer).Close(); err != nil {
		log.Print(err)
	}
}()
m := mymodule.NewWithWASI(mymodule.NewWASI(mymodule.WASIConfig{
	Args:   []string{"prog"},
	Stdout: os.Stdout,
	FS:     fsys,
}))
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
make lint              # run golangci-lint
make release/check     # validate the GoReleaser config + dry-run a build
```

`make install/wat2wasm` dispatches to Homebrew on macOS and to
apt/dnf/pacman/apk on Linux (whichever is available); it is a no-op
if `wat2wasm` is already on `PATH`.

## License

MIT — see [LICENSE](LICENSE).
