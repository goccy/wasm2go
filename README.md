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
translated module. The implementation is one self-contained file
that only uses Go's standard library (`os`, `time`, `syscall`,
`net`) — there is no platform-specific file split and no third-party
dependency, so generated output builds for every `GOOS` Go supports
(linux, darwin, freebsd, netbsd, openbsd, dragonfly, solaris,
illumos, aix, windows) without any extra wiring on the consumer
side.

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
