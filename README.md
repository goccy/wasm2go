# wasm2go

`wasm2go` is an ahead-of-time compiler that translates a WebAssembly
binary into **standalone Go source code**. The generated package runs
the module natively — no interpreter and no embedded wasm runtime — so
it builds and links like any other Go code.

It is useful when you want to ship a wasm-compiled library (for
example a large C/C++ codebase built with the WASI SDK) inside a Go
program without paying the startup and memory cost of a wasm engine.

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
