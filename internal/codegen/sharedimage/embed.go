// Package sharedimage carries the copy-on-write shared-memory-image runtime
// that wasm2go emits alongside a translated module.
//
// It lives here as source text rather than as a string literal in the
// generator because it is ordinary Go that happens to be output: keeping it in
// .go.txt files means it stays readable, reviewable, and greppable. The only
// generated parts are the identifiers the surrounding package decides — the
// package name and the Module field names, which single-package output keeps
// unexported and multi-package output must export.
package sharedimage

import (
	"bytes"
	_ "embed"
	"fmt"
	"go/format"
	"text/template"
)

//go:embed sharedimage.go.txt
var coreTmpl string

//go:embed sharedimage_mmap.go.txt
var mmapTmpl string

//go:embed sharedimage_nommap.go.txt
var nommapTmpl string

//go:embed sharedimage_linux.go.txt
var linuxTmpl string

//go:embed sharedimage_nolinux.go.txt
var nolinuxTmpl string

//go:embed sharedimage_high.go.txt
var highTmpl string

//go:embed sharedimage_nohigh.go.txt
var nohighTmpl string

//go:embed memreserve.go.txt
var reserveTmpl string

//go:embed memreserve_on.go.txt
var reserveOnTmpl string

//go:embed memreserve_off.go.txt
var reserveOffTmpl string

// Names are the identifiers the emitting package supplies.
type Names struct {
	Pkg     string // package clause of the generated files
	Module  string // the Module type's name (always "Module" today)
	Memory  string // Module's linear-memory field
	MemMu   string // Module's memory lock field
	MemSize string // Module's *atomic.Uint64 current-size field
	DataEnd string // Module's data-segment-extent field
	MemRes  string // Module's owned-reservation field

	// SaveGlobals is the generated globals-snapshot function (see
	// emitGlobalsSnapshot); multi-package output exports it.
	SaveGlobals string

	// Exported adds the exported forms of the reservation runtime that
	// the module's other packages call (multi-package output).
	Exported bool
	// The shape of a linear memory's reservation (see memreserve.go.txt):
	// it runs ReserveGuard bytes past its limit; the limit is at most
	// ReserveMax, ReserveDefault for a memory given no ceiling, and always
	// ReserveMax when ReserveFixed.
	ReserveGuard   uint64
	ReserveMax     uint64
	ReserveDefault uint64
	ReserveFixed   bool
}

// ReservedConstraint is the build constraint under which a linear memory
// is a reservation (memreserve_on.go): a unix host with a 64-bit address
// space, without the wasm2go_boundschecks tag. It names the 32-bit hosts
// rather than the 64-bit ones, so that gcasm's capture, which drops the
// files whose constraint names amd64 or arm64, keeps these as they are.
//
// The assembly gcasm captures is compiled from the generated code in this
// form (the bounds checks it carries are the reservation's), so it applies
// under exactly this constraint, and the pure Go form everywhere else:
// see codegen's pureFallbackTag and gcasm's archSpecs.
const ReservedConstraint = "unix && !wasm2go_boundschecks && !(386 || arm || mips || mipsle)"

// Reserved is ReservedConstraint, for the templates' build lines.
func (Names) Reserved() string { return ReservedConstraint }

// Files renders the runtime: output filename → formatted Go source. The
// files split by platform (mmap / no mmap, whether the pages a process
// changed can be told, whether an image file's descriptor is kept out of
// the low numbers, whether memory is a reservation) and must be emitted
// together.
func Files(n Names) (map[string][]byte, error) {
	out := map[string][]byte{}
	for name, src := range map[string]string{
		"sharedimage.go":        coreTmpl,
		"sharedimage_mmap.go":   mmapTmpl,
		"sharedimage_nommap.go": nommapTmpl,
		"sharedimage_linux.go":  linuxTmpl,
		"sharedimage_other.go":  nolinuxTmpl,
		"sharedimage_high.go":   highTmpl,
		"sharedimage_nohigh.go": nohighTmpl,
		"memreserve.go":         reserveTmpl,
		"memreserve_on.go":      reserveOnTmpl,
		"memreserve_off.go":     reserveOffTmpl,
	} {
		t, err := template.New(name).Parse(src)
		if err != nil {
			return nil, fmt.Errorf("sharedimage: parsing %s: %w", name, err)
		}
		var buf bytes.Buffer
		if err := t.Execute(&buf, n); err != nil {
			return nil, fmt.Errorf("sharedimage: rendering %s: %w", name, err)
		}
		formatted, err := format.Source(buf.Bytes())
		if err != nil {
			return nil, fmt.Errorf("sharedimage: formatting %s: %w", name, err)
		}
		out[name] = formatted
	}
	return out, nil
}
