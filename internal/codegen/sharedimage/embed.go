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

//go:embed sharedimage_cow_linux.go.txt
var cowLinuxTmpl string

//go:embed sharedimage_cow_other.go.txt
var cowOtherTmpl string

//go:embed sharedimage_noreserve_linux.go.txt
var noReserveLinuxTmpl string

//go:embed sharedimage_noreserve_other.go.txt
var noReserveOtherTmpl string

// Names are the identifiers the emitting package supplies.
type Names struct {
	Pkg       string // package clause of the generated files
	Module    string // the Module type's name (always "Module" today)
	Memory    string // Module's linear-memory field
	MemSize   string // Module's *atomic.Uint64 current-size field
	MemMu     string // Module's *sync.Mutex that memory.grow takes
	MemShared string // Module's shared-memory flag
	DataEnd   string // Module's data-segment-extent field

	// SaveGlobals is the generated globals-snapshot function (see
	// emitGlobalsSnapshot); multi-package output exports it.
	SaveGlobals string
}

// Files renders the runtime: output filename → formatted Go source. The
// files split by platform (mmap / no mmap, copy-on-write forks / copies,
// Linux's MAP_NORESERVE / none) and must be emitted together.
func Files(n Names) (map[string][]byte, error) {
	out := map[string][]byte{}
	for name, src := range map[string]string{
		"sharedimage.go":           coreTmpl,
		"sharedimage_mmap.go":      mmapTmpl,
		"sharedimage_nommap.go":    nommapTmpl,
		"sharedimage_cow_linux.go": cowLinuxTmpl,
		"sharedimage_cow_other.go": cowOtherTmpl,

		"sharedimage_noreserve_linux.go": noReserveLinuxTmpl,
		"sharedimage_noreserve_other.go": noReserveOtherTmpl,
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
