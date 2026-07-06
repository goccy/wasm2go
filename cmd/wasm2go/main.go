// Command wasm2go is the CLI front-end of the wasm2go transpiler.
//
// Usage:
//
//	wasm2go -i input.wasm -o out.go -pkg mypkg -import example.com/myproj/wmod
//	wasm2go -i large.wasm -out-dir ./wmod -pkg wmod -import example.com/myproj/wmod
//
// Single-file output (the default) is selected automatically for any
// wasm whose total function-body size fits in the internal multi-file
// threshold. Larger modules require -out-dir; the binary refuses to
// emit a single-file translation that would crush the Go compiler.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/wasm2go/internal/wasm"
	"github.com/goccy/wasm2go/transpile"
)

const multiFileThreshold = 1 << 20 // mirrors codegen.defaultMultiPackageThreshold

func main() {
	dump := flag.Bool("dump", false, "print a summary of the parsed module to stderr instead of generating Go")
	in := flag.String("i", "", "input wasm file (default: stdin)")
	out := flag.String("o", "", "output Go file (default: stdout); single-file mode only")
	pkg := flag.String("pkg", "wasm2go", "Go package name to emit")
	importPath := flag.String("import", "", "Go import path the generated package will live at (required)")
	outDir := flag.String("out-dir", "", "output directory for multi-package mode; required when the wasm exceeds the internal multi-file threshold")
	bulkExportPrefix := flag.String("bulk-export-prefix", "", "treat exports matching `<prefix><svc>_<mt>` as bulk-dispatch entries (one standalone Inv_<svc>_<mt> per match)")
	keepDeadFuncs := flag.Bool("keep-dead-funcs", false, "disable whole-function dead-code elimination (useful for diffing)")
	entryExports := flag.String("entry-exports", "", "comma-separated list of export names that are DCE roots; the literal value \"NONE\" means no export is a root")
	promotionReport := flag.String("promotion-report", "", "write the SSA memory-promotion report (JSON: per-function frame/rodata/slab classification) to this path")
	flag.Parse()

	var r io.Reader
	if *in == "" {
		r = bufio.NewReader(os.Stdin)
	} else {
		f, err := os.Open(*in)
		if err != nil {
			fail("open input: %v", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				fail("close input: %v", err)
			}
		}()
		r = bufio.NewReader(f)
	}

	mod, err := wasm.Parse(r)
	if err != nil {
		fail("parse: %v", err)
	}

	if *dump {
		if err := printSummary(os.Stderr, mod); err != nil {
			fail("print summary: %v", err)
		}
		return
	}

	if *importPath == "" {
		fail("-import is required (Go import path of the generated package)")
	}

	// Decide single-file vs multi-package based on the same threshold
	// codegen.Translate uses internally — so we can require -out-dir
	// up front when the user is about to land in multi-package mode.
	total := 0
	for i := range mod.Functions {
		total += len(mod.Functions[i].Body)
	}
	wantsMulti := total > multiFileThreshold

	opts := transpile.Options{
		Package:             *pkg,
		OutputImportPath:    *importPath,
		BulkExportPrefix:    *bulkExportPrefix,
		KeepDeadFuncs:       *keepDeadFuncs,
		EntryExports:        parseEntryExports(*entryExports),
		PromotionReportPath: *promotionReport,
	}

	if wantsMulti {
		if *outDir == "" {
			fail("input wasm requires multi-package output (total %d bytes of function bodies > %d threshold); pass -out-dir", total, multiFileThreshold)
		}
		res, err := transpile.Translate(io.Discard, mod, opts)
		if err != nil {
			fail("translate: %v", err)
		}
		for relPath, data := range res.Files {
			outPath := filepath.Join(*outDir, relPath)
			if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
				fail("mkdir %s: %v", outPath, err)
			}
			if err := os.WriteFile(outPath, data, 0644); err != nil {
				fail("write %s: %v", outPath, err)
			}
		}
		for name, data := range res.Sidecars {
			outPath := filepath.Join(*outDir, name)
			if err := os.WriteFile(outPath, data, 0644); err != nil {
				fail("write sidecar %s: %v", outPath, err)
			}
		}
		return
	}

	var w io.Writer
	var outDirForSidecars string
	if *out == "" {
		bw := bufio.NewWriter(os.Stdout)
		defer func() {
			if err := bw.Flush(); err != nil {
				fail("flush stdout: %v", err)
			}
		}()
		w = bw
	} else {
		f, err := os.Create(*out)
		if err != nil {
			fail("create output: %v", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				fail("close output: %v", err)
			}
		}()
		bw := bufio.NewWriter(f)
		defer func() {
			if err := bw.Flush(); err != nil {
				fail("flush output: %v", err)
			}
		}()
		w = bw
		outDirForSidecars = filepath.Dir(*out)
	}

	res, err := transpile.Translate(w, mod, opts)
	if err != nil {
		fail("translate: %v", err)
	}
	if outDirForSidecars != "" {
		// Single-file mode still carries companion files (the pure
		// fallback + gcasm bundle) in res.Files.
		for name, data := range res.Files {
			p := filepath.Join(outDirForSidecars, name)
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				fail("mkdir for %s: %v", p, err)
			}
			if err := os.WriteFile(p, data, 0644); err != nil {
				fail("write %s: %v", p, err)
			}
		}
		for name, data := range res.Sidecars {
			p := filepath.Join(outDirForSidecars, name)
			if err := os.WriteFile(p, data, 0644); err != nil {
				fail("write sidecar %s: %v", p, err)
			}
		}
		for name, data := range res.AuxFiles {
			p := filepath.Join(outDirForSidecars, name)
			if err := os.WriteFile(p, data, 0644); err != nil {
				fail("write aux file %s: %v", p, err)
			}
		}
	}
}

// parseEntryExports parses the -entry-exports flag into the
// Options.EntryExports slice. An empty string returns nil (every
// export is a root). The literal "NONE" returns a non-nil empty
// slice (no export is a root). Otherwise the value is split on commas
// with whitespace trimmed and empty fields dropped.
func parseEntryExports(v string) []string {
	if v == "" {
		return nil
	}
	if v == "NONE" {
		return []string{}
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fail(format string, args ...any) {
	// fail() is a terminal sink: nothing reasonable can be done if the
	// error message itself fails to write, because we are about to
	// os.Exit and there is no other channel to surface a write error.
	// Check the error explicitly so the linter sees the awareness,
	// even though the only useful action is to keep exiting.
	if _, err := fmt.Fprintf(os.Stderr, "wasm2go: "+format+"\n", args...); err != nil {
		// stderr is broken; exit anyway.
		_ = err
	}
	os.Exit(1)
}

// errWriter wraps an io.Writer so a sequence of Fprintf calls can be
// emitted without a per-call error check; the first failure is kept
// and surfaced when the caller asks for it. Keeps printSummary
// readable while still propagating write errors instead of dropping
// them.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) Fprintf(format string, args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

func printSummary(w io.Writer, m *wasm.Module) error {
	ew := &errWriter{w: w}
	ew.Fprintf("types:    %d\n", len(m.Types))
	ew.Fprintf("imports:  %d (funcs %d, tables %d, mems %d, globals %d)\n",
		len(m.Imports), m.NumImportedFuncs, m.NumImportedTables, m.NumImportedMems, m.NumImportedGlobals)
	ew.Fprintf("functions:%d (defined; total incl imports = %d)\n",
		len(m.Functions), uint32(len(m.Functions))+m.NumImportedFuncs)
	ew.Fprintf("tables:   %d (defined)\n", len(m.Tables))
	ew.Fprintf("memories: %d (defined)\n", len(m.Memories))
	for i, mem := range m.Memories {
		ew.Fprintf("  mem[%d]: min=%d pages (=%d MiB) max=%d hasMax=%v\n",
			i, mem.Limits.Min, mem.Limits.Min*64/1024, mem.Limits.Max, mem.Limits.HasMax)
	}
	ew.Fprintf("globals:  %d (defined)\n", len(m.Globals))
	ew.Fprintf("exports:  %d\n", len(m.Exports))
	for _, e := range m.Exports {
		kind := []string{"func", "table", "memory", "global"}[e.Kind]
		ew.Fprintf("  %s %q -> %d\n", kind, e.Name, e.Index)
	}
	ew.Fprintf("elements: %d segments\n", len(m.Elements))
	var elemTotal int
	for _, e := range m.Elements {
		elemTotal += len(e.FuncIdxs)
	}
	ew.Fprintf("  total entries: %d\n", elemTotal)
	ew.Fprintf("datas:    %d segments\n", len(m.Datas))
	var dataTotal int
	for _, d := range m.Datas {
		dataTotal += len(d.Bytes)
	}
	ew.Fprintf("  total bytes: %d\n", dataTotal)
	if m.Start != nil {
		ew.Fprintf("start:    func %d\n", *m.Start)
	}
	return ew.err
}
