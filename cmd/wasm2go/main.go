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

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/wasm"
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
		defer f.Close()
		r = bufio.NewReader(f)
	}

	mod, err := wasm.Parse(r)
	if err != nil {
		fail("parse: %v", err)
	}

	if *dump {
		printSummary(os.Stderr, mod)
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

	opts := codegen.Options{
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
		res, err := codegen.Translate(io.Discard, mod, opts)
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
		defer bw.Flush()
		w = bw
	} else {
		f, err := os.Create(*out)
		if err != nil {
			fail("create output: %v", err)
		}
		defer f.Close()
		bw := bufio.NewWriter(f)
		defer bw.Flush()
		w = bw
		outDirForSidecars = filepath.Dir(*out)
	}

	res, err := codegen.Translate(w, mod, opts)
	if err != nil {
		fail("translate: %v", err)
	}
	if outDirForSidecars != "" {
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
	fmt.Fprintf(os.Stderr, "wasm2go: "+format+"\n", args...)
	os.Exit(1)
}

func printSummary(w io.Writer, m *wasm.Module) {
	fmt.Fprintf(w, "types:    %d\n", len(m.Types))
	fmt.Fprintf(w, "imports:  %d (funcs %d, tables %d, mems %d, globals %d)\n",
		len(m.Imports), m.NumImportedFuncs, m.NumImportedTables, m.NumImportedMems, m.NumImportedGlobals)
	fmt.Fprintf(w, "functions:%d (defined; total incl imports = %d)\n",
		len(m.Functions), uint32(len(m.Functions))+m.NumImportedFuncs)
	fmt.Fprintf(w, "tables:   %d (defined)\n", len(m.Tables))
	fmt.Fprintf(w, "memories: %d (defined)\n", len(m.Memories))
	for i, mem := range m.Memories {
		fmt.Fprintf(w, "  mem[%d]: min=%d pages (=%d MiB) max=%d hasMax=%v\n",
			i, mem.Limits.Min, mem.Limits.Min*64/1024, mem.Limits.Max, mem.Limits.HasMax)
	}
	fmt.Fprintf(w, "globals:  %d (defined)\n", len(m.Globals))
	fmt.Fprintf(w, "exports:  %d\n", len(m.Exports))
	for _, e := range m.Exports {
		kind := []string{"func", "table", "memory", "global"}[e.Kind]
		fmt.Fprintf(w, "  %s %q -> %d\n", kind, e.Name, e.Index)
	}
	fmt.Fprintf(w, "elements: %d segments\n", len(m.Elements))
	var elemTotal int
	for _, e := range m.Elements {
		elemTotal += len(e.FuncIdxs)
	}
	fmt.Fprintf(w, "  total entries: %d\n", elemTotal)
	fmt.Fprintf(w, "datas:    %d segments\n", len(m.Datas))
	var dataTotal int
	for _, d := range m.Datas {
		dataTotal += len(d.Bytes)
	}
	fmt.Fprintf(w, "  total bytes: %d\n", dataTotal)
	if m.Start != nil {
		fmt.Fprintf(w, "start:    func %d\n", *m.Start)
	}
}
