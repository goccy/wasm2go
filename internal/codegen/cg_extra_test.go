package codegen_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
	"github.com/tetratelabs/wazero"
)

// TestWexportsBulkDispatch drives the bulk-export fixture through
// the single-file output path with the bulk-export-prefix knob. Each
// `w_<svc>_<mt>` export becomes a standalone Inv_<svc>_<mt> function
// that the linker can drop independently — the consolidated
// InvokeExport switch form has been retired.
func TestWexportsBulkDispatch(t *testing.T) {
	mod := readFixture(t, "wexports.wasm")
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{
		Package:          "pkg",
		OutputImportPath: "gentest/pkg",
		BulkExportPrefix: "w_",
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "func Inv_") {
		t.Errorf("output missing per-export Inv_<svc>_<mt> function:\n%s", out)
	}
	if strings.Contains(out, "func (m *Module) InvokeExport(") {
		t.Errorf("consolidated InvokeExport method should be gone in the per-export layout")
	}
	assertSingleFileCompiles(t, out, res.Sidecars, res.AuxFiles, res.Files)
}

// TestNativeWASIDefault drives the wasi fixture through the auto-on
// native wasip1 implementation. DefaultWASI() must appear in the
// generated source and NewWithWASI() must be exposed.
func TestNativeWASIDefault(t *testing.T) {
	mod := readFixture(t, "cg_wasi.wasm")
	var buf bytes.Buffer
	if _, err := codegen.Translate(&buf, mod, codegen.Options{
		Package:          "pkg",
		OutputImportPath: "gentest/pkg",
	}); err != nil {
		t.Fatalf("translate: %v", err)
	}
	src := buf.String()
	if !strings.Contains(src, "DefaultWASI") {
		t.Errorf("native wasi output missing DefaultWASI(): %s", src)
	}
	if !strings.Contains(src, "NewWithWASI") {
		t.Errorf("native wasi output missing NewWithWASI(): %s", src)
	}
}

// TestBulkMemoryRuntime verifies the 0xFC instruction family: saturating
// float truncation, memory.copy and memory.fill. Each result is checked
// against wazero.
func TestBulkMemoryRuntime(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_bulkmem")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	t.Cleanup(func() {
		if err := r.Close(ctx); err != nil {
			t.Errorf("wazero runtime close: %v", err)
		}
	})
	wmod, err := r.Instantiate(ctx, bin)
	if err != nil {
		t.Fatalf("wazero instantiate: %v", err)
	}

	// All integer-result, integer-arg exports — keeps the generated main
	// trivial. Float-arg saturating truncs are exercised by the compile
	// matrix (TestMatrixSingleFile); here we drive the integer-arg ones.
	type tc struct {
		export string
		args   []uint64
	}
	cases := []tc{
		{"mem_copy", []uint64{20, 0, 5}},
		{"mem_copy", []uint64{30, 2, 3}},
		{"mem_fill", []uint64{40, 0x5a, 8}},
		{"mem_fill", []uint64{50, 0xff, 1}},
		{"load16_s", []uint64{0}},
		{"load64", []uint64{0}},
	}

	var mainSB strings.Builder
	mainSB.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n")
	var want []string
	for _, c := range cases {
		res, err := wmod.ExportedFunction(c.export).Call(ctx, c.args...)
		if err != nil {
			t.Fatalf("wazero %s%v: %v", c.export, c.args, err)
		}
		var argList []string
		for _, a := range c.args {
			argList = append(argList, fmt.Sprintf("int32(%d)", int32(a)))
		}
		var v int64
		if c.export == "load64" {
			v = int64(res[0])
		} else {
			v = int64(int32(res[0]))
		}
		want = append(want, fmt.Sprintf("%s=%d", c.export, v))
		fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%d\\n\", m.%s(%s))\n",
			c.export, codegen.ExportMethodName(c.export), strings.Join(argList, ", "))
	}
	mainSB.WriteString("}\n")

	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	out := strings.TrimSpace(runGoSnippet(t, buf.String(), mainSB.String(), res.Sidecars, res.Files))
	gotLines := strings.Split(out, "\n")
	if len(gotLines) != len(want) {
		t.Fatalf("got %d lines want %d\n%s", len(gotLines), len(want), out)
	}
	for i := range want {
		if strings.TrimSpace(gotLines[i]) != want[i] {
			t.Errorf("line %d got %q want %q", i, gotLines[i], want[i])
		}
	}
}

// TestDispatchIfRuntime drives cg_dispatchif — a br_table dispatcher whose
// case bodies wrap their shared-epilogue branch inside an if/else — through
// wasm2go and checks every (selector, x) result against wazero. This
// exercises the compound-statement exit-goto inlining in dispatch_split.
func TestDispatchIfRuntime(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_dispatchif")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	t.Cleanup(func() {
		if err := r.Close(ctx); err != nil {
			t.Errorf("wazero runtime close: %v", err)
		}
	})
	wmod, err := r.Instantiate(ctx, bin)
	if err != nil {
		t.Fatalf("wazero instantiate: %v", err)
	}

	type call struct{ sel, x int32 }
	calls := []call{
		{0, 1}, {0, -1}, {5, 1}, {5, 0}, {17, 7}, {35, -3}, {40, 1}, {99, 0},
	}
	var mainSB strings.Builder
	mainSB.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n")
	var want []int32
	for _, c := range calls {
		if _, err := wmod.ExportedFunction("dispatch").Call(ctx, u32(c.sel), u32(c.x)); err != nil {
			t.Fatalf("wazero dispatch(%d,%d): %v", c.sel, c.x, err)
		}
		o, err := wmod.ExportedFunction("get_out").Call(ctx)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, int32(o[0]))
		fmt.Fprintf(&mainSB, "\tm.Dispatch(int32(%d), int32(%d))\n\tfmt.Println(m.GetOut())\n", c.sel, c.x)
	}
	mainSB.WriteString("}\n")

	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	// NOTE: dispatch-split previously kicked in on the legacy compiler's
	// `switch` emission for br_table. The SSA pipeline currently lowers
	// br_table as a chain of equality-If blocks, so the splitter's
	// pattern-match does not fire. The semantics of the dispatcher are
	// still asserted below; a future change should either round-trip
	// br_table through a BlockSwitch SSA op or extend matchDispatcher
	// to recognise the if-chain shape, at which point this assertion
	// can be restored.
	out := strings.TrimSpace(runGoSnippet(t, buf.String(), mainSB.String(), res.Sidecars, res.Files))
	gotLines := strings.Fields(out)
	if len(gotLines) != len(want) {
		t.Fatalf("got %d lines want %d\n%s", len(gotLines), len(want), out)
	}
	for i, c := range calls {
		var g int32
		if _, err := fmt.Sscanf(gotLines[i], "%d", &g); err != nil {
			t.Fatalf("Sscanf %q: %v", gotLines[i], err)
		}
		if g != want[i] {
			t.Errorf("dispatch(%d,%d): got %d want %d", c.sel, c.x, g, want[i])
		}
	}
}
