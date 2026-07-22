package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestEqzBranchFusion pins the emitted shape of the eqz→comparison
// lowering end to end: a branch on i32.eqz renders as a direct Go
// comparison (`l0 == int32(0)`), value uses render as
// `b2i32(x == 0)`, and the i32_eqz / i64_eqz helpers are gone from
// the output entirely.
func TestEqzBranchFusion(t *testing.T) {
	bin := testfixture.Wasm(t, "eqz_fuse.wat")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var all strings.Builder
	all.Write(buf.Bytes())
	for _, data := range res.Files {
		all.Write(data)
	}
	src := all.String()

	if strings.Contains(src, "i32_eqz") || strings.Contains(src, "i64_eqz") {
		t.Errorf("eqz helper survived in generated output")
	}
	if !strings.Contains(src, "l0 == int32(0)") {
		t.Errorf("expected fused i32 comparison `l0 == int32(0)` in output:\n%s", src)
	}
	if !strings.Contains(src, "l0 == int64(0)") {
		t.Errorf("expected fused i64 comparison `l0 == int64(0)` in output:\n%s", src)
	}
	// Branch position must be a bare `if x == 0`, not `!= 0` on a
	// materialized 0/1.
	if !strings.Contains(src, "if l0 == int32(0)") {
		t.Errorf("expected branch-fused `if l0 == int32(0)` in output:\n%s", src)
	}
}
