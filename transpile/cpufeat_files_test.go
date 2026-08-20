package transpile_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/transpile"
)

// TestCPUFeatFilesSurviveGcasmCleanup transpiles a SIMD module end to
// end and asserts the CPU feature-detection files reach the output.
// The gcasm backend's cleanup pass deletes the codegen own-backend
// amd64 decls/asm in favor of the bundle's; cpufeat_amd64.go carries
// an amd64 build tag and once fell to that filter, which broke the
// bundle build (the feature-dispatch stubs read base.HasAVX2).
func TestCPUFeatFilesSurviveGcasmCleanup(t *testing.T) {
	wasm := testfixture.Wasm(t, "cg_simd")
	res, err := transpile.Transpile(bytes.NewReader(wasm), io.Discard,
		transpile.Options{Package: "wasm2go", OutputImportPath: "example.com/x"})
	if err != nil {
		t.Fatalf("transpile: %v", err)
	}
	for _, want := range []string{
		"cpufeat_amd64.go", "cpufeat_amd64.s",
		"cpufeat_arm64_darwin.go", "cpufeat_arm64_linux.go", "cpufeat_arm64_other.go",
	} {
		if _, ok := res.Files[want]; !ok {
			t.Errorf("missing %s in transpile output", want)
		}
	}
}
