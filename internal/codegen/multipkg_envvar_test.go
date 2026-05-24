package codegen_test

import (
	"bytes"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
)

// TestMultiPackageEnvVarOverride verifies that the
// WASM2GO_MULTIPACKAGE_THRESHOLD environment variable forces the
// multi-package layout when the in-process override is unset.
// Subprocess invocations of the wasm2go CLI / library rely on this
// so they can override the threshold without an in-process Go hook.
func TestMultiPackageEnvVarOverride(t *testing.T) {
	// Setting in-process override to -1 keeps it unset so the env-var
	// fallback is what's exercised here.
	defer codegen.SetMultiPackageThreshold(-1)()
	t.Setenv("WASM2GO_MULTIPACKAGE_THRESHOLD", "0")

	mod := readFixture(t, "arith.wasm")
	res, err := codegen.Translate(nil, mod, codegen.Options{
		Package:          "wmod",
		OutputImportPath: "gentest/wmod",
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if _, ok := res.Files["base/base.go"]; !ok {
		t.Errorf("env-var override did not trigger multi-package layout: " +
			"base/base.go missing from Result.Files")
	}
}

// TestMultiPackageInProcessOverrideWinsOverEnv verifies that the
// in-process override (SetMultiPackageThreshold) takes priority over
// the env-var fallback, so a caller that explicitly sets the override
// is not silently subverted by an inherited env var.
func TestMultiPackageInProcessOverrideWinsOverEnv(t *testing.T) {
	// Env var asks for multi-package (threshold = 0); in-process
	// override sets a very high value so a tiny fixture cannot exceed
	// it. The in-process value wins, so we expect single-file output.
	t.Setenv("WASM2GO_MULTIPACKAGE_THRESHOLD", "0")
	defer codegen.SetMultiPackageThreshold(1 << 30)()

	mod := readFixture(t, "arith.wasm")
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{
		Package:          "wmod",
		OutputImportPath: "gentest/wmod",
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(res.Files) != 0 {
		t.Errorf("in-process override did not win over env: Result.Files = %d entries, want 0", len(res.Files))
	}
}
