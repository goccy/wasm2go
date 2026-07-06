package gcasm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// runArm64Gate assembles + links the generated arm64 test binary — which
// drives the emitted .s through the real Go assembler and linker, and so
// catches bad operands, undefined symbols, and frame/pcsp errors on ANY
// host arch — and then executes it ONLY when the host can run arm64
// binaries. A non-arm64 runner (e.g. linux/amd64 CI) cannot exec an arm64
// binary ("exec format error"), so there we assemble-verify and skip the
// value check. On an arm64 host (or `GOARCH=arm64 go test` on Apple
// Silicon) the binary runs natively and the asm-vs-pure parity is checked.
func runArm64Gate(t *testing.T, dir, pkg, runName, diag string) {
	t.Helper()
	bin := filepath.Join(dir, "gcasm_gate.test")
	build := exec.Command("go", "test", "-c", "-o", bin, pkg)
	build.Dir = dir
	build.Env = append(os.Environ(), "GOARCH=arm64")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("arm64 assemble/link failed: %v\n%s\n--- asm ---\n%s", err, out, diag)
	}
	if runtime.GOARCH != "arm64" {
		t.Skipf("assembled+linked OK; skipping arm64 execution on %s/%s host", runtime.GOOS, runtime.GOARCH)
	}
	cmd := exec.Command(bin, "-test.run", runName, "-test.v")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("arm64 execution failed: %v\n%s\n--- asm ---\n%s", err, out, diag)
	}
}
