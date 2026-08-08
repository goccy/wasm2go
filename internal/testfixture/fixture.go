// Package testfixture compiles .wat test fixtures to wasm on demand.
// It is a non-test package so that any test binary in the module can import it.
package testfixture

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var (
	cacheMu sync.Mutex
	cache   = map[string][]byte{}
)

// Wasm compiles testdata/<basename>.wat via wat2wasm and returns the wasm bytes.
// name may include or omit the .wasm or .wat extension — both are accepted and
// stripped to derive the bare basename.
// Results are cached per-process so each fixture is compiled at most once.
func Wasm(t testing.TB, name string) []byte {
	t.Helper()

	// Strip known extensions to get the bare basename.
	base := name
	if strings.HasSuffix(base, ".wasm") {
		base = strings.TrimSuffix(base, ".wasm")
	} else if strings.HasSuffix(base, ".wat") {
		base = strings.TrimSuffix(base, ".wat")
	}

	cacheMu.Lock()
	if data, ok := cache[base]; ok {
		cacheMu.Unlock()
		return data
	}
	cacheMu.Unlock()

	root := repoRoot()
	watPath := filepath.Join(root, "testdata", base+".wat")
	if _, err := os.Stat(watPath); err != nil {
		t.Fatalf("testfixture: wat source not found: %s", watPath)
	}

	// --enable-exceptions lets EH fixtures (try/catch/throw/tag) compile; it
	// only enables the feature, so non-EH fixtures are unaffected.
	cmd := exec.Command("wat2wasm", "--enable-exceptions", "--enable-threads", "--enable-memory64", "--output=-", watPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("testfixture: wat2wasm %s: %v\n%s", base, err, stderr.String())
	}
	data := stdout.Bytes()

	cacheMu.Lock()
	cache[base] = data
	cacheMu.Unlock()

	return data
}

// WasmPath compiles testdata/<basename>.wat and writes the result to a
// temporary file whose path is returned. The file is owned by t.TempDir()
// and is cleaned up when the test ends. This is useful for tests that must
// hand a file path to an external binary (e.g. the wasm2go CLI).
func WasmPath(t testing.TB, name string) string {
	t.Helper()
	data := Wasm(t, name)

	// Derive a clean basename for the temp-file name.
	base := name
	if strings.HasSuffix(base, ".wasm") {
		base = strings.TrimSuffix(base, ".wasm")
	} else if strings.HasSuffix(base, ".wat") {
		base = strings.TrimSuffix(base, ".wat")
	}

	dir := t.TempDir()
	p := filepath.Join(dir, base+".wasm")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatalf("testfixture: write temp wasm %s: %v", base, err)
	}
	return p
}

// repoRoot locates the repository root by walking up from this source file
// until it finds a directory containing go.mod.
func repoRoot() string {
	// runtime.Caller(0) gives the absolute path of this source file.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("testfixture: runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic(fmt.Sprintf("testfixture: go.mod not found above %s", filepath.Dir(file)))
		}
		dir = parent
	}
}
