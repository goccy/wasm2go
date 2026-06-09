package codegen_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestBuildAsmPackageArith is the codegen + asmgen integration
// happy-path. arith.wat goes through BuildAsmPackage and the
// resulting Go package is exercised twice: once on the host
// (amd64 — the asm bodies run) and once cross-built for arm64
// (assemble-only). On a non-amd64 host the running portion is
// skipped; the cross-build portion always runs.
func TestBuildAsmPackageArith(t *testing.T) {
	bin := testfixture.Wasm(t, "arith")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Translate now always emits the asm bundle. Single-pkg path
	// writes the shared file to w and Result.Files carries the
	// pure-Go fallback + the asm bundle.
	var mainBuf bytes.Buffer
	res, err := codegen.Translate(&mainBuf, mod, codegen.Options{
		Package:          "arith",
		OutputImportPath: "asmgentest/arith",
	})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if res.Files == nil {
		t.Fatal("Translate(asm-on) returned no Files")
	}

	// Sanity check: every expected asm/fallback file is present.
	// When both archs declare the same symbols and no stubs are
	// emitted, the per-arch decls files are collapsed into a single
	// decls.go gated on `//go:build amd64 || arm64`.
	expect := []string{"arith_pure.go", "decls.go", "amd64.s", "arm64.s"}
	for _, f := range expect {
		if _, ok := res.Files[f]; !ok {
			t.Errorf("missing %q in output (have: %v)", f, fileList(res.Files))
		}
	}

	dir := t.TempDir()
	// Place the arith package at <dir>/arith/ so the driver can
	// import it as `asmgentest/arith`. Writing into the module
	// root would force the driver to import the module path itself,
	// which conflicts with the package being a non-main library.
	pkgDir := filepath.Join(dir, "arith")
	if err := os.Mkdir(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir pkg: %v", err)
	}
	mustWriteAll(t, pkgDir, res.Files)
	mustWriteAll(t, pkgDir, map[string][]byte{
		"arith.go": mainBuf.Bytes(),
	})
	mustWriteAll(t, dir, map[string][]byte{
		"go.mod": []byte("module asmgentest\n\ngo 1.25\n"),
	})

	// Cross-build arm64 — assemble-only validation.
	t.Run("cross-build-arm64", func(t *testing.T) {
		cmd := exec.Command("go", "build", "./...")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("GOARCH=arm64 go build: %v\n%s", err, out)
		}
	})

	// amd64 execution — drop in a driver main package next to the
	// arith package and call selected exports through the asm path.
	t.Run("amd64-run", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			t.Skipf("GOARCH=%s; amd64-only run", runtime.GOARCH)
		}
		drvDir := filepath.Join(dir, "driver")
		if err := os.Mkdir(drvDir, 0o755); err != nil {
			t.Fatalf("mkdir driver: %v", err)
		}
		mustWriteAll(t, drvDir, map[string][]byte{
			"main.go": []byte(`package main

import (
	"fmt"
	"os"
	"strconv"

	arith "asmgentest/arith"
)

func main() {
	m := arith.New()
	switch os.Args[1] {
	case "add":
		a, _ := strconv.ParseInt(os.Args[2], 10, 32)
		b, _ := strconv.ParseInt(os.Args[3], 10, 32)
		fmt.Println(m.Add(int32(a), int32(b)))
	case "mul64":
		a, _ := strconv.ParseInt(os.Args[2], 10, 64)
		b, _ := strconv.ParseInt(os.Args[3], 10, 64)
		fmt.Println(m.Mul64(a, b))
	case "div_s":
		a, _ := strconv.ParseInt(os.Args[2], 10, 32)
		b, _ := strconv.ParseInt(os.Args[3], 10, 32)
		fmt.Println(m.DivS(int32(a), int32(b)))
	case "rotl":
		a, _ := strconv.ParseInt(os.Args[2], 10, 32)
		b, _ := strconv.ParseInt(os.Args[3], 10, 32)
		fmt.Println(m.Rotl(int32(a), int32(b)))
	default:
		fmt.Fprintln(os.Stderr, "unknown:", os.Args[1])
		os.Exit(2)
	}
}
`),
		})

		exe := filepath.Join(drvDir, "driver")
		cb := exec.Command("go", "build", "-o", exe, ".")
		cb.Dir = drvDir
		if out, err := cb.CombinedOutput(); err != nil {
			t.Fatalf("driver build: %v\n%s", err, out)
		}
		cases := []struct {
			args []string
			want string
		}{
			{[]string{"add", "2", "3"}, "5"},
			{[]string{"mul64", "6", "7"}, "42"},
			{[]string{"div_s", "20", "4"}, "5"},
			{[]string{"rotl", "1", "1"}, "2"},
		}
		for _, tc := range cases {
			out, err := exec.Command(exe, tc.args...).CombinedOutput()
			if err != nil {
				t.Errorf("%v: %v\n%s", tc.args, err, out)
				continue
			}
			got := strings.TrimSpace(string(out))
			if got != tc.want {
				t.Errorf("%v = %q, want %q", tc.args, got, tc.want)
			}
		}
	})
}

// TestBuildAsmPackageMultiPkg drives cg_manyfuncs.wat through
// BuildAsmPackage with multi-package mode forced (chunkBytes=0).
// The fixture's 30 leaf functions plus sum_all distribute across
// several chunks, exercising cross-chunk asm CALLs (sum_all in one
// chunk calls leaves living in other chunks). The test asserts the
// full bundle cross-builds for both amd64 and arm64; running the
// driver end-to-end is left to a follow-up because cg_manyfuncs
// also exercises globals and call_indirect whose driver scaffold
// is non-trivial to script.
func TestBuildAsmPackageMultiPkg(t *testing.T) {
	// Threshold = 64 forces small chunks so each chunk's pair of
	// leaf functions ends up in a separate package; sum_all (the
	// 31st function) then makes cross-chunk asm CALLs to leaves
	// spread across other chunks — that's the actual surface this
	// test exists to validate.
	restore := codegen.SetMultiPackageThreshold(64)
	defer restore()

	bin := testfixture.Wasm(t, "cg_manyfuncs")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := codegen.Translate(bytes.NewBuffer(nil), mod, codegen.Options{
		Package:          "manyfuncs",
		OutputImportPath: "asmgentest/manyfuncs",
	})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if res.Files == nil {
		t.Fatal("multi-pkg test expected Files map (chunk threshold = 0)")
	}

	// Sanity check structure: base must exist, every chunk must
	// have its asm+pure trio, and wrappers must land in base since
	// cg_manyfuncs has globals and call_indirect.
	hasBase := false
	hasWrappers := false
	chunkPureCount := 0
	for path := range res.Files {
		switch path {
		case "base/base.go":
			hasBase = true
		case "base/wrappers.go":
			hasWrappers = true
		}
		if strings.HasSuffix(path, "_pure.go") && strings.HasPrefix(path, "p") {
			chunkPureCount++
		}
	}
	if !hasBase {
		t.Errorf("missing base/base.go: %v", fileList(res.Files))
	}
	if !hasWrappers {
		t.Errorf("missing base/wrappers.go (cg_manyfuncs needs them): %v", fileList(res.Files))
	}
	if chunkPureCount < 1 {
		t.Errorf("no chunk _pure.go found: %v", fileList(res.Files))
	}

	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "manyfuncs")
	if err := os.Mkdir(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir pkg: %v", err)
	}
	mustWriteAll(t, pkgDir, res.Files)
	mustWriteAll(t, dir, map[string][]byte{
		"go.mod": []byte("module asmgentest\n\ngo 1.25\n"),
	})

	// Cross-build amd64 — verifies the entire multi-chunk asm
	// bundle assembles, types match, and the chain of chunk
	// imports resolves cross-package symbols at link time.
	t.Run("amd64", func(t *testing.T) {
		cmd := exec.Command("go", "build", "./...")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("amd64 build: %v\n%s", err, out)
		}
	})

	t.Run("arm64", func(t *testing.T) {
		cmd := exec.Command("go", "build", "./...")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("arm64 build: %v\n%s", err, out)
		}
	})
}

func mustWriteAll(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	for path, content := range files {
		full := filepath.Join(dir, path)
		if d := filepath.Dir(full); d != dir {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", d, err)
			}
		}
		if err := os.WriteFile(full, content, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

func fileList(m map[string][]byte) string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}

// Silence "imported and not used" for strconv when amd64-run branch
// is skipped at compile time (it always compiles, just may not run).
var _ = strconv.Itoa
