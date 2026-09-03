package transpile_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/transpile"
)

// asmOverrideWat exports sumf(ptr, n) -> f32: the sum of n f32 values
// at ptr in linear memory.
const asmOverrideWat = `(module
  (memory (export "memory") 1)
  (func (export "sumf") (param $p i32) (param $n i32) (result f32)
    (local $acc f32)
    (block $done
      (loop $l
        (br_if $done (i32.le_s (local.get $n) (i32.const 0)))
        (local.set $acc (f32.add (local.get $acc) (f32.load (local.get $p))))
        (local.set $p (i32.add (local.get $p) (i32.const 4)))
        (local.set $n (i32.sub (local.get $n) (i32.const 1)))
        (br $l)))
    (local.get $acc)))
`

// Override bodies for the host baselines. Both follow the contract:
// arguments at l0+8 / l1+12 / r0+16 (FP), memory through the base and
// size registers the prologue loads, every access range checked
// against the size with the miss sent to ovr_oob, no calls.
const asmOverrideNeon = `	MOVWU	l0+8(FP), R1
	MOVW	l1+12(FP), R2
	FMOVS	$0.0, F0
	CMPW	$1, R2
	BLT	done
	LSL	$2, R2, R3
	ADD	R1, R3, R3
	CMP	R3, R21
	BLO	ovr_oob
	ADD	R20, R1, R1
loop:
	FMOVS	(R1), F1
	FADDS	F1, F0, F0
	ADD	$4, R1, R1
	SUBW	$1, R2, R2
	CBNZW	R2, loop
done:
	FMOVS	F0, r0+16(FP)
	RET
`

const asmOverrideSSE4 = `	MOVL	l0+8(FP), SI
	MOVL	l1+12(FP), CX
	XORPS	X0, X0
	TESTL	CX, CX
	JLE	done
	MOVL	CX, DX
	SHLQ	$2, DX
	ADDQ	SI, DX
	CMPQ	R15, DX
	JCS	ovr_oob
	ADDQ	R14, SI
loop:
	ADDSS	(SI), X0
	ADDQ	$4, SI
	DECL	CX
	JNZ	loop
done:
	MOVSS	X0, r0+16(FP)
	RET
`

const asmOverrideManifest = `{
  "version": 1,
  "memory64": false,
  "functions": [{
    "export": "sumf",
    "params": ["i32", "i32"],
    "result": "f32",
    "bodies": [
      {"arch": "arm64", "feature": "neon", "frame": 0, "file": "sumf_arm64_neon.s"},
      {"arch": "amd64", "feature": "sse4", "frame": 0, "file": "sumf_amd64_sse4.s"}
    ]
  }]
}
`

// asmOverrideDriver sums a few ranges through the export. With the
// "oob" argument it also calls the export once past the end of memory:
// the override contract requires that to reach ovr_oob and trap (the
// lowered scalar path does not check bounds — it relies on the host
// fault — so only the override build runs that probe).
const asmOverrideDriver = `package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"

	"ovrtest/pkg"
)

func main() {
	m := pkg.New()
	mem := m.Memory()
	for i := 0; i < 1000; i++ {
		binary.LittleEndian.PutUint32(mem[64+4*i:], math.Float32bits(float32(i)*0.25-3))
	}
	for _, c := range [][2]int32{{64, 0}, {64, 1}, {64, 7}, {68, 100}, {64, 1000}, {64, -5}} {
		fmt.Println(m.Sumf(c[0], c[1]))
	}
	if len(os.Args) > 1 && os.Args[1] == "oob" {
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Println("trap")
				}
			}()
			fmt.Println(m.Sumf(int32(len(mem))-8, 4))
		}()
	}
}
`

// TestAsmOverrideEndToEnd transpiles the module twice — lowered, and
// with the project-supplied bodies — builds both, and requires the
// same outputs, including the out-of-bounds trap.
func TestAsmOverrideEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("wat2wasm"); err != nil {
		t.Skip("wat2wasm not installed")
	}
	dir := t.TempDir()
	write := func(rel string, data string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("t.wat", asmOverrideWat)
	write("overrides/sumf_arm64_neon.s", asmOverrideNeon)
	write("overrides/sumf_amd64_sse4.s", asmOverrideSSE4)
	write("overrides/overrides.json", asmOverrideManifest)
	if out, err := exec.Command("wat2wasm", "--output="+filepath.Join(dir, "t.wasm"), filepath.Join(dir, "t.wat")).CombinedOutput(); err != nil {
		t.Fatalf("wat2wasm: %v\n%s", err, out)
	}
	bin, err := os.ReadFile(filepath.Join(dir, "t.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	restore := transpile.SetMultiPackageThreshold(1 << 30)
	defer restore()

	run := func(name, manifest string, args ...string) (string, string) {
		t.Helper()
		m, err := transpile.Parse(bytes.NewReader(bin))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		var buf bytes.Buffer
		res, err := transpile.Translate(&buf, m, transpile.Options{
			Package:          "pkg",
			OutputImportPath: "ovrtest/pkg",
			AsmOverrides:     manifest,
		})
		if err != nil {
			t.Fatalf("%s: Translate: %v", name, err)
		}
		mod := filepath.Join(dir, name)
		w := func(rel string, data []byte) {
			p := filepath.Join(mod, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		w("go.mod", []byte("module ovrtest\n\ngo 1.25.0\n"))
		w("pkg/gen.go", buf.Bytes())
		var asm strings.Builder
		for rel, data := range res.Files {
			w("pkg/"+rel, data)
			if strings.HasSuffix(rel, ".s") {
				asm.Write(data)
			}
		}
		for n, data := range res.Sidecars {
			w("pkg/"+n, data)
		}
		w("main.go", []byte(asmOverrideDriver))
		cmd := exec.Command("go", append([]string{"run", "."}, args...)...)
		cmd.Dir = mod
		// The asm bundle is built for amd64 only at GOAMD64=v2 or
		// higher (the SSE4.1 baseline); v1 compiles the pure tree.
		cmd.Env = append(os.Environ(), "GOARCH="+runtime.GOARCH, "GOAMD64=v2")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: go run: %v\n%s", name, err, out)
		}
		return string(out), asm.String()
	}
	plain, plainAsm := run("plain", "")
	over, overAsm := run("override", filepath.Join(dir, "overrides", "overrides.json"), "oob")
	overLines := strings.Split(strings.TrimSpace(over), "\n")
	if len(overLines) != 7 || overLines[6] != "trap" {
		t.Fatalf("override build: expected six sums and a trap:\n%s", over)
	}
	if want := strings.Join(overLines[:6], "\n") + "\n"; plain != want {
		t.Fatalf("outputs differ\nlowered:\n%s\noverride:\n%s", plain, want)
	}
	if overLines[0] != "0" || overLines[2] != "-15.75" {
		t.Fatalf("unexpected sums:\n%s", over)
	}
	feature := map[string]string{"arm64": "ovrneon", "amd64": "ovrsse4"}[runtime.GOARCH]
	if !strings.Contains(overAsm, feature) || !strings.Contains(overAsm, "ovr_oob:") {
		t.Fatalf("override body not emitted for %s", runtime.GOARCH)
	}
	if strings.Contains(plainAsm, "ovr_oob:") {
		t.Fatal("lowered build must not carry override bodies")
	}
}
