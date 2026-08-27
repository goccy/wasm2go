package transpile_test

// End-to-end coverage for SIMD loop unrolling: the cg_simd_loop
// fixture runs its counted loops at every trip count around the
// unroll factor (remainder loop, exact multiples, below-factor trips)
// and under every pass configuration — unrolling on and off, fusion
// on and off — and all configurations must agree with the Go-side
// reference sums.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/transpile"
)

func TestGcasmSimdLoopUnroll(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_simd_loop.wasm")

	// The generated main seeds memory with a deterministic pattern and
	// prints loopsum/dot2 for trips 0..9 (trip 0 skips the loop by the
	// module's own guard).
	mainSrc := `package main

import (
	"fmt"

	"simdlooptest/pkg"
)

func main() {
	m := pkg.New()
	for i := int32(0); i < 1024; i++ {
		m.Seed8(i, (i*7+3)%256)
	}
	// scaledot block headers: u16 table indexes kept small so every
	// table entry lands inside the seeded region.
	for it := int32(0); it < 10; it++ {
		for _, base := range []int32{0, 256} {
			m.Seed8(base+18*it, (base/8+it*3)%64)
			m.Seed8(base+18*it+1, 0)
		}
	}
	for i := int32(0); i < 160; i++ {
		m.Seed8(2048+i, (i*13+5)%256)
		m.Seed8(3072+i, (i*11+9)%256)
	}
	for n := int32(0); n <= 9; n++ {
		m.Axpy(2048, 3072, n)
		m.Strideaxpy(2048, 3072, n, 20)
		m.Axpy64(2048, 3072, int64(n))
		fmt.Print(m.Loopsum(0, n), " ", m.Dot2(0, 256, n), " ", m.Quantnarrow(0, n), " ", m.Scaledot(0, 256, n), " ", m.Loopsum(3072, n), " ", m.Gathersum(0, n), " ", m.Loopsum64(0, int64(n)), " ", m.Gemm4(0, 512, int64(n), 20), " ")
	}
	fmt.Println()
}
`
	build := func(t *testing.T, opts transpile.Options, wantChase bool) string {
		t.Helper()
		m, err := transpile.Parse(bytes.NewReader(bin))
		if err != nil {
			t.Fatal(err)
		}
		opts.Package = "pkg"
		opts.OutputImportPath = "simdlooptest/pkg"
		var buf bytes.Buffer
		res, err := transpile.Translate(&buf, m, opts)
		if err != nil {
			t.Fatalf("translate: %v", err)
		}
		if wantChase {
			// The scaledot scale chain must have been internalized as
			// scalar nodes (the synthetic helper bodies then call the
			// scalar helpers in their pure fallback).
			chased := bytes.Contains(buf.Bytes(), []byte("simd_scalar_i32_load16_u"))
			for _, data := range res.Files {
				chased = chased || bytes.Contains(data, []byte("simd_scalar_i32_load16_u"))
			}
			if !chased {
				t.Error("scale chain was not internalized: no simd_scalar_i32_load16_u in generated output")
			}
		}
		dir := t.TempDir()
		w := func(rel string, data []byte) {
			p := filepath.Join(dir, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		w("go.mod", []byte("module simdlooptest\n\ngo 1.25.0\n"))
		if buf.Len() > 0 {
			w("pkg/gen.go", buf.Bytes())
		}
		for _, set := range []map[string][]byte{res.Files, res.Sidecars, res.AuxFiles} {
			for name, data := range set {
				if len(data) == 0 {
					continue
				}
				w("pkg/"+name, data)
			}
		}
		w("main.go", []byte(mainSrc))
		cmd := exec.Command("go", "run", ".")
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go run: %v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}

	// Go-side reference.
	mem := make([]byte, 4096)
	for i := 0; i < 1024; i++ {
		mem[i] = byte((i*7 + 3) % 256)
	}
	for it := int32(0); it < 10; it++ {
		for _, base := range []int32{0, 256} {
			mem[base+18*it] = byte((base/8 + it*3) % 64)
			mem[base+18*it+1] = 0
		}
	}
	for i := int32(0); i < 160; i++ {
		mem[2048+i] = byte((i*13 + 5) % 256)
		mem[3072+i] = byte((i*11 + 9) % 256)
	}
	sat32 := func(f float64) int32 {
		switch {
		case f != f: // NaN
			return 0
		case f >= 2147483647:
			return 2147483647
		case f <= -2147483648:
			return -2147483648
		}
		return int32(f)
	}
	loopsum := func(p, n int32) int32 {
		var acc [4]int32
		for it := int32(0); it < n; it++ {
			for l := 0; l < 4; l++ {
				off := int(p) + 16*int(it) + 4*l
				acc[l] += int32(uint32(mem[off]) | uint32(mem[off+1])<<8 | uint32(mem[off+2])<<16 | uint32(mem[off+3])<<24)
			}
		}
		return acc[0] + acc[1] + acc[2] + acc[3]
	}
	dot2 := func(x, y, n int32) int32 {
		var acc [4]int32
		for it := int32(0); it < n; it++ {
			for lane := 0; lane < 16; lane++ {
				a := int32(int8(mem[int(x)+16*int(it)+lane]))
				b := int32(int8(mem[int(y)+16*int(it)+lane]))
				acc[(lane/2)%4] += a * b
			}
		}
		// dot pairs adjacent i16 products into i32 lanes; the lane
		// mapping above mirrors low/high extend + dot + add exactly
		// for the summed result (all four lanes are added together
		// below, so only the total needs to match).
		return acc[0] + acc[1] + acc[2] + acc[3]
	}
	quantnarrow := func(p, n int32) int32 {
		sat16 := func(v int32) int16 {
			if v > 32767 {
				return 32767
			}
			if v < -32768 {
				return -32768
			}
			return int16(v)
		}
		sat8 := func(v int16) int8 {
			if v > 127 {
				return 127
			}
			if v < -128 {
				return -128
			}
			return int8(v)
		}
		scales := [4]float32{0.5, 0.25, 2.0, 4.0}
		var acc int32
		for it := int32(0); it < n; it++ {
			var i8 [16]int8
			for q := 0; q < 4; q++ { // quarter = one source vector
				for l := 0; l < 4; l++ {
					off := int(p) + 64*int(it) + 16*q + 4*l
					f := math.Float32frombits(binary.LittleEndian.Uint32(mem[off:]))
					r := math.RoundToEven(float64(float32(f) * scales[q]))
					i8[8*(q/2)+(q%2)*4+l] = sat8(sat16(sat32(r)))
				}
			}
			acc += int32(i8[0]) + int32(i8[5]) + int32(i8[10]) + int32(i8[15])
		}
		return acc
	}
	scaledot := func(x, y, n int32) int32 {
		lut := func(base int32) float32 {
			idx := int32(uint32(mem[base]) | uint32(mem[base+1])<<8)
			return math.Float32frombits(binary.LittleEndian.Uint32(mem[idx<<2+768:]))
		}
		var acc [4]float32
		for it := int32(0); it < n; it++ {
			bx, by := x+18*it, y+18*it
			prod := lut(bx) * lut(by)
			for l := int32(0); l < 4; l++ {
				ax := int32(binary.LittleEndian.Uint32(mem[bx+2+4*l:]))
				ay := int32(binary.LittleEndian.Uint32(mem[by+2+4*l:]))
				acc[l] += prod * (float32(ax) * float32(ay))
			}
		}
		var out int32
		for l := 0; l < 4; l++ {
			out += sat32(float64(acc[l]))
		}
		return out
	}
	gathersum := func(p, n int32) int32 {
		ld32 := func(off int32) int32 {
			return int32(binary.LittleEndian.Uint32(mem[off:]))
		}
		var acc [4]int32
		for it := int32(0); it < n; it++ {
			b := p + 24*it
			acc[0] += ld32(b)
			acc[1] += ld32(b + 20)
			acc[2] += ld32(b + 40)
			acc[3] += ld32(b + 60)
			for l := int32(0); l < 4; l++ {
				acc[l] += int32(uint32(binary.LittleEndian.Uint16(mem[b+8+2*l:])))
			}
		}
		return acc[0] + acc[1] + acc[2] + acc[3]
	}
	axpy := func(x, y, n int32) {
		for it := int32(0); it < n; it++ {
			for l := int32(0); l < 4; l++ {
				xo, yo := x+16*it+4*l, y+16*it+4*l
				xa := int32(binary.LittleEndian.Uint32(mem[xo:]))
				ya := int32(binary.LittleEndian.Uint32(mem[yo:]))
				binary.LittleEndian.PutUint32(mem[yo:], math.Float32bits(float32(ya)+float32(xa)))
			}
		}
	}
	gemm4 := func(a, b int32, n int64, stride int32) int32 {
		ld := func(off int32) [4]uint32 {
			var v [4]uint32
			for l := int32(0); l < 4; l++ {
				v[l] = binary.LittleEndian.Uint32(mem[off+4*l:])
			}
			return v
		}
		var acc [4][4]uint32
		for it := int64(0); it < n; it++ {
			ao := a + 4*int32(it)
			bo := b + stride*int32(it)
			x0, x1 := ld(bo), ld(bo+16)
			s0 := binary.LittleEndian.Uint32(mem[ao:])
			s1 := binary.LittleEndian.Uint32(mem[ao+128:])
			for l := 0; l < 4; l++ {
				f := func(x uint32, sc uint32) uint32 {
					return math.Float32bits(math.Float32frombits(x) * math.Float32frombits(sc))
				}
				acc[0][l] += 0 // layout note: accumulate below
				acc[0][l] = math.Float32bits(math.Float32frombits(acc[0][l]) + math.Float32frombits(f(x0[l], s0)))
				acc[1][l] = math.Float32bits(math.Float32frombits(acc[1][l]) + math.Float32frombits(f(x0[l], s1)))
				acc[2][l] = math.Float32bits(math.Float32frombits(acc[2][l]) + math.Float32frombits(f(x1[l], s0)))
				acc[3][l] = math.Float32bits(math.Float32frombits(acc[3][l]) + math.Float32frombits(f(x1[l], s1)))
			}
		}
		var out int32
		for l := 0; l < 4; l++ {
			out += int32(acc[0][l] + acc[1][l] + acc[2][l] + acc[3][l])
		}
		return out
	}
	strideaxpy := func(x, y, n, stride int32) {
		for it := int32(0); it < n; it++ {
			for l := int32(0); l < 4; l++ {
				xo, yo := x+stride*it+4*l, y+stride*it+4*l
				xa := int32(binary.LittleEndian.Uint32(mem[xo:]))
				ya := int32(binary.LittleEndian.Uint32(mem[yo:]))
				binary.LittleEndian.PutUint32(mem[yo:], math.Float32bits(float32(ya)+float32(xa)))
			}
		}
	}
	var want strings.Builder
	for n := int32(0); n <= 9; n++ {
		axpy(2048, 3072, n)
		strideaxpy(2048, 3072, n, 20)
		axpy(2048, 3072, n) // axpy64 mirrors axpy semantics
		fmt.Fprintf(&want, "%d %d %d %d %d %d %d %d ", loopsum(0, n), dot2(0, 256, n), quantnarrow(0, n), scaledot(0, 256, n), loopsum(3072, n), gathersum(0, n), loopsum(0, n), gemm4(0, 512, int64(n), 20))
	}

	configs := []struct {
		name      string
		opts      transpile.Options
		wantChase bool
	}{
		{"unroll+fuse", transpile.Options{SIMDUnroll: 4}, true},
		{"loopfuse", transpile.Options{FuseLoops: true}, false},
		{"unroll+loopfuse", transpile.Options{SIMDUnroll: 4, FuseLoops: true}, true},
		{"unroll+loopfuse2", transpile.Options{SIMDUnroll: 4, FuseLoops: true, FuseLoopUnroll: 2}, true},
		{"nounroll", transpile.Options{}, false},
		// Loop outlining (threshold 2 = outline every eligible loop),
		// alone and combined with unroll + loop fusion the way the
		// production pipeline stacks them.
		{"outline", transpile.Options{OutlineMinValues: 2}, false},
		{"outline+unroll+loopfuse", transpile.Options{OutlineMinValues: 2, SIMDUnroll: 4, FuseLoops: true}, false},
	}
	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			got := build(t, cfg.opts, cfg.wantChase)
			if got != strings.TrimSpace(want.String()) {
				t.Errorf("got  %q\nwant %q", got, strings.TrimSpace(want.String()))
			}
		})
	}
}
