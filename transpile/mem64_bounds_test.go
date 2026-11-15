package transpile_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/transpile"
)

// TestMem64OutOfBoundsTraps pins the bounds of a memory64 memory: an
// access whose bytes all lie below memory.size works, and one that
// reaches memory.size or past it traps — far past the memory, at 2^63,
// and at an address whose sum with the static offset wraps a u64 as
// well — for plain loads and stores of every width, static offsets
// below and above the memory's minimum, constant addresses, inline and
// helper atomics, v128 accesses (alone, sharing one coalesced range
// check, and fused into one region with other ops) and the bulk
// operations, before and after memory.grow (also a grow inside the
// accessing function). A trapped store writes nothing, and a store
// before a trapping load in the same function has happened. Accesses
// whose check another one's stands for (a later access off the same
// address that reaches further, one inside a branch, one whose address
// is an i64.add that wraps) trap as they would on their own. Both
// backends: the generated code as the host builds it, and the pure Go
// form. Which form the first is follows the build: the assembly on
// arm64 and on amd64 from GOAMD64=v2 up, the pure fallback otherwise —
// run the test with GOARCH=arm64 or GOAMD64=v2 to cover the assembly.
func TestMem64OutOfBoundsTraps(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts transpile.Options
	}{
		{name: "asm"},
		{name: "pure", opts: transpile.Options{PureOnly: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := runMem64(t, buildMem64With(t, "cg_mem64_bounds.wat", mem64BoundsMain, tc.opts))
			want := strings.TrimSpace(mem64BoundsWant)
			if got != want {
				gl, wl := strings.Split(got, "\n"), strings.Split(want, "\n")
				for i := 0; i < len(gl) || i < len(wl); i++ {
					var g, w string
					if i < len(gl) {
						g = gl[i]
					}
					if i < len(wl) {
						w = wl[i]
					}
					if g != w {
						t.Errorf("line %d:\ngot:  %s\nwant: %s", i+1, g, w)
					}
				}
			}
		})
	}
}

// mem64BoundsMain drives cg_mem64_bounds. Addresses are printed relative
// to memory.size ("end") so the expectations read as the rule they pin.
const mem64BoundsMain = `	m := pkg.New()
	end := uint64(m.Size()) * 65536
	run := func(label string, f func() any) {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("%s: trap %v\n", label, r)
			}
		}()
		fmt.Printf("%s: %v\n", label, f())
	}
	type at struct {
		label string
		addr  uint64
	}
	edges := func(size uint64) []at {
		return []at{
			{"end-size", end - size},
			{"end-size+1", end - size + 1},
			{"end", end},
			{"2^40", 1 << 40},
			{"2^63", 1 << 63},
			{"2^64-1", ^uint64(0)},
		}
	}
	for _, a := range edges(1) {
		run("load8 "+a.label, func() any { return m.Load8(int64(a.addr)) })
	}
	for _, a := range edges(2) {
		run("load16 "+a.label, func() any { return m.Load16(int64(a.addr)) })
	}
	for _, a := range edges(4) {
		run("load32 "+a.label, func() any { return m.Load32(int64(a.addr)) })
	}
	for _, a := range edges(8) {
		run("load64 "+a.label, func() any { return m.Load64(int64(a.addr)) })
		run("loadf64 "+a.label, func() any { return m.Loadf64(int64(a.addr)) })
	}
	for _, a := range edges(4) {
		run("load64s32 "+a.label, func() any { return m.Load64s32(int64(a.addr)) })
	}
	for _, a := range edges(20) {
		run("load32off "+a.label, func() any { return m.Load32off(int64(a.addr)) })
	}
	run("load32off 2^64-16", func() any { return m.Load32off(-16) })
	run("load8far 0", func() any { return m.Load8far(0) })
	run("load64max 0", func() any { return m.Load64max(0) })
	for _, a := range edges(1) {
		run("store8 "+a.label, func() any { m.Store8(int64(a.addr), 1); return "ok" })
	}
	for _, a := range edges(2) {
		run("store16 "+a.label, func() any { m.Store16(int64(a.addr), 2); return "ok" })
	}
	for _, a := range edges(4) {
		run("store32 "+a.label, func() any { m.Store32(int64(a.addr), 3); return "ok" })
		run("store64n32 "+a.label, func() any { m.Store64n32(int64(a.addr), 4); return "ok" })
	}
	for _, a := range edges(8) {
		run("store64 "+a.label, func() any { m.Store64(int64(a.addr), 5); return "ok" })
	}
	for _, a := range edges(24) {
		run("store64off "+a.label, func() any { m.Store64off(int64(a.addr), 6); return "ok" })
	}
	m.Store32(int64(end-4), 0x11223344)
	run("store64 end-4", func() any { m.Store64(int64(end-4), -1); return "ok" })
	run("after the trapped store, load32 end-4", func() any { return m.Load32(int64(end - 4)) })
	run("constlow", func() any { return m.Constlow() })
	run("consthigh", func() any { return m.Consthigh() })
	run("constwrap", func() any { return m.Constwrap() })
	for _, a := range edges(8) {
		run("atomicload64 "+a.label, func() any { return m.Atomicload64(int64(a.addr)) })
	}
	run("atomicload64 4", func() any { return m.Atomicload64(4) })
	for _, a := range edges(4) {
		run("atomicstore32 "+a.label, func() any { m.Atomicstore32(int64(a.addr), 7); return "ok" })
		run("atomicadd32 "+a.label, func() any { return m.Atomicadd32(int64(a.addr), 1) })
	}
	run("atomicstore32 2", func() any { m.Atomicstore32(2, 7); return "ok" })
	for _, a := range edges(16) {
		run("vload "+a.label, func() any { return m.Vload(int64(a.addr)) })
		run("vstore "+a.label, func() any { m.Vstore(int64(a.addr), 8); return "ok" })
	}
	for _, a := range edges(32) {
		run("vsum "+a.label, func() any { return m.Vsum(int64(a.addr)) })
	}
	run("vsum 2^64-16", func() any { return m.Vsum(-16) })
	for _, a := range edges(16) {
		run("vaddstore dst "+a.label, func() any { m.Vaddstore(int64(a.addr), 0); return "ok" })
	}
	for _, a := range edges(32) {
		run("vaddstore src "+a.label, func() any { m.Vaddstore(0, int64(a.addr)); return "ok" })
	}
	run("fill end-16 16", func() any { m.Fill(int64(end-16), 16); return "ok" })
	run("fill end-16 17", func() any { m.Fill(int64(end-16), 17); return "ok" })
	run("fill 2^64-8 16", func() any { m.Fill(-8, 16); return "ok" })
	run("copy 0 end-8 8", func() any { m.Copy(0, int64(end-8), 8); return "ok" })
	run("copy 0 end-8 9", func() any { m.Copy(0, int64(end-8), 9); return "ok" })
	run("storethenload end-8", func() any { return m.Storethenload(int64(end-8), 9) })
	run("after it, load64 end-8", func() any { return m.Load64(int64(end - 8)) })
	for _, a := range edges(16) {
		run("loadpair "+a.label, func() any { m.Loadpair(int64(a.addr)); return "ok" })
		run("loadthenstore "+a.label, func() any { m.Loadthenstore(int64(a.addr)); return "ok" })
		run("loadbranch "+a.label, func() any { m.Loadbranch(int64(a.addr), 1); return "ok" })
	}
	run("loadwrap end-16", func() any { m.Loadwrap(int64(end - 16)); return "ok" })
	run("loadwrap 2^64-8", func() any { m.Loadwrap(-8); return "ok" })
	run("growload end", func() any { return m.Growload(int64(end)) })
	end = uint64(m.Size()) * 65536
	run("size after growload", func() any { return m.Size() })
	run("grow 1", func() any { return m.Grow(1) })
	end = uint64(m.Size()) * 65536
	for _, a := range edges(1) {
		run("grown load8 "+a.label, func() any { return m.Load8(int64(a.addr)) })
	}
	for _, a := range edges(8) {
		run("grown store64 "+a.label, func() any { m.Store64(int64(a.addr), 10); return "ok" })
	}
	run("grown consthigh", func() any { return m.Consthigh() })
	for _, a := range edges(196609) {
		run("grown load8far "+a.label, func() any { return m.Load8far(int64(a.addr)) })
	}
`

const oob = "trap wasm: memory access out of bounds"
const aoob = "trap wasm: atomic access out of bounds"
const unaligned = "trap wasm: unaligned atomic access"
const voob = "trap wasm: v128 memory access out of bounds"

// mem64BoundsWant is what mem64BoundsMain prints.
var mem64BoundsWant = edgeLines("load8", "0", oob) +
	edgeLines("load16", "0", oob) +
	edgeLines("load32", "0", oob) +
	interleave(edgeLines("load64", "0", oob), edgeLines("loadf64", "0", oob)) +
	edgeLines("load64s32", "0", oob) +
	edgeLines("load32off", "0", oob) +
	"load32off 2^64-16: " + oob + "\n" +
	"load8far 0: " + oob + "\n" +
	"load64max 0: " + oob + "\n" +
	edgeLines("store8", "ok", oob) +
	edgeLines("store16", "ok", oob) +
	interleave(edgeLines("store32", "ok", oob), edgeLines("store64n32", "ok", oob)) +
	edgeLines("store64", "ok", oob) +
	edgeLines("store64off", "ok", oob) +
	"store64 end-4: " + oob + "\n" +
	"after the trapped store, load32 end-4: 287454020\n" +
	"constlow: 0\n" +
	"consthigh: " + oob + "\n" +
	"constwrap: " + oob + "\n" +
	edgeLines("atomicload64", fmt.Sprint(int64(0x1122334400000006)), aoob) +
	"atomicload64 4: " + unaligned + "\n" +
	interleave(edgeLines("atomicstore32", "ok", aoob), edgeLines("atomicadd32", "7", aoob)) +
	"atomicstore32 2: " + unaligned + "\n" +
	interleave(edgeLines("vload", "0", voob), edgeLines("vstore", "ok", voob)) +
	edgeLines("vsum", "8", voob) +
	"vsum 2^64-16: " + voob + "\n" +
	edgeLines("vaddstore dst", "ok", voob) +
	edgeLines("vaddstore src", "ok", voob) +
	"fill end-16 16: ok\n" +
	"fill end-16 17: trap wasm: memory.fill out of bounds\n" +
	"fill 2^64-8 16: trap wasm: memory.fill out of bounds\n" +
	"copy 0 end-8 8: ok\n" +
	"copy 0 end-8 9: trap wasm: memory.copy out of bounds\n" +
	"storethenload end-8: " + oob + "\n" +
	"after it, load64 end-8: 9\n" +
	interleave3(edgeLines("loadpair", "ok", oob), edgeLines("loadthenstore", "ok", oob), edgeLines("loadbranch", "ok", oob)) +
	"loadwrap end-16: ok\n" +
	"loadwrap 2^64-8: " + oob + "\n" +
	"growload end: 0\n" +
	"size after growload: 3\n" +
	"grow 1: 3\n" +
	edgeLines("grown load8", "0", oob) +
	edgeLines("grown store64", "ok", oob) +
	"grown consthigh: 0\n" +
	edgeLines("grown load8far", "0", oob)

// edgeLines is the expectation of one op over mem64BoundsMain's edges:
// the last in-bounds address gives ok, every other one traps with trap.
func edgeLines(op, ok, trap string) string {
	var b strings.Builder
	for i, label := range []string{"end-size", "end-size+1", "end", "2^40", "2^63", "2^64-1"} {
		res := trap
		if i == 0 {
			res = ok
		}
		b.WriteString(op + " " + label + ": " + res + "\n")
	}
	return b.String()
}

// interleave merges two edgeLines blocks line by line, as a loop that
// runs two ops per edge prints them.
func interleave(a, b string) string {
	al := strings.Split(strings.TrimSuffix(a, "\n"), "\n")
	bl := strings.Split(strings.TrimSuffix(b, "\n"), "\n")
	var out strings.Builder
	for i := range al {
		out.WriteString(al[i] + "\n" + bl[i] + "\n")
	}
	return out.String()
}

// interleave3 is interleave for three ops per edge.
func interleave3(a, b, c string) string {
	al := strings.Split(strings.TrimSuffix(a, "\n"), "\n")
	bl := strings.Split(strings.TrimSuffix(b, "\n"), "\n")
	cl := strings.Split(strings.TrimSuffix(c, "\n"), "\n")
	var out strings.Builder
	for i := range al {
		out.WriteString(al[i] + "\n" + bl[i] + "\n" + cl[i] + "\n")
	}
	return out.String()
}
