package codegen

import (
	_ "embed"
	"strings"
)

// The SIMD helper implementation set. Unlike the name-filtered helpers in
// helpers.go, these ship as whole files: the pure lane ops have per-arch
// native bodies (simd_asm_*.s) selected by build tags. The asm arches only
// compile the scalar bodies their assembly does not cover
// (simd_scalar_rest_<arch>.go, a few KB) — the full reference set in
// simd_scalar.go is tagged out there, since keeping generated Go small is
// the whole point of the asm backend. tools/gen-simd-asm regenerates all of
// them.

//go:embed helpers/simd_scalar.go
var simdScalarSrc string

//go:embed helpers/simd_pair.go
var simdPairSrc string

//go:embed helpers/simd_fallback.go
var simdFallbackSrc string

//go:embed helpers/simd_asm_decls_arm64.go
var simdAsmDeclsArm64Src string

//go:embed helpers/simd_asm_decls_amd64.go
var simdAsmDeclsAmd64Src string

//go:embed helpers/simd_scalar_rest_arm64.go
var simdScalarRestArm64Src string

//go:embed helpers/simd_scalar_rest_amd64.go
var simdScalarRestAmd64Src string

//go:embed helpers/simd_asm_arm64.s
var simdAsmArm64Src string

//go:embed helpers/cpufeat_arm64_darwin.go
var cpufeatArm64DarwinSrc string

//go:embed helpers/cpufeat_arm64_linux.go
var cpufeatArm64LinuxSrc string

//go:embed helpers/cpufeat_arm64_other.go
var cpufeatArm64OtherSrc string

//go:embed helpers/simd_asm_amd64.s
var simdAsmAmd64Src string

// appendSimdHelperFiles adds the SIMD helper files to the output tree when
// the module uses any SIMD helper. In multi-package mode the entry points
// are exported (simd_ → Simd_) to match helperRef's capitalized cross-
// package references; the internal utilities (simdToU8, simdConst*, ...)
// stay package-private either way.
func (t *translator) appendSimdHelperFiles(files map[string][]byte) {
	if !t.usesSimd {
		return
	}
	dir, pkg := "", t.opts.Package
	if t.multiPackage {
		dir, pkg = "base/", "base"
	}
	goFile := func(src string) []byte {
		src = strings.Replace(src, "package helpers", "package "+pkg, 1)
		if t.multiPackage {
			src = strings.ReplaceAll(src, "simd_", "Simd_")
		}
		return []byte(src)
	}
	asmFile := func(src string) []byte {
		if t.multiPackage {
			src = strings.ReplaceAll(src, "simd_", "Simd_")
		}
		return []byte(src)
	}
	files[dir+"simd_scalar.go"] = goFile(simdScalarSrc)
	files[dir+"simd_pair.go"] = goFile(simdPairSrc)
	files[dir+"simd_fallback.go"] = goFile(simdFallbackSrc)
	files[dir+"simd_asm_decls_arm64.go"] = goFile(simdAsmDeclsArm64Src)
	files[dir+"simd_asm_decls_amd64.go"] = goFile(simdAsmDeclsAmd64Src)
	files[dir+"simd_scalar_rest_arm64.go"] = goFile(simdScalarRestArm64Src)
	files[dir+"simd_scalar_rest_amd64.go"] = goFile(simdScalarRestAmd64Src)
	files[dir+"simd_asm_arm64.s"] = asmFile(simdAsmArm64Src)
	files[dir+"simd_asm_amd64.s"] = asmFile(simdAsmAmd64Src)
	files[dir+"cpufeat_arm64_darwin.go"] = goFile(cpufeatArm64DarwinSrc)
	files[dir+"cpufeat_arm64_linux.go"] = goFile(cpufeatArm64LinuxSrc)
	files[dir+"cpufeat_arm64_other.go"] = goFile(cpufeatArm64OtherSrc)
}
