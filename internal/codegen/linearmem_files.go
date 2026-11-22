package codegen

import (
	_ "embed"
	"strings"
)

// The linear-memory allocation runtime ships as whole files, like the SIMD
// set: the guarded reservation needs syscall.Mmap and syscall.Mprotect, which
// the syscall package provides together only on linux and darwin, so the
// implementation is split by build tag rather than name-filtered out of
// helpers.go. Its functions keep their lowercase names in both layouts — only
// the helpers.go helpers that call them (initLinearMemory, memoryGrow) are
// referenced across packages.

//go:embed helpers/linearmem_guard.go
var linearMemGuardSrc string

//go:embed helpers/linearmem_mmap.go
var linearMemMmapSrc string

//go:embed helpers/linearmem_other.go
var linearMemOtherSrc string

// appendLinearMemoryFiles adds the allocation runtime to the output tree of
// a module with linear memory, next to the Module struct (base/ in
// multi-package output).
func (t *translator) appendLinearMemoryFiles(files map[string][]byte) {
	if len(t.mod.Memories) == 0 {
		return
	}
	dir, pkg := "", t.opts.Package
	if t.multiPackage {
		dir, pkg = "base/", "base"
	}
	for name, src := range map[string]string{
		"linearmem_guard.go": linearMemGuardSrc,
		"linearmem_mmap.go":  linearMemMmapSrc,
		"linearmem_other.go": linearMemOtherSrc,
	} {
		files[dir+name] = []byte(strings.Replace(src, "package helpers", "package "+pkg, 1))
	}
}
