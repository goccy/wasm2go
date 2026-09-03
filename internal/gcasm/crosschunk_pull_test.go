package gcasm

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
)

// fallbackCallerChunkBytes packs the fixture's transformed sibling and
// its pure-Go fallback caller into ONE chunk package (the planner
// first-fit packs SCCs by size), so that package both references the
// remote callee from Go (the fallback body) and CALLs it from asm
// (the sibling's spelled direct call).
const fallbackCallerChunkBytes = 100

var (
	plainPullRe = regexp.MustCompile(`(?m)^//go:linkname (Fn\d+) (\S+)$`)
	trampRe     = regexp.MustCompile(`(?m)^TEXT ·(Fn\d+)\(SB\), NOSPLIT, \$0-(\d+)\n\tJMP (\S+)·(Fn\d+)\(SB\)`)
)

// chunkDirsOf lists the pN chunk packages of a materialised tree.
func chunkDirsOf(tree map[string][]byte) []string {
	seen := map[string]bool{}
	for name := range tree {
		if i := strings.IndexByte(name, '/'); i > 0 && strings.HasPrefix(name, "p") {
			seen[name[:i]] = true
		}
	}
	var dirs []string
	for d := range seen {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return dirs
}

// TestCrossChunkFallbackBodyCallsUseTrampolines: on a plan-9-spellable
// import path, a fallback body's Go-level reference to a remote FnN
// reaches it through a local NOSPLIT tail-JMP trampoline — never a
// bodyless //go:linkname pull of the remote symbol. A pull next to the
// same package's spelled asm CALLs makes the compiler emit a DUPOK
// ABI0 wrapper under the REMOTE name; whichever of that wrapper and
// the remote's real TEXT the linker loads first wins, and when the
// wrapper wins the two ABI wrappers call each other forever (the
// "nosplit stack over 792 byte limit ... infinite cycle" link error).
// The direct asm CALLs themselves stay: they are the hop-count win of
// the direct-call path and are harmless on their own.
func TestCrossChunkFallbackBodyCallsUseTrampolines(t *testing.T) {
	const importPath = "github.com/gentest/pkg"
	tree := finalBundleTreeAt(t, "cg_crosscall_fallbackcaller", importPath, fallbackCallerChunkBytes)
	spelledRoot := asmSpellPath(importPath)
	var directCalls, tramps int
	for _, dir := range chunkDirsOf(tree) {
		for _, arch := range []string{"amd64", "arm64"} {
			decls := string(tree[dir+"/decls_"+arch+".go"])
			asm := string(tree[dir+"/"+arch+".s"])
			for _, m := range plainPullRe.FindAllStringSubmatch(decls, -1) {
				t.Errorf("%s/decls_%s.go: bodyless //go:linkname pull of %s (%s) — asm-referenced remote fns must use a trampoline", dir, arch, m[2], m[1])
			}
			directCalls += strings.Count(asm, "CALL "+spelledRoot)
			for _, m := range trampRe.FindAllStringSubmatch(asm, -1) {
				tramps++
				if m[1] != m[4] {
					t.Errorf("%s/%s.s: trampoline %s jumps to %s", dir, arch, m[1], m[4])
				}
				if !strings.HasPrefix(m[3], spelledRoot+"∕") {
					t.Errorf("%s/%s.s: trampoline %s target %q is not a spelled remote symbol", dir, arch, m[1], m[3])
				}
				// The local decl the trampoline implements must be a bare
				// asm decl (no linkname) so the compiler binds it locally.
				if !strings.Contains(decls, "\nfunc "+m[1]+"(") {
					t.Errorf("%s/decls_%s.go: no local decl for trampoline %s", dir, arch, m[1])
				}
			}
		}
	}
	if tramps == 0 {
		t.Error("no cross-chunk trampoline emitted for the fallback body's remote call")
	}
	if directCalls == 0 {
		t.Error("no spelled direct cross-chunk CALL emitted; the direct-call path must survive the trampoline change")
	}
}

// An unspellable import path never spells asm references, so the
// bodyless linkname pull is safe there and stays (no trampoline can
// name the remote either).
func TestCrossChunkFallbackBodyCallsKeepPullOnUnspellablePath(t *testing.T) {
	const importPath = "github.com/gen-test/pkg"
	tree := finalBundleTreeAt(t, "cg_crosscall_fallbackcaller", importPath, fallbackCallerChunkBytes)
	var pulls, tramps, spelled int
	for _, dir := range chunkDirsOf(tree) {
		for _, arch := range []string{"amd64", "arm64"} {
			pulls += len(plainPullRe.FindAllString(string(tree[dir+"/decls_"+arch+".go"]), -1))
			asm := string(tree[dir+"/"+arch+".s"])
			tramps += len(trampRe.FindAllString(asm, -1))
			spelled += strings.Count(asm, "∕")
		}
	}
	if pulls == 0 {
		t.Error("unspellable path emitted no //go:linkname pull for the fallback body's remote call")
	}
	if tramps != 0 || spelled != 0 {
		t.Errorf("unspellable path emitted %d trampolines / %d spelled references; must be 0", tramps, spelled)
	}
}

// TestCrossChunkBundleLinksInEveryPackageOrder links a consumer of the
// fixture bundle for both asm targets with the chunk packages imported
// in ascending AND descending order. The linker resolves DUPOK symbols
// first-come, so a bundle that is only correct for one package load
// order is not correct: the production consumer's import graph decides
// the order, not the bundle.
func TestCrossChunkBundleLinksInEveryPackageOrder(t *testing.T) {
	const modPath = "github.com/gentest"
	tree := finalBundleTreeAt(t, "cg_crosscall_fallbackcaller", modPath+"/pkg", fallbackCallerChunkBytes)
	dirs := chunkDirsOf(tree)
	if len(dirs) < 2 {
		t.Fatalf("fixture did not split into multiple chunks: %v", dirs)
	}
	root := t.TempDir()
	write := func(name string, data []byte) {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", []byte("module "+modPath+"\n\ngo 1.25.0\n"))
	for name, data := range tree {
		write("pkg/"+name, data)
	}
	orders := map[string][]string{"ascending": dirs}
	rev := make([]string, len(dirs))
	for i, d := range dirs {
		rev[len(dirs)-1-i] = d
	}
	orders["descending"] = rev
	targets := []struct {
		name string
		env  []string
	}{
		{"linux/arm64", []string{"GOOS=linux", "GOARCH=arm64"}},
		{"linux/amd64-v2", []string{"GOOS=linux", "GOARCH=amd64", "GOAMD64=v2"}},
		{"linux/amd64-v1", []string{"GOOS=linux", "GOARCH=amd64", "GOAMD64=v1"}},
	}
	for orderName, order := range orders {
		// The consumer must REACH the exports: the linker's dead-code
		// pass drops unreferenced text before the nosplit walk, so a
		// blank-import consumer would link even a poisoned bundle.
		var main strings.Builder
		main.WriteString("package main\n\nimport (\n\t\"fmt\"\n\n")
		for _, d := range order {
			main.WriteString("\t_ \"" + modPath + "/pkg/" + d + "\"\n")
		}
		main.WriteString("\t\"" + modPath + "/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n\tfmt.Println(pkg." +
			codegen.ExportMethodName("fallbackcaller") + "(m, 1, 2))\n}\n")
		write("cmd/"+orderName+"/main.go", []byte(main.String()))
		for _, tg := range targets {
			t.Run(orderName+"/"+tg.name, func(t *testing.T) {
				cmd := exec.Command("go", "build", "-o", os.DevNull, "./cmd/"+orderName)
				cmd.Dir = root
				cmd.Env = append(append(os.Environ(), "CGO_ENABLED=0"), tg.env...)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("consumer does not link with chunks imported in %s order on %s: %v\n%s", orderName, tg.name, err, out)
				}
			})
		}
	}
}
