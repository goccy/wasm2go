package gcasm

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Insn is one captured instruction: its byte offset within the
// function (the -S listing's second column — the label space) and
// the instruction text exactly as gc printed it.
type Insn struct {
	Off  int
	Text string
}

// Fn is one captured function.
type Fn struct {
	Name      string // symbol as printed (importpath.FnN)
	FrameSize int    // locals, from the TEXT directive ($frame-args)
	ArgSize   int
	Flags     []string // TEXT flags minus ABIInternal (NOSPLIT, NOFRAME, ...)
	Insns     []Insn
}

// DataSym is one captured data symbol (jump tables and similar
// RODATA the function bodies reference).
type DataSym struct {
	Name   string
	Size   int
	Bytes  []byte
	Relocs []DataReloc
}

// DataReloc is a pointer-sized relocation inside a DataSym (jump
// tables hold code addresses: R_ADDR entries referencing the
// function's PCs).
type DataReloc struct {
	Off    int
	Sym    string
	Addend int
}

// Capture compiles pkgDir with `go build -gcflags=<pkgPath>=-S` and
// parses the listing. Functions come back keyed AND sorted by name —
// the iteration/emission order is part of the determinism contract.
//
// GOARCH is forced to amd64: the transform targets amd64 encodings,
// and bundle generation must produce identical output on any host
// (the primary dev machine is darwin/arm64).
func Capture(pkgDir, pkgPath string) ([]*Fn, []*DataSym, error) {
	return captureArch(pkgDir, pkgPath, "amd64")
}

// captureArch compiles for a specific GOARCH and parses the listing.
// Bundle generation must produce identical output on any host, so the
// arch is pinned explicitly rather than inherited from the environment
// (the primary dev machine is darwin/arm64 under Rosetta).
func captureArch(pkgDir, pkgPath, arch string) ([]*Fn, []*DataSym, error) {
	cmd := exec.Command("go", "build", "-gcflags", pkgPath+"=-S", "./...")
	cmd.Dir = pkgDir
	cmd.Env = append(os.Environ(), "GOARCH="+arch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("gcasm capture: go build: %w\n%s", err, diagnostics(out))
	}
	return ParseListing(string(out))
}

var (
	stextRe = regexp.MustCompile(`^([^\s]+) STEXT`)
	insnRe  = regexp.MustCompile(`^\t0x[0-9a-f]+ (\d+) \([^)]*\)\t(.*)$`)
	textRe  = regexp.MustCompile(`TEXT\t([^\s(]+)\(SB\), ([^,]+), \$(\d+)-(\d+)$`)
	dataRe  = regexp.MustCompile(`^([^\s]+) SRODATA (?:static )?(?:dupok )?size=(\d+)$`)
	hexRe   = regexp.MustCompile(`^\t0x[0-9a-f]+ ((?:[0-9a-f]{2} )+)`)
	relocRe = regexp.MustCompile(`^\trel (\d+)\+(\d+) t=R_ADDR ([^\s]+)\+(\d+)$`)
)

// ParseListing parses `go tool compile -S` output (as produced via
// `go build -gcflags=-S`, possibly with several packages' sections
// interleaved at FUNCTION granularity — gc prints each function
// block atomically under its output lock).
func ParseListing(listing string) ([]*Fn, []*DataSym, error) {
	var fns []*Fn
	var datas []*DataSym
	var cur *Fn
	var curData *DataSym
	for _, line := range strings.Split(listing, "\n") {
		if m := stextRe.FindStringSubmatch(line); m != nil {
			cur = &Fn{Name: m[1]}
			curData = nil
			continue
		}
		if m := dataRe.FindStringSubmatch(line); m != nil {
			sz, err := strconv.Atoi(m[2])
			if err != nil {
				return nil, nil, fmt.Errorf("gcasm: bad data size %q: %w", m[2], err)
			}
			curData = &DataSym{Name: m[1], Size: sz}
			cur = nil
			datas = append(datas, curData)
			continue
		}
		if cur != nil {
			if m := insnRe.FindStringSubmatch(line); m != nil {
				off, err := strconv.Atoi(m[1])
				if err != nil {
					return nil, nil, fmt.Errorf("gcasm: bad insn offset %q: %w", m[1], err)
				}
				txt := m[2]
				if tm := textRe.FindStringSubmatch(txt); tm != nil {
					fs, err1 := strconv.Atoi(tm[3])
					as, err2 := strconv.Atoi(tm[4])
					if err1 != nil || err2 != nil {
						return nil, nil, fmt.Errorf("gcasm: bad TEXT sizes in %q", txt)
					}
					cur.FrameSize, cur.ArgSize = fs, as
					wrapper := false
					for _, f := range strings.Split(tm[2], "|") {
						f = strings.TrimSpace(f)
						if f == "WRAPPER" {
							wrapper = true
						}
						if f != "ABIInternal" && f != "" {
							cur.Flags = append(cur.Flags, f)
						}
					}
					// Compiler-generated ABI bridge wrappers (emitted
					// when the other-ABI symbol of a function is
					// referenced) shadow the real definition under the
					// same name — drop them.
					if wrapper {
						cur = nil
						continue
					}
					fns = append(fns, cur)
					continue
				}
				cur.Insns = append(cur.Insns, Insn{Off: off, Text: txt})
				continue
			}
			// hex-dump rows and rel rows inside a function are skipped;
			// a non-tab line ends the function.
			if !strings.HasPrefix(line, "\t") {
				cur = nil
			}
			continue
		}
		if curData != nil {
			if m := hexRe.FindStringSubmatch(line); m != nil {
				for _, b := range strings.Fields(m[1]) {
					v, err := strconv.ParseUint(b, 16, 8)
					if err != nil {
						return nil, nil, fmt.Errorf("gcasm: bad hex byte %q: %w", b, err)
					}
					curData.Bytes = append(curData.Bytes, byte(v))
				}
				continue
			}
			if m := relocRe.FindStringSubmatch(line); m != nil {
				off, err := strconv.Atoi(m[1])
				if err != nil {
					return nil, nil, fmt.Errorf("gcasm: bad insn offset %q: %w", m[1], err)
				}
				add, err := strconv.Atoi(m[4])
				if err != nil {
					return nil, nil, fmt.Errorf("gcasm: bad reloc addend %q: %w", m[4], err)
				}
				curData.Relocs = append(curData.Relocs, DataReloc{Off: off, Sym: m[3], Addend: add})
				continue
			}
			if !strings.HasPrefix(line, "\t") {
				curData = nil
			}
		}
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].Name < fns[j].Name })
	sort.Slice(datas, func(i, j int) bool { return datas[i].Name < datas[j].Name })
	return fns, datas, nil
}

// diagnostics extracts go build's error lines from a -gcflags=-S run. The
// listing dwarfs the errors by megabytes and, with parallel package compiles,
// the errors can land anywhere in the stream — a head or tail clip usually
// keeps only listing noise. KEEP the shapes an error takes (package headers,
// file:line:col messages, go's own tool complaints) instead of trying to
// enumerate every listing shape there is.
func diagnostics(b []byte) string {
	errLine := regexp.MustCompile(`^[^\s#].*\.(go|s):[0-9]+(:[0-9]+)?: `)
	var diag []string
	for _, ln := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(ln, "# "),
			strings.HasPrefix(ln, "go: "),
			strings.HasPrefix(ln, "go build"),
			errLine.MatchString(ln):
			diag = append(diag, ln)
		}
	}
	out := strings.Join(diag, "\n")
	if out == "" {
		// Nothing error-shaped: fall back to the raw tail rather than hiding
		// everything.
		return clip(b[max(0, len(b)-2000):])
	}
	if len(out) > 8000 {
		out = out[:8000] + "...[clipped]"
	}
	return out
}

func clip(b []byte) string {
	if len(b) > 2000 {
		return string(b[:2000]) + "...[clipped]"
	}
	return string(b)
}

// PureFilter maps a translated file set to a capture-ready one: the
// generated asm bundle is removed so `go build` on the HOST arch
// compiles the pure Go bodies (which normally sit behind
// `//go:build !amd64 && !arm64` while decls.go + amd64.s/arm64.s
// serve those arches). `.s` files and files tagged for the asm
// arches are dropped; the pure-guard build tag is stripped. Files
// without a build tag (go.mod, sidecar binaries, shared sources)
// pass through unchanged.
func PureFilter(files map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(files))
	for name, data := range files {
		if strings.HasSuffix(name, ".s") {
			continue
		}
		s := string(data)
		if strings.HasPrefix(s, "//go:build") {
			line := s
			if idx := strings.Index(s, "\n"); idx >= 0 {
				line = s[:idx]
			}
			expr := strings.TrimSpace(strings.TrimPrefix(line, "//go:build"))
			switch {
			case strings.Contains(expr, "!amd64"):
				// Pure body: strip the guard (plus the blank line
				// conventionally following it).
				rest := s[len(line):]
				rest = strings.TrimPrefix(rest, "\n")
				rest = strings.TrimPrefix(rest, "\n")
				s = rest
			case strings.Contains(expr, "amd64"):
				// Asm-mode-only source (decls, aliases).
				continue
			}
		}
		if strings.HasSuffix(name, ".go") {
			// Keep the cold trap constructors out of captured bodies:
			// inlined, they surface `CALL runtime.gopanic` with
			// ABIInternal register arguments and `type:*` / `..stmp_*`
			// operands that neither the transform nor Plan9 asm can
			// express. As out-of-line calls they are zero-argument and
			// ABI-agnostic.
			s = strings.ReplaceAll(s, "\nfunc wasm_trap_", "\n//go:noinline\nfunc wasm_trap_")
		}
		out[name] = []byte(s)
	}
	return out
}
