package codegen

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

func TestNrc2ProbeLlama(t *testing.T) {
	path := os.Getenv("NRC2_PROBE_WASM")
	if path == "" {
		t.Skip("set NRC2_PROBE_WASM")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Logf("close: %v", err)
		}
	}()
	m, err := wasm.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	tab := nrc2TableSet(m)
	t.Logf("table entries: %d; elements segs: %d; datas: %d; imports: %d",
		len(tab), len(m.Elements), len(m.Datas), m.NumImportedFuncs)
	if fi, ok := tab[753]; ok {
		t.Logf("tab[753] = func %d", fi)
	} else {
		t.Logf("tab[753] MISSING")
	}
	for segIdx, ds := range m.Datas {
		b := ds.Bytes
		for off := 0; off+24 <= len(b); off += 4 {
			vd := binary.LittleEndian.Uint32(b[off+4:])
			vdt := binary.LittleEndian.Uint32(b[off+8:])
			nrows := binary.LittleEndian.Uint64(b[off+16:])
			if vd == 753 && vdt == 8 && nrows == 1 {
				t.Logf("row at seg %d (passive=%v) off %#x", segIdx, ds.Passive, off)
			}
		}
	}
}
