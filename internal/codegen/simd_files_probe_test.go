package codegen

import "testing"

func TestSimdHelperFileSetIncludesAmd64CPUFeat(t *testing.T) {
	tr := &translator{usesSimd: true}
	files := map[string][]byte{}
	tr.appendSimdHelperFiles(files)
	for _, want := range []string{"cpufeat_amd64.go", "cpufeat_amd64.s", "cpufeat_arm64_linux.go"} {
		if _, ok := files[want]; !ok {
			t.Errorf("missing %s; got %d files", want, len(files))
		}
	}
}
