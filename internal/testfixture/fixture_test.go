package testfixture

import (
	"slices"
	"testing"
)

func TestFlagsOf(t *testing.T) {
	help := []byte(`usage: wat2wasm [options] filename
      --disable-exceptions                     Disable Experimental exception handling
      --enable-threads                         Enable Threading support
      --disable-memory64                       Disable 64-bit memory
`)
	got := flagsOf(help, "--enable-exceptions", "--enable-threads", "--enable-memory64")
	if want := []string{"--enable-threads"}; !slices.Equal(got, want) {
		t.Errorf("flagsOf = %q, want %q", got, want)
	}
}

func TestWasm(t *testing.T) {
	if len(Wasm(t, "arith.wat")) == 0 {
		t.Fatal("no wasm")
	}
}
