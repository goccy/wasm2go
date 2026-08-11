package asmgen

import (
	"runtime"
	"testing"
)

// The widecmp fixture drives the emitters the arith/control fixtures
// never reach: variable-count 64-bit shifts (emitShift64*), 64-bit
// compares materialized into an i32 (emitCmp64*), the inline float
// min/max and compare families, the fused bit-test conditional
// branch, and EmitUnreachable on a trapping arm.
var widecmpExports = []string{
	"shl64", "shr_s64", "shr_u64",
	"lt_s64", "gt_u64", "eq64",
	"flt", "fge",
	"bittest", "trapif",
}

// f32.min/f64.max inline only on amd64; arm64 lowers them to helper
// calls the standalone driver has no bodies for.
var widecmpMinMaxExports = []string{"fmin", "fmax"}

var widecmpMinMaxCases = []driverCase{}

var widecmpCases = []driverCase{
	{"shl64", []string{"1", "40"}, "1099511627776"},
	{"shl64", []string{"-1", "1"}, "-2"},
	{"shl64", []string{"1", "64"}, "1"}, // count masks mod 64
	{"shr_s64", []string{"-1099511627776", "40"}, "-1"},
	{"shr_s64", []string{"1099511627776", "40"}, "1"},
	{"shr_u64", []string{"-1", "63"}, "1"},
	{"shr_u64", []string{"1099511627776", "40"}, "1"},
	{"lt_s64", []string{"-1", "1"}, "1"},
	{"lt_s64", []string{"1", "-1"}, "0"},
	{"lt_s64", []string{"-9223372036854775808", "9223372036854775807"}, "1"},
	{"gt_u64", []string{"-1", "1"}, "1"}, // unsigned: 2^64-1 > 1
	{"gt_u64", []string{"1", "-1"}, "0"},
	{"eq64", []string{"42", "42"}, "1"},
	{"eq64", []string{"42", "43"}, "0"},
	{"flt", []string{"1", "2"}, "1"},
	{"flt", []string{"2", "1"}, "0"},
	{"flt", []string{"NaN", "1"}, "0"}, // unordered compares false
	{"fge", []string{"2", "1"}, "1"},
	{"fge", []string{"NaN", "1"}, "0"},
	{"bittest", []string{"8"}, "1"},
	{"bittest", []string{"12"}, "1"},
	{"bittest", []string{"7"}, "0"},
	{"trapif", []string{"0"}, "7"},
}

func TestEmitWideCmpAMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	buildAndRunDriver(t, "asmgen_widecmp", widecmpExports, driverPlaceholder, widecmpCases)
	buildAndRunDriver(t, "asmgen_widecmp", widecmpMinMaxExports, driverPlaceholder, widecmpMinMaxCases)
}

func TestEmitWideCmpARM64(t *testing.T) {
	if !canExecDarwinARM64() && runtime.GOARCH != "arm64" {
		t.Skipf("host cannot execute arm64 binaries (GOOS=%s GOARCH=%s)", runtime.GOOS, runtime.GOARCH)
	}
	buildAndRunDriverArch(t, "asmgen_widecmp", widecmpExports, driverPlaceholder, widecmpCases, "arm64")
}
