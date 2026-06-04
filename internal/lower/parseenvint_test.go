package lower

import "testing"

// TestParseEnvInt covers the env-int parser with set/unset/garbage inputs.
// parseEnvInt is the helper that backs the SSA-bisection env vars
// (WASM2GO_SSA_MINFUNC / WASM2GO_SSA_MAXFUNC).
func TestParseEnvInt(t *testing.T) {
	const key = "WASM2GO_TEST_PARSEENVINT"
	t.Setenv(key, "")
	if got := parseEnvInt(key, 7); got != 7 {
		t.Errorf("parseEnvInt unset = %d want default 7", got)
	}
	t.Setenv(key, "123")
	if got := parseEnvInt(key, 7); got != 123 {
		t.Errorf("parseEnvInt(123) = %d want 123", got)
	}
	t.Setenv(key, "-5")
	if got := parseEnvInt(key, 7); got != -5 {
		t.Errorf("parseEnvInt(-5) = %d want -5", got)
	}
	t.Setenv(key, "not-a-number")
	if got := parseEnvInt(key, 7); got != 7 {
		t.Errorf("parseEnvInt(garbage) = %d want default 7", got)
	}
}
