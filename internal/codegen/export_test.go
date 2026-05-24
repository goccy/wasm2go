package codegen

// SetMultiPackageThresholdForTest forces the auto-derived multi-package
// decision threshold to b for the duration of a test. The previous
// value is returned so the caller can restore it via defer:
//
//	defer codegen.SetMultiPackageThresholdForTest(
//	    codegen.SetMultiPackageThresholdForTest(0))()
//
// Production code MUST NOT touch this — it exists solely so the codegen
// test suite can exercise the multi-package + linkname-split layout on
// the small fixtures that ship in testdata.
func SetMultiPackageThresholdForTest(b int) func() {
	prev := multiPackageThresholdOverride
	multiPackageThresholdOverride = b
	return func() { multiPackageThresholdOverride = prev }
}
