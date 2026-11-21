package codegen

import "testing"

// sharedWaiters forks n instances of w, each with a guest that has
// registered for signals and handles SIGTERM.
func sharedWaiters(t *testing.T, w *WasiStubs, n int) (instances []*WasiStubs, modules []*Module) {
	t.Helper()
	for i := 0; i < n; i++ {
		child, cm := w.Fork(), newForkTestModule()
		t.Cleanup(func() {
			if err := child.CloseAll(); err != nil {
				t.Error(err)
			}
		})
		if rc := child.Proc_signal_register(cm, sigFlagOff); rc != 0 {
			t.Fatalf("Proc_signal_register rc=%d", rc)
		}
		setDispositions(t, child, cm, signalMask(wasiSIGTERM), 0, 0)
		instances = append(instances, child)
		modules = append(modules, cm)
	}
	return instances, modules
}
