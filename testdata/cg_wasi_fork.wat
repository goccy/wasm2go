;; cg_wasi_fork.wat — imports the non-standard process imports of the
;; Go-native wasi runtime (proc_fork, proc_wait, proc_wait_any, proc_kill) so
;; a generated bundle has to bind them to the emitted WasiStubs methods.
;; Results are left in linear memory: the forked pid at 100, the pid and
;; status of the last successful wait at 104 and 108.
(module
  (import "wasi_snapshot_preview1" "proc_fork"
    (func $proc_fork (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_wait"
    (func $proc_wait (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_wait_any"
    (func $proc_wait_any (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_kill"
    (func $proc_kill (param i32 i32) (result i32)))

  (memory (export "memory") 1)

  (func (export "fork") (result i32)
    (call $proc_fork (i32.const 100)))

  (func (export "forked_pid") (result i32)
    (i32.load (i32.const 100)))

  (func (export "wait_pid") (param $pid i32) (param $options i32) (result i32)
    (i32.store (i32.const 104) (local.get $pid))
    (call $proc_wait (local.get $pid) (local.get $options) (i32.const 108)))

  (func (export "wait_any") (param $options i32) (result i32)
    (call $proc_wait_any (local.get $options) (i32.const 104) (i32.const 108)))

  (func (export "waited_pid") (result i32)
    (i32.load (i32.const 104)))

  (func (export "waited_status") (result i32)
    (i32.load (i32.const 108)))

  (func (export "kill") (param $pid i32) (param $sig i32) (result i32)
    (call $proc_kill (local.get $pid) (local.get $sig)))
)
