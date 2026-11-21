;; cg_wasi_fork_child_type.wat — exports __wasip1_posix_extension_fork_child
;; with a parameter: not the () -> i32 entry of a fork child.
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (func (export "__wasip1_posix_extension_fork_child") (param i32) (result i32)
    (local.get 0))
)
