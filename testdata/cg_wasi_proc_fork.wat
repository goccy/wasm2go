;; cg_wasi_proc_fork.wat — forks through wasip1_posix_extension's proc_fork
;; and waits for the child with proc_wait. The child, entered through
;; __wasip1_posix_extension_fork_child, ends with the cell at 100 and the
;; global $g it was forked with.
(module
  (import "wasip1_posix_extension" "proc_fork" (func $fork (param i32) (result i32)))
  (import "wasip1_posix_extension" "proc_wait" (func $wait (param i32 i32 i32) (result i32)))

  (memory (export "memory") 1)
  (global $g (mut i32) (i32.const 0))

  ;; the child's wait status, or the negative errno of the fork or the wait
  (func (export "run") (result i32)
    (local $rc i32)
    (i32.store (i32.const 100) (i32.const 7))
    (global.set $g (i32.const 3))
    (local.set $rc (call $fork (i32.const 8)))
    (if (i32.ne (local.get $rc) (i32.const 0)) (then (return (local.get $rc))))
    (local.set $rc (call $wait (i32.load (i32.const 8)) (i32.const 0) (i32.const 12)))
    (if (i32.ne (local.get $rc) (i32.const 0)) (then (return (local.get $rc))))
    (i32.load (i32.const 12)))

  ;; cell + 10*g
  (func (export "__wasip1_posix_extension_fork_child") (result i32)
    (i32.add (i32.load (i32.const 100)) (i32.mul (global.get $g) (i32.const 10))))
)
