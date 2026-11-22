;; cg_signal_flag.wat — a guest without threads reads its signal flag word as
;; proc_signal_register asks: with i32.atomic.load on a memory that is not
;; shared. register names the word at 16; spin loads it until the host has
;; raised it, and clears it with i32.atomic.store.
(module
  (import "wasip1_posix_extension" "proc_signal_register"
    (func $proc_signal_register (param i32) (result i32)))
  (memory (export "memory") 1)

  (func (export "register") (result i32)
    (call $proc_signal_register (i32.const 16)))

  (func (export "spin")
    (loop $wait
      (br_if $wait (i32.eqz (i32.atomic.load (i32.const 16)))))
    (i32.atomic.store (i32.const 16) (i32.const 0))))
