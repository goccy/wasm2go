;; A module whose data segments are ACTIVE, as a memory that is not shared
;; has them (a C program's): the constructors copy them into memory,
;; not the start section. One segment is on the second page.
;;
;; The start section bumps a counter in memory, so that a test can tell that
;; it ran on the memory a constructor was given.
(module
  (memory (export "memory") 2)

  (data (i32.const 1024) "active data")
  (data (i32.const 70000) "Z")

  (func $start
    ;; runs++ at byte 100
    i32.const 100
    i32.const 100
    i32.load8_u
    i32.const 1
    i32.add
    i32.store8)
  (start $start)

  (func (export "peek") (param i32) (result i32)
    local.get 0
    i32.load8_u))
