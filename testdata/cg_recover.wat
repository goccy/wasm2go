;; cg_recover.wat — exercises the per-export Inv_<svc>_<mt> wrapper's
;; trap-recovery contract. Each bulk-dispatch export mutates the
;; module's single mutable global before triggering a wasm trap; the
;; non-bulk system exports `get_g` and `reset_g` give the test
;; a way to observe and reset that global between calls.
;;
;; The contract under test is:
;;   - a wasm trap inside `Inv_<svc>_<mt>` does NOT panic; the
;;     wrapper recovers and surfaces it as an `error`;
;;   - every mutable global is restored to the value it had at
;;     wrapper entry, even when the trap fires after the global
;;     has been mutated;
;;   - repeated trap+recover cycles do not leak goroutines or
;;     accumulate Go heap allocations on the wrapper path.
(module
  (memory (export "memory") 1)
  (global $g (mut i32) (i32.const 100))

  ;; w_1_0 — mutate global, then trap via integer divide by zero.
  (func (export "w_1_0") (param i32 i32) (result i64)
    (global.set $g (i32.const 999))
    (i64.extend_i32_s (i32.div_s (i32.const 1) (i32.const 0))))

  ;; w_1_1 — mutate global, then trap via `unreachable`.
  (func (export "w_1_1") (param i32 i32) (result i64)
    (global.set $g (i32.const 999))
    (unreachable))

  ;; w_1_2 — mutate global, then trap via i32.trunc_f32_s of NaN
  ;; (wasm spec: invalid conversion to integer is a trap).
  (func (export "w_1_2") (param i32 i32) (result i64)
    (global.set $g (i32.const 999))
    (i64.extend_i32_s (i32.trunc_f32_s (f32.const nan))))

  ;; w_2_0 — mutate global, then succeed (returns l0+l1). Used as
  ;; the no-trap control so the test can assert that wrapping a
  ;; clean call still updates the global and returns the right
  ;; value through Inv_<svc>_<mt>.
  (func (export "w_2_0") (param i32 i32) (result i64)
    (global.set $g (i32.const 999))
    (i64.extend_i32_s (i32.add (local.get 0) (local.get 1))))

  ;; get_g — read the mutable global. Non-bulk export so wasm2go
  ;; emits its own direct wrapper (`Module.GetG`) instead of an
  ;; `Inv_*` entry.
  (func (export "get_g") (result i32)
    (global.get $g))

  ;; reset_g — restore the global to its initial value (100).
  (func (export "reset_g")
    (global.set $g (i32.const 100))))
