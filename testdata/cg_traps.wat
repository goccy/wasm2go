;; cg_traps.wat — fixtures that exercise wasm trap semantics. Used to
;; verify that wasm2go does NOT DCE away trapping ops whose result is
;; unused: every export here performs a trapping op and drops the
;; result, then returns a constant. A correct translation must trap
;; (panic) at runtime; a broken DCE returns the constant cleanly.
(module
  ;; i32.div_s by zero, drop, then return 42.
  (func (export "div_s32_drop_then_42") (result i32)
    (drop (i32.div_s (i32.const 1) (i32.const 0)))
    (i32.const 42))

  ;; i32.div_u by zero, drop, then return 42.
  (func (export "div_u32_drop_then_42") (result i32)
    (drop (i32.div_u (i32.const 1) (i32.const 0)))
    (i32.const 42))

  ;; i32.rem_s by zero, drop, then return 42.
  (func (export "rem_s32_drop_then_42") (result i32)
    (drop (i32.rem_s (i32.const 1) (i32.const 0)))
    (i32.const 42))

  ;; i32.rem_u by zero, drop, then return 42.
  (func (export "rem_u32_drop_then_42") (result i32)
    (drop (i32.rem_u (i32.const 1) (i32.const 0)))
    (i32.const 42))

  ;; i64.div_s by zero, drop, then return 42.
  (func (export "div_s64_drop_then_42") (result i32)
    (drop (i64.div_s (i64.const 1) (i64.const 0)))
    (i32.const 42))

  ;; i32.trunc_f32_s of NaN, drop, then return 42.
  (func (export "trunc_f32_s_nan_drop_then_42") (result i32)
    (drop (i32.trunc_f32_s (f32.const nan)))
    (i32.const 42))

  ;; Memory.grow followed by drop, then return memory.size. Used to
  ;; check that memory.grow is not emitted twice when its result is
  ;; immediately discarded.
  (memory 1)
  (func (export "grow_drop_then_size") (result i32)
    (drop (memory.grow (i32.const 1)))
    (memory.size)))
