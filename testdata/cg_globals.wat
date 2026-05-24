;; cg_globals.wat — globals of every value type (i32/i64/f32/f64), both
;; mutable and immutable, plus get/set on each. Exercises globalType and
;; the global.get/global.set lowering for non-integer global types.
(module
  (global $gi32  (mut i32) (i32.const 11))
  (global $gi64  (mut i64) (i64.const 22))
  (global $gf32  (mut f32) (f32.const 1.5))
  (global $gf64  (mut f64) (f64.const 2.5))
  (global $cimmu i32 (i32.const 99))

  (func (export "get_i32") (result i32) (global.get $gi32))
  (func (export "set_i32") (param i32) (global.set $gi32 (local.get 0)))
  (func (export "get_i64") (result i64) (global.get $gi64))
  (func (export "set_i64") (param i64) (global.set $gi64 (local.get 0)))
  (func (export "get_f32") (result f32) (global.get $gf32))
  (func (export "set_f32") (param f32) (global.set $gf32 (local.get 0)))
  (func (export "get_f64") (result f64) (global.get $gf64))
  (func (export "set_f64") (param f64) (global.set $gf64 (local.get 0)))
  (func (export "get_const") (result i32) (global.get $cimmu))

  ;; round-trip through a global within a single call
  (func (export "bump_i32") (param i32) (result i32)
    (global.set $gi32 (i32.add (global.get $gi32) (local.get 0)))
    (global.get $gi32))
  (func (export "bump_f64") (param f64) (result f64)
    (global.set $gf64 (f64.add (global.get $gf64) (local.get 0)))
    (global.get $gf64))
)
