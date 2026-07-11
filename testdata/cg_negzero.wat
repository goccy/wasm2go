;; cg_negzero.wat — negative-zero float constants. Go has no -0.0 literal
;; (constant arithmetic is exact, so `float64(-0)` is +0): every constant
;; and global-initializer path must preserve the sign bit some other way.
;; Results are observed as raw bits via reinterpret so the fixture harness
;; compares them exactly.
(module
  ;; Constant emitted inside a function body (SSA OpConstF64/OpConstF32).
  (func (export "f64_negzero_bits") (result i64)
    (i64.reinterpret_f64 (f64.const -0)))
  (func (export "f32_negzero_bits") (result i32)
    (i32.reinterpret_f32 (f32.const -0)))

  ;; The same constants observed through a call, so a folded reinterpret
  ;; could not mask a broken literal.
  (func $nz64 (result f64) (f64.const -0))
  (func $nz32 (result f32) (f32.const -0))
  (func (export "f64_negzero_call_bits") (result i64)
    (i64.reinterpret_f64 (call $nz64)))
  (func (export "f32_negzero_call_bits") (result i32)
    (i32.reinterpret_f32 (call $nz32)))

  ;; Global initializers: -0 must not be treated as "zero value already
  ;; correct", and non-zero negatives must keep their sign.
  (global $gnz64 f64 (f64.const -0))
  (global $gnz32 f32 (f32.const -0))
  (func (export "global_f64_negzero_bits") (result i64)
    (i64.reinterpret_f64 (global.get $gnz64)))
  (func (export "global_f32_negzero_bits") (result i32)
    (i32.reinterpret_f32 (global.get $gnz32)))

  ;; -0 must survive arithmetic identities: x*1, x+(-0), min(-0,+0).
  (func (export "f64_negzero_mul1_bits") (result i64)
    (i64.reinterpret_f64 (f64.mul (f64.const -0) (f64.const 1))))
  (func (export "f64_min_negzero_bits") (result i64)
    (i64.reinterpret_f64 (f64.min (f64.const -0) (f64.const 0))))

  ;; NaN payload constants keep going through the frombits path.
  (func (export "f64_nan_payload_bits") (result i64)
    (i64.reinterpret_f64 (f64.const nan:0x123456)))
)
