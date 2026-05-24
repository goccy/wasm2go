;; cg_specialfp.wat — float constants that are NaN / +Inf / -Inf, which
;; wasm2go must emit via math.Float{32,64}frombits rather than a decimal
;; literal (the f32ConstExpr / f64ConstExpr special-value path).
(module
  (func (export "f32_nan") (result f32) (f32.const nan))
  (func (export "f32_inf") (result f32) (f32.const inf))
  (func (export "f32_ninf") (result f32) (f32.const -inf))
  (func (export "f64_nan") (result f64) (f64.const nan))
  (func (export "f64_inf") (result f64) (f64.const inf))
  (func (export "f64_ninf") (result f64) (f64.const -inf))
  ;; arithmetic that yields inf at runtime
  (func (export "div_by_zero_f64") (param f64 f64) (result f64)
    (f64.div (local.get 0) (local.get 1)))
)
