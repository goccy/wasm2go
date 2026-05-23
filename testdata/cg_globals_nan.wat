;; cg_globals_nan.wat — float globals initialised to NaN / Inf, exercising
;; the special-value path in the global-init emitter (math.Float*frombits).
(module
  (global $gnan (mut f64) (f64.const nan))
  (global $ginf (mut f32) (f32.const inf))
  (func (export "is_nan") (result i32) (f64.ne (global.get $gnan) (global.get $gnan)))
  (func (export "inf_gt") (result i32) (f32.gt (global.get $ginf) (f32.const 1e30)))
)
