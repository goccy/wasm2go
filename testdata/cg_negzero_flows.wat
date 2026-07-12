;; cg_negzero_flows.wat — negative zero flowing through non-constant shapes:
;; locals, block results, phi merges, select, and a data segment. Hunts the
;; path that still loses -0 in SpiderMonkey's Math.sumPrecise after the
;; f64.const fix (observed on BOTH backends).
(module
  (memory (export "memory") 1)
  (data (i32.const 8) "\00\00\00\00\00\00\00\80")   ;; -0.0 le bytes
  (func (export "via_local") (result i64)
    (local f64)
    (local.set 0 (f64.const -0))
    (i64.reinterpret_f64 (local.get 0)))
  (func (export "via_block") (result i64)
    (i64.reinterpret_f64 (block (result f64) (f64.const -0))))
  (func (export "via_phi") (param i32) (result i64)
    (local f64)
    (if (local.get 0)
      (then (local.set 1 (f64.const -0)))
      (else (local.set 1 (f64.const 1))))
    (i64.reinterpret_f64 (local.get 1)))
  (func (export "via_select") (param i32) (result i64)
    (i64.reinterpret_f64
      (select (f64.const -0) (f64.const 2) (local.get 0))))
  (func (export "via_copysign_cc") (result i64)
    (i64.reinterpret_f64 (f64.copysign (f64.const 0) (f64.const -1))))
  (func (export "via_copysign_cv") (result i64)
    ;; sign source is a runtime -0 built by neg, not a parameter
    (i64.reinterpret_f64 (f64.copysign (f64.const 0) (f64.neg (f64.const 0)))))
  (func (export "via_copysign_vc") (result i64)
    (i64.reinterpret_f64 (f64.copysign (f64.const 0) (f64.const -1))))
  (func (export "via_neg_zero") (result i64)
    (i64.reinterpret_f64 (f64.neg (f64.const 0))))
  (func (export "via_load") (result i64)
    (i64.reinterpret_f64 (f64.load (i32.const 8))))
  (func (export "via_add") (result i64)
    (i64.reinterpret_f64 (f64.add (f64.const -0) (f64.const -0))))
  (func (export "via_mul_neg1") (result i64)
    (i64.reinterpret_f64 (f64.mul (f64.const 0) (f64.const -1))))
)
