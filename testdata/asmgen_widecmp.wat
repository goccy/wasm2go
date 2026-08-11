(module
  ;; 64-bit shifts through the variable-count emitters.
  (func (export "shl64") (param i64 i64) (result i64)
    local.get 0
    local.get 1
    i64.shl)
  (func (export "shr_s64") (param i64 i64) (result i64)
    local.get 0
    local.get 1
    i64.shr_s)
  (func (export "shr_u64") (param i64 i64) (result i64)
    local.get 0
    local.get 1
    i64.shr_u)

  ;; 64-bit compares producing a materialized i32 (emitCmp64 family).
  (func (export "lt_s64") (param i64 i64) (result i32)
    local.get 0
    local.get 1
    i64.lt_s)
  (func (export "gt_u64") (param i64 i64) (result i32)
    local.get 0
    local.get 1
    i64.gt_u)
  (func (export "eq64") (param i64 i64) (result i32)
    local.get 0
    local.get 1
    i64.eq)

  ;; float min/max and compares (inline float emitters).
  (func (export "fmin") (param f32 f32) (result f32)
    local.get 0
    local.get 1
    f32.min)
  (func (export "fmax") (param f64 f64) (result f64)
    local.get 0
    local.get 1
    f64.max)
  (func (export "flt") (param f32 f32) (result i32)
    local.get 0
    local.get 1
    f32.lt)
  (func (export "fge") (param f64 f64) (result i32)
    local.get 0
    local.get 1
    f64.ge)

  ;; A conditional branch on a masked bit (the fused bit-test branch)
  ;; plus an unreachable arm (EmitUnreachable on the cold path).
  (func (export "bittest") (param i32) (result i32)
    local.get 0
    i32.const 8
    i32.and
    if (result i32)
      i32.const 1
    else
      i32.const 0
    end)
  (func (export "trapif") (param i32) (result i32)
    local.get 0
    if
      unreachable
    end
    i32.const 7)
)
