(module
  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add)

  (func (export "sub") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.sub)

  (func (export "mul64") (param i64 i64) (result i64)
    local.get 0
    local.get 1
    i64.mul)

  (func (export "div_s") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.div_s)

  (func (export "shifts") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.shl
    local.get 1
    i32.shr_u)

  (func (export "rotl") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.rotl)

  (func (export "lt_s") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.lt_s)

  (func (export "lt_u") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.lt_u))
