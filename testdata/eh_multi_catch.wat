;; Multi-clause catch dispatch: one try with catch $a / catch $b / catch_all.
;; $f(0) throws $a(10) -> 10+1 = 11; $f(1) throws $b(20) -> 20+2 = 22;
;; $f(2) throws $c (no payload) -> catch_all = 99. run = 11+22+99 = 132.
(module
  (tag $a (param i32))
  (tag $b (param i32))
  (tag $c)
  (func $throw_sel (param i32)
    local.get 0
    i32.eqz
    if
      i32.const 10
      throw $a
    end
    local.get 0
    i32.const 1
    i32.eq
    if
      i32.const 20
      throw $b
    end
    throw $c)
  (func $f (param i32) (result i32)
    try (result i32)
      local.get 0
      call $throw_sel
      i32.const 0
    catch $a
      i32.const 1
      i32.add
    catch $b
      i32.const 2
      i32.add
    catch_all
      i32.const 99
    end)
  (func (export "run") (result i32)
    i32.const 0
    call $f
    i32.const 1
    call $f
    i32.add
    i32.const 2
    call $f
    i32.add))
