;; Same multi-clause dispatch as eh_multi_catch, but a `return` inside the try
;; body forces the recover-trampoline emit path (a function return cannot be
;; expressed inside the structured emitter's try closure). $f(3) takes that
;; return. run = 11 + 22 + 99 + 7 = 139.
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
      i32.const 3
      i32.eq
      if
        i32.const 7
        return
      end
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
    i32.add
    i32.const 3
    call $f
    i32.add))
