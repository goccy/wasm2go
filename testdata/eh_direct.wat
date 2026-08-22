;; Exception-handling fixture for the direct-asm backend: every
;; branch-based EH op the emitters lower (OpExcPending / OpExcTag /
;; OpExcVal / OpExcRaise / OpExcRearm / OpExcClear) across all four
;; operand widths (i32 i64 f32 f64), with both constant and computed
;; throw operands, tag dispatch with a non-matching clause, and a
;; catch_all rethrow.
(module
  (tag $e (param i32 i64 f32 f64))
  (tag $g (param i32))

  ;; fn0: throws $e with constant operands when x != 0.
  ;; The i64 wraps to 42 in the catcher's i32 combine.
  (func $maybe_throw (param i32)
    local.get 0
    if
      i32.const 41
      i64.const 0x10000002A
      f32.const 43.5
      f64.const 44.25
      throw $e
    end)

  ;; fn1: catch $e and combine all four operands into one i32 (all
  ;; helper-free ops so the direct emitter keeps the whole body):
  ;; v0 + wrap(v1) + bits(v2) + hi32(bits(v3)). -1 when nothing throws.
  (func $catch_sum (param i32) (result i32)
    (local $a i32) (local $b i64) (local $c f32) (local $d f64)
    try (result i32)
      local.get 0
      call $maybe_throw
      i32.const -1
    catch $e
      local.set $d
      local.set $c
      local.set $b
      local.set $a
      local.get $a
      local.get $b
      i32.wrap_i64
      i32.add
      local.get $c
      i32.reinterpret_f32
      i32.add
      local.get $d
      i64.reinterpret_f64
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.add
    end)

  ;; fn2: tag dispatch that does NOT match ($g clause on an $e throw)
  ;; plus a catch_all rethrow; the outer try catches the re-raised $e
  ;; and returns its first operand. -2 when nothing throws.
  (func $reraise (param i32) (result i32)
    (local $a i32) (local $b i64) (local $c f32) (local $d f64)
    try (result i32)
      try (result i32)
        local.get 0
        call $maybe_throw
        i32.const -2
      catch $g
        ;; not taken for $e throws; result is $g's i32 operand
      catch_all
        rethrow 0
      end
    catch $e
      local.set $d
      local.set $c
      local.set $b
      local.set $a
      local.get $a
    end)

  ;; fn3: throws $e with COMPUTED operands (params, not constants).
  (func $throw_vals (param i32 i64 f32 f64)
    local.get 0
    local.get 1
    local.get 2
    local.get 3
    throw $e)

  ;; fn4: builds (x, x+1, x+2, x+3) across the four widths, throws,
  ;; catches, and combines with the same helper-free recipe as fn1.
  (func $catch_dyn (param i32) (result i32)
    (local $a i32) (local $b i64) (local $c f32) (local $d f64)
    try (result i32)
      local.get 0
      local.get 0
      i32.const 1
      i32.add
      i64.extend_i32_s
      local.get 0
      i32.const 2
      i32.add
      f32.convert_i32_s
      local.get 0
      i32.const 3
      i32.add
      f64.convert_i32_s
      call $throw_vals
      i32.const -3
    catch $e
      local.set $d
      local.set $c
      local.set $b
      local.set $a
      local.get $a
      local.get $b
      i32.wrap_i64
      i32.add
      local.get $c
      i32.reinterpret_f32
      i32.add
      local.get $d
      i64.reinterpret_f64
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.add
    end)

  ;; fn5: throws the OTHER tag.
  (func $throw_g
    i32.const 9
    throw $g)

  ;; fn6: reports which tag was caught: 1 for $e, 100 + operand for $g.
  (func $which (param i32) (result i32)
    (local $a i32) (local $b i64) (local $c f32) (local $d f64)
    try (result i32)
      local.get 0
      if
        call $throw_g
      else
        i32.const 1
        call $maybe_throw
      end
      i32.const 0
    catch $e
      local.set $d
      local.set $c
      local.set $b
      local.set $a
      i32.const 1
    catch $g
      i32.const 100
      i32.add
    end)

  (export "catch_sum" (func $catch_sum))
  (export "reraise" (func $reraise))
  (export "catch_dyn" (func $catch_dyn))
  (export "which" (func $which)))
