;; cg_misc.wat — opcodes and block shapes the other fixtures miss: nop,
;; drop, typed select, blocks with a result type, if/else producing a
;; value, loops with a carried result, and unreachable in dead code.
(module
  (func (export "with_nop") (param i32) (result i32)
    (nop)
    (local.get 0)
    (nop))

  (func (export "with_drop") (param i32 i32) (result i32)
    (local.get 0)
    (local.get 1)
    (drop)) ;; drops second, leaves first

  ;; block that yields a value (block result type).
  (func (export "block_result") (param i32) (result i32)
    (block (result i32)
      (i32.add (local.get 0) (i32.const 1))))

  ;; if/else as an expression (if with a result type).
  (func (export "if_value") (param i32) (result i32)
    (if (result i32) (local.get 0)
      (then (i32.const 100))
      (else (i32.const 200))))

  ;; loop carrying a result via a block.
  (func (export "loop_sum") (param $n i32) (result i32)
    (local $i i32)
    (local $acc i32)
    (block $done (result i32)
      (loop $l
        (br_if $done (local.get $acc) (i32.ge_s (local.get $i) (local.get $n)))
        (local.set $acc (i32.add (local.get $acc) (local.get $i)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l))
      (local.get $acc)))

  ;; typed select (select with an explicit result-type immediate).
  (func (export "typed_select") (param i64 i64 i32) (result i64)
    (select (result i64) (local.get 0) (local.get 1) (local.get 2)))

  ;; unreachable after an unconditional return — dead code the compiler
  ;; must still decode without tripping.
  (func (export "dead_after_return") (param i32) (result i32)
    (return (local.get 0))
    (unreachable))

  ;; explicit return inside a branch.
  (func (export "early_return") (param i32) (result i32)
    (if (local.get 0)
      (then (return (i32.const 7))))
    (i32.const 9))

  ;; nested block + br to outer.
  (func (export "nested_br") (param i32) (result i32)
    (block $outer (result i32)
      (block $inner
        (br_if $inner (local.get 0))
        (br $outer (i32.const 1)))
      (i32.const 2)))
)
