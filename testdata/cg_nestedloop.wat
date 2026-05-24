;; cg_nestedloop.wat — control-flow shapes that the structured SSA emitter
;; cannot cleanly reconstruct (nested loops, sequential loops), forcing the
;; goto-based emitMultiBlock fallback path. Uses only opcodes inside the
;; narrow SSA-lowering set (i32 add/sub/mul/lt, local get/set, block/loop/
;; br/br_if) so the function actually reaches SSA codegen.
(module
  ;; Two nested loops: outer counts i in [0,n), inner counts j in [0,i),
  ;; accumulating i*j-ish work. Nested loops are explicitly out of scope
  ;; for the structured emitter.
  (func (export "nested") (param $n i32) (result i32)
    (local $i i32)
    (local $j i32)
    (local $acc i32)
    (block $outer_done
      (loop $outer
        (br_if $outer_done (i32.ge_s (local.get $i) (local.get $n)))
        (local.set $j (i32.const 0))
        (block $inner_done
          (loop $inner
            (br_if $inner_done (i32.ge_s (local.get $j) (local.get $i)))
            (local.set $acc
              (i32.add (local.get $acc)
                (i32.add (local.get $i) (local.get $j))))
            (local.set $j (i32.add (local.get $j) (i32.const 1)))
            (br $inner)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $outer)))
    (local.get $acc))

  ;; Two sequential (non-nested) loops in one function: first sums 0..n,
  ;; then doubles the running total m times.
  (func (export "seq2") (param $n i32) (param $m i32) (result i32)
    (local $i i32)
    (local $acc i32)
    (block $d1
      (loop $l1
        (br_if $d1 (i32.ge_s (local.get $i) (local.get $n)))
        (local.set $acc (i32.add (local.get $acc) (local.get $i)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l1)))
    (local.set $i (i32.const 0))
    (block $d2
      (loop $l2
        (br_if $d2 (i32.ge_s (local.get $i) (local.get $m)))
        (local.set $acc (i32.add (local.get $acc) (local.get $acc)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l2)))
    (local.get $acc))

  ;; Multi-exit loop: the loop can leave to two distinct follow blocks
  ;; ($hit and $miss) depending on which condition fires. The structured
  ;; emitter rejects multi-exit loops, so this routes through the
  ;; goto-based emitMultiBlock.
  (func (export "multiexit") (param $n i32) (param $target i32) (result i32)
    (local $i i32)
    (block $miss
      (block $hit
        (loop $l
          (br_if $hit (i32.eq (local.get $i) (local.get $target)))
          (br_if $miss (i32.ge_s (local.get $i) (local.get $n)))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $l)))
      ;; reached via $hit
      (return (i32.mul (local.get $i) (i32.const 10))))
    ;; reached via $miss
    (i32.const -1))
)
