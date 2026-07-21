;; Fixture for the wasm-level leaf inliner: a caller invoking two small
;; leaf callees — one with params/result and an early return, one with
;; declared locals, a loop and memory stores. Both must be spliced into
;; the caller (no OpCallDirect survives) and the behavior must match
;; the called semantics exactly.
(module
  (memory 1)
  (func $leaf (param $a i32) (param $b i32) (result i32)
    (if (i32.eqz (local.get $a)) (then (return (i32.const 7))))
    (i32.add (local.get $a) (local.get $b)))
  (func $memleaf (param $p i32) (local $i i32)
    (block $done
      (loop $l
        (br_if $done (i32.ge_u (local.get $i) (i32.const 4)))
        (i32.store (i32.add (local.get $p) (i32.mul (local.get $i) (i32.const 4))) (local.get $i))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l))))
  (func (export "run") (param $x i32) (result i32)
    (call $memleaf (i32.const 64))
    (i32.add
      (call $leaf (local.get $x) (i32.const 5))
      (i32.load (i32.const 72)))))
