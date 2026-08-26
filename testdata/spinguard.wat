;; spinguard.wat — loop shapes for the bare-atomic-spin preemption guard
;; (spinguard.go). `bare_spin` is ggml_barrier's wait: an inline atomic
;; load compared against an argument, back-branching with no call — the
;; shape that must receive a spinRelax guard. `spin_with_call` is the
;; same wait but with a direct call in the body (already preemptible —
;; no guard), and `plain_loop` spins on a non-atomic load (not a
;; cross-thread wait — no guard). `big_spin` is a bare spin whose body
;; carries dozens of data-dependent values: it must still be guarded,
;; at a shorter derived interval (the guard budget is time, not
;; iterations).
(module
  (memory 1 1 shared)
  ;; $tick recurses on its own (compile-time-unknown) argument, so no
  ;; amount of inlining or constant folding removes the recursive call —
  ;; the spin_with_call loop keeps a genuine OpCallDirect, which its
  ;; no-guard expectation needs. (A constant or straight-line callee
  ;; gets inlined away, correctly turning the caller into a bare spin —
  ;; the guard analysis runs on the final, post-inline code.) At runtime
  ;; the argument is a zeroed memory word, so the recursion never fires.
  (func $tick (param i32) (result i32)
    (if (result i32) (local.get 0)
      (then (call $tick (local.get 0)))
      (else (i32.const 1))))
  (func (export "bare_spin") (param i32) (result i32)
    (loop $w
      (br_if $w (i32.eq (i32.atomic.load (i32.const 16)) (local.get 0))))
    (i32.atomic.load (i32.const 16)))
  (func (export "bare_spin64") (param i64) (result i64)
    (loop $w
      (br_if $w (i64.eq (i64.atomic.load (i32.const 24)) (local.get 0))))
    (i64.atomic.load (i32.const 24)))
  (func (export "spin_with_call") (param i32) (result i32)
    (loop $w
      (drop (call $tick (i32.atomic.load (i32.const 48))))
      (br_if $w (i32.eq (i32.atomic.load (i32.const 16)) (local.get 0))))
    (i32.atomic.load (i32.const 16)))
  (func (export "big_spin") (param i32) (result i32)
    (local i32)
    (loop $w
      (local.set 1 (i32.mul (i32.add (i32.xor (i32.mul (i32.add (i32.xor (i32.mul (i32.add (i32.xor (i32.mul (i32.add (i32.xor (i32.mul (i32.add (i32.xor (i32.mul (i32.add (i32.xor (i32.mul (i32.add (i32.xor (i32.mul (i32.add (i32.xor (i32.mul (i32.add (i32.xor (i32.mul (i32.add (i32.xor (i32.mul (i32.add (i32.xor (i32.mul (i32.add (i32.xor (i32.mul (i32.add (i32.xor (i32.mul (local.get 1) (i32.const 654435747)) (i32.const 147483637)) (i32.const 723777223)) (i32.const 297842322)) (i32.const 874135908)) (i32.const 300713404)) (i32.const 877006734)) (i32.const 451071065)) (i32.const 18975748)) (i32.const 445557479)) (i32.const 954737977)) (i32.const 528803076)) (i32.const 105096655)) (i32.const 531678126)) (i32.const 107970553)) (i32.const 682031787)) (i32.const 248887926)) (i32.const 677566809)) (i32.const 178021163)) (i32.const 687070589)) (i32.const 261265992)) (i32.const 837493786)) (i32.const 264075474)) (i32.const 831980196)) (i32.const 406041327)) (i32.const 982334913)) (i32.const 408916381)) (i32.const 985208943)) (i32.const 492165306)) (i32.const 68454501)) (i32.const 495036228)) (i32.const 61892367)) (i32.const 638054881)) (i32.const 212250156)) (i32.const 640924687)) (i32.const 215121114)) (i32.const 717541523)) (i32.const 224629086)) (i32.const 792398768)) (i32.const 219111304)))
      (br_if $w (i32.eq (i32.atomic.load (i32.const 16))
                        (i32.add (local.get 0) (local.get 1)))))
    (local.get 1))
  (func (export "plain_loop") (param i32) (result i32)
    (loop $w
      (br_if $w (i32.eq (i32.load (i32.const 16)) (local.get 0))))
    (i32.load (i32.const 16))))
