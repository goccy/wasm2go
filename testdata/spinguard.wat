;; spinguard.wat — loop shapes for the bare-atomic-spin preemption guard
;; (spinguard.go). `bare_spin` is ggml_barrier's wait: an inline atomic
;; load compared against an argument, back-branching with no call — the
;; shape that must receive a spinRelax guard. `spin_with_call` is the
;; same wait but with a direct call in the body (already preemptible —
;; no guard), and `plain_loop` spins on a non-atomic load (not a
;; cross-thread wait — no guard).
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
  (func (export "plain_loop") (param i32) (result i32)
    (loop $w
      (br_if $w (i32.eq (i32.load (i32.const 16)) (local.get 0))))
    (i32.load (i32.const 16))))
