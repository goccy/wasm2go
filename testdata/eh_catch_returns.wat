;; Regression: a catch landing pad that leaves the function directly.
;;
;; A landing pad is entered by unwinding, not by a CFG edge, so it has no
;; predecessors. Usually it also has a successor — the try's `end` falls through
;; to the region's Post — which is why PruneDeadBlocks, whose rule is "no preds
;; AND no succs", never touched one. A handler that ends in `return` has neither,
;; so it was pruned out of Func.Blocks while the TryRegion kept pointing at it.
;; The recover trampoline then emitted the `case <id>: goto L<id>` that resumes
;; into the handler for a label nobody defined:
;;
;;   p_pure.go:33:10: label L3 not defined
;;
;; `plain` is the minimal shape: no loop, no br_table, just a try whose catch
;; returns. `inLoop` is the same handler inside a loop, which is where it was
;; first hit — there the pruned handler also made the structured emitter's
;; block-count check fail, so the whole function fell back to the goto emitter
;; and produced the uncompilable output above.
;;
;; $t throws only for 7.
(module
  (tag $e (param i32))

  (func $t (param i32)
    local.get 0
    i32.const 7
    i32.eq
    if
      i32.const 99
      throw $e
    end)

  ;; plain(0) = 1, plain(7) = 42
  (func (export "plain") (param $x i32) (result i32)
    (try
      (do (call $t (local.get $x)))
      (catch $e (return (i32.const 42))))
    (i32.const 1))

  ;; inLoop(0) = 3 (i counts to 3 and the loop exits)
  ;; inLoop(7) = 42 (throws on the first iteration; the handler returns i + 41)
  (func (export "inLoop") (param $x i32) (result i32)
    (local $i i32)
    (block $done
      (loop $lp
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (try
          (do
            (call $t (local.get $x))
            (br_if $done (i32.ge_s (local.get $i) (i32.const 3))))
          (catch $e (return (i32.add (local.get $i) (i32.const 41)))))
        (br $lp)))
    (local.get $i))
)
