;; ssa_cf.wat — targeted control-flow patterns for debugging the
;; multi-block SSA lowering. Each export exercises one structured-
;; control shape so a failure pinpoints the broken pattern.
(module
  ;; --- if/else producing a result ---
  (func (export "abs") (param i32) (result i32)
    (if (result i32) (i32.lt_s (local.get 0) (i32.const 0))
      (then (i32.sub (i32.const 0) (local.get 0)))
      (else (local.get 0))))

  ;; --- if WITHOUT else, side-effecting (no result) ---
  (func (export "clamp_if") (param i32) (result i32)
    (local i32)
    (local.set 1 (local.get 0))
    (if (i32.lt_s (local.get 1) (i32.const 0))
      (then (local.set 1 (i32.const 0))))
    (local.get 1))

  ;; --- counted loop with br_if back-edge ---
  ;; count(n): increments c until c >= n, returns c. = max(n, 1).
  (func (export "count") (param i32) (result i32)
    (local i32)
    (loop
      (local.set 1 (i32.add (local.get 1) (i32.const 1)))
      (br_if 0 (i32.lt_s (local.get 1) (local.get 0))))
    (local.get 1))

  ;; --- block + br forward exit ---
  ;; early(n): if n>10 return 100 else return n.
  (func (export "early") (param i32) (result i32)
    (local i32)
    (local.set 1 (local.get 0))
    (block
      (br_if 0 (i32.le_s (local.get 1) (i32.const 10)))
      (local.set 1 (i32.const 100)))
    (local.get 1))

  ;; --- loop with accumulator (phi for both i and sum) ---
  ;; sum(n) = 0+1+...+n  (n>=0).
  (func (export "sum") (param i32) (result i32)
    (local i32) ;; 1: i
    (local i32) ;; 2: acc
    (block
      (loop
        (br_if 1 (i32.gt_s (local.get 1) (local.get 0)))
        (local.set 2 (i32.add (local.get 2) (local.get 1)))
        (local.set 1 (i32.add (local.get 1) (i32.const 1)))
        (br 0)))
    (local.get 2))

  ;; --- br followed by a nested block in the dead region ---
  ;; deadnest(n): n!=0 -> 0 ; n==0 -> 42. The nested block after the
  ;; `br 0` is unreachable and its `end` must not pop the outer frame.
  (func (export "deadnest") (param i32) (result i32)
    (local i32)
    (block
      (br_if 0 (local.get 0))
      (local.set 1 (i32.const 42))
      (br 0)
      (block
        (local.set 1 (i32.const 99))
        (br 0))
      (local.set 1 (i32.const 7)))
    (local.get 1))

  ;; --- block WITH a result value carried across br ---
  ;; pick(n): n>0 -> 111 else 222, via a (result i32) block.
  (func (export "pick") (param i32) (result i32)
    (block (result i32)
      (i32.const 111)
      (br_if 0 (i32.gt_s (local.get 0) (i32.const 0)))
      (drop)
      (i32.const 222)))

  ;; --- explicit return from inside nested control ---
  ;; ret_nested(n): n<0 -> -1 (early return) ; else n+1.
  (func (export "ret_nested") (param i32) (result i32)
    (block
      (br_if 0 (i32.ge_s (local.get 0) (i32.const 0)))
      (return (i32.const -1)))
    (i32.add (local.get 0) (i32.const 1)))

  ;; --- br to depth 1 out of nested blocks + inner fall-through ---
  ;; deep(n): n>5 -> 1000 else n.
  (func (export "deep") (param i32) (result i32)
    (local i32)
    (local.set 1 (local.get 0))
    (block
      (block
        (br_if 0 (i32.le_s (local.get 1) (i32.const 5)))
        (local.set 1 (i32.const 1000))
        (br 1)))
    (local.get 1))

  ;; --- loop with a counter, exits via br 1, value via local ---
  ;; mul2(n): returns n*2 by adding n times.
  (func (export "mul2") (param i32) (result i32)
    (local i32) ;; 1: i
    (local i32) ;; 2: acc
    (block
      (loop
        (br_if 1 (i32.ge_s (local.get 1) (local.get 0)))
        (local.set 2 (i32.add (local.get 2) (i32.const 2)))
        (local.set 1 (i32.add (local.get 1) (i32.const 1)))
        (br 0)))
    (local.get 2))

  ;; --- block-result exited via `br` from inside an if, AND via
  ;;     fall-through. Reproduces a stale-stack bug pattern: the if's
  ;;     then-branch ends in `br 1` carrying a value, leaving its
  ;;     pushed value on the operand stack. The post-region stack must
  ;;     reset to the block-entry height so the base value (1000)
  ;;     below the result survives intact.
  ;; brblock(n): n!=0 -> 1007 ; n==0 -> 1009.
  (func (export "brblock") (param i32) (result i32)
    (i32.const 1000)            ;; base value, must survive untouched
    (block (result i32)
      (local.get 0)
      (if
        (then
          (i32.const 7)
          (br 1)))
      (i32.const 9))
    (i32.add))                  ;; 1000 + block-result

  ;; --- foldable: all-constant arithmetic. ConstProp collapses the
  ;;     whole expression to a single constant. fold_arith(_) = 14.
  ;;     The param is unused — DCE drops the dead OpParam value.
  (func (export "fold_arith") (param i32) (result i32)
    (i32.add (i32.const 2) (i32.mul (i32.const 3) (i32.const 4))))

  ;; --- foldable: a repeated subexpression. The wasm computes
  ;;     (n+1) twice; CSE merges the duplicate. fold_cse(n) = (n+1)^2.
  (func (export "fold_cse") (param i32) (result i32)
    (i32.mul
      (i32.add (local.get 0) (i32.const 1))
      (i32.add (local.get 0) (i32.const 1))))

  ;; --- foldable: a dead computation alongside the live result.
  ;;     DCE removes the unused product. fold_dead(n) = n+1.
  (func (export "fold_dead") (param i32) (result i32)
    (local i32)
    (local.set 1 (i32.mul (local.get 0) (local.get 0))) ;; dead: l1 unused
    (i32.add (local.get 0) (i32.const 1)))

  ;; --- nested if inside loop ---
  ;; counteven(n) = number of even values in [0, n).
  (func (export "counteven") (param i32) (result i32)
    (local i32) ;; 1: i
    (local i32) ;; 2: cnt
    (block
      (loop
        (br_if 1 (i32.ge_s (local.get 1) (local.get 0)))
        (if (i32.eqz (i32.and (local.get 1) (i32.const 1)))
          (then (local.set 2 (i32.add (local.get 2) (i32.const 1)))))
        (local.set 1 (i32.add (local.get 1) (i32.const 1)))
        (br 0)))
    (local.get 2))

  ;; --- br_table inside a loop, one arm exiting the loop ---
  ;; table_loop_exit(n): advance i from n until i is odd and i >= n+3.
  ;;
  ;; The loop's exit is a `br $done` nested inside one arm of a br_table. The
  ;; structured emitter renders the table as a Go `switch`, and every arm here
  ;; terminates, so nothing follows the switch and the `for` body ends with it.
  ;; Go binds a bare `break` to the innermost switch — so the exit must NAME
  ;; the loop. A bare break would leave only the switch and fall off the end of
  ;; the loop body, which is the back-edge: the loop would never terminate.
  (func (export "table_loop_exit") (param i32) (result i32)
    (local i32) ;; 1: i
    (local.set 1 (local.get 0))
    (block $done
      (loop $again
        (local.set 1 (i32.add (local.get 1) (i32.const 1)))
        (block $trap
          (block $odd
            (block $even
              ;; selector is 0 or 1, so the default ($trap) arm is dead. It is
              ;; here to remove the br_table's post-dominator, which is what
              ;; makes the `switch` the last statement of the loop body — and
              ;; therefore what makes a mis-bound `break` fall onto the
              ;; back-edge instead of onto a following statement.
              (br_table $even $odd $trap
                (i32.and (local.get 1) (i32.const 1))))
            ;; even: keep going
            (br $again))
          ;; odd: leave once i has caught up with n+5
          (br_if $done (i32.ge_s (local.get 1) (i32.add (local.get 0) (i32.const 5))))
          (br $again))
        (unreachable)))
    (local.get 1))

)
