;; cg_deadend.wat — functions whose every path leaves via return/br, so the
;; implicit function-end is unreachable. The SSA lowering must synthesise a
;; well-formed terminator (zeroValueOf) for the dead trailing block.
(module
  ;; if/else, both arms return — function-end falls into a dead block.
  (func (export "both_return") (param $x i32) (result i32)
    (if (local.get $x)
      (then (return (i32.const 1)))
      (else (return (i32.const 2))))
    ;; unreachable: both arms already returned.
    (unreachable))

  ;; block whose only exit is a br to the function root.
  (func (export "br_root") (param $x i32) (result i32)
    (block $b
      (br_if $b (local.get $x))
      (return (i32.const 10)))
    (return (i32.const 20)))

  ;; loop that never falls through — exits only via return.
  (func (export "loop_return") (param $n i32) (result i32)
    (local $i i32)
    (loop $l
      (if (i32.ge_s (local.get $i) (local.get $n))
        (then (return (local.get $i))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $l))
    (unreachable))
)
