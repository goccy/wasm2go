;; Reachable unreachable: trap path is in the control-flow graph,
;; so SSA's DCE keeps the BlockUnreachable terminator.
(module
  (func (export "trap_if_zero") (param $x i32) (result i32)
    (if (i32.eqz (local.get $x))
      (then (unreachable)))
    (i32.const 42))
  (func (export "always_42") (result i32) (i32.const 42))
)
