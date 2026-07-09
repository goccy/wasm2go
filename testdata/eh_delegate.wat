;; End-to-end EH fixture for `delegate`. run()'s inner `try ... delegate 0`
;; forwards the exception thrown by $thrower to the enclosing $o try, whose
;; `catch $e` yields the operand 42. Exercises delegate lowering (a handler-less
;; try region that recovers-and-re-panics to the enclosing handler).
(module
  (tag $e (param i32))
  (func $thrower (param i32)
    local.get 0
    throw $e)

  (func (export "run") (result i32)
    try $o (result i32)
      try
        i32.const 42
        call $thrower
      delegate 0        ;; forward to $o's handler
      i32.const 0       ;; unreachable: $thrower always throws
    catch $e
    end))
