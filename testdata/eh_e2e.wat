;; End-to-end EH fixture: `run` calls a function that throws tag $e with operand
;; 42; the try/catch catches it and yields the operand as the result. Exercises
;; throw -> panic(wasmExc), try/catch -> defer/recover, and OpCatchArg.
(module
  (tag $e (param i32))
  (func $thrower
    i32.const 42
    throw $e)
  (func (export "run") (result i32)
    try (result i32)
      call $thrower
      i32.const 0
    catch $e
    end))
