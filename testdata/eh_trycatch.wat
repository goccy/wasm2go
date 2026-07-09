;; Exception-handling fixture for the wasm2go parser/decoder (legacy EH
;; proposal — the shape clang emits for setjmp/longjmp under -wasm-enable-sjlj).
;; Exercises: tag section, throw, try/catch <tag>, catch_all, rethrow, delegate.
(module
  (tag $e (param i32))

  (func $throwing
    i32.const 7
    throw $e)

  (func $catching (result i32)
    try (result i32)
      call $throwing
      i32.const 0
    catch $e
      ;; the exception's i32 operand is pushed here
    catch_all
      i32.const -1
    end)

  (func $rethrowing
    try
      call $throwing
    catch_all
      rethrow 0
    end)

  (func $delegating
    try
      call $throwing
    delegate 0)

  ;; Exercises mutable-locals mode: a local set before the try and read in
  ;; both the body and the catch handler (must survive the exceptional edge).
  (func $withlocal (param i32) (result i32)
    (local i32)
    local.get 0
    i32.const 1
    i32.add
    local.set 1
    try (result i32)
      call $throwing
      local.get 1
    catch_all
      local.get 1
    end)

  (export "catching" (func $catching))
  (export "withlocal" (func $withlocal)))
