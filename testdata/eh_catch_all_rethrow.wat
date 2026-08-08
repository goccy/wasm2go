;; A catch_all that re-raises (the C++ "cleanup during unwind" shape: run the
;; cleanup, then rethrow 0). The rethrown exception keeps its tag and payload,
;; so the enclosing catch $a still receives 42.
(module
  (tag $a (param i32))
  (func (export "run") (result i32)
    try (result i32)
      try
        i32.const 42
        throw $a
      catch_all
        rethrow 0
      end
      i32.const 0
    catch $a
    end))
