;; `rethrow l` with a non-zero depth re-raises an OUTER catch's exception.
;; The inner catch_all holds $a(99) but rethrow 1 names the outer catch $a,
;; whose exception is $a(42); the top-level try must observe 42, not 99.
(module
  (tag $a (param i32))
  (func (export "run") (result i32)
    try (result i32)
      try (result i32)
        i32.const 42
        throw $a
      catch $a
        drop
        try (result i32)
          i32.const 99
          throw $a
        catch_all
          rethrow 1
        end
      end
    catch $a
    end))
