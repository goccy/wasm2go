;; `delegate l` must skip every try between it and its target. The inner
;; delegate 1 targets the OUTER try (catch $a), so the middle catch_all —
;; which would otherwise swallow the exception — must never run.
;; Expected: 42 (999 would mean the delegate stopped at the middle try).
(module
  (tag $a (param i32))
  (func (export "run") (result i32)
    try (result i32)
      try (result i32)
        try
          i32.const 42
          throw $a
        delegate 1
        i32.const 0
      catch_all
        i32.const 999
      end
    catch $a
    end))
