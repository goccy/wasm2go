;; A br out of a protected body leaves the try WITHOUT passing its Post block
;; (this same br is what routes the function to the recover-trampoline). The
;; try's active-flag must drop on that exit edge: the later throw happens
;; OUTSIDE the try and must propagate to the caller, not into the stale
;; handler. Expected: 222 (111 would mean the exited try still caught it).
(module
  (tag $a)
  (func $inner (result i32)
    block $out
      try
        br $out
      catch_all
        i32.const 111
        return
      end
    end
    throw $a)
  (func (export "run") (result i32)
    try (result i32)
      call $inner
    catch_all
      i32.const 222
    end))
