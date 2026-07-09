;; br_table exercised through the STRUCTURED emitter: three cases (plus default)
;; each set $r then br to the common join $end, which returns $r. This is the
;; N-way analogue of an if/else with a shared join. run(sel) yields:
;;   0 -> 11, 1 -> 22, 2 -> 33, anything else -> 33 (default maps to case 2).
(module
  (func (export "run") (param $sel i32) (result i32)
    (local $r i32)
    (block $end
      (block $c2
        (block $c1
          (block $c0
            local.get $sel
            br_table $c0 $c1 $c2 $c2)
          i32.const 11
          local.set $r
          br $end)
        i32.const 22
        local.set $r
        br $end)
      i32.const 33
      local.set $r)
    local.get $r))
