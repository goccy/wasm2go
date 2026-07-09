;; Forces the recover-TRAMPOLINE goto-EH path: a try/catch sits inside a loop
;; that has TWO distinct exit targets ($b1, $b2), so the structured emitter
;; bails (multi-exit loop) and the function is laid out via emitTrampoline.
;; run($x): each iteration increments $i, throws $i and catches it into $r; then
;;   if $r == $x  -> $b1 -> $r = 100
;;   if $i >= 10  -> $b2 -> $r = 200
;; so run(3) = 100 (caught 3 == x on the 3rd iteration) and run(50) = 200.
(module
  (tag $e (param i32))
  (func $thrower (param i32)
    local.get 0
    throw $e)
  (func (export "run") (param $x i32) (result i32)
    (local $r i32)
    (local $i i32)
    block $done
      block $b2
        block $b1
          loop $lp
            local.get $i
            i32.const 1
            i32.add
            local.set $i
            try
              local.get $i
              call $thrower
            catch $e
              local.set $r
            end
            local.get $r
            local.get $x
            i32.eq
            br_if $b1
            local.get $i
            i32.const 10
            i32.ge_s
            br_if $b2
            br $lp
          end
        end
        i32.const 100
        local.set $r
        br $done
      end
      i32.const 200
      local.set $r
      br $done
    end
    local.get $r))
