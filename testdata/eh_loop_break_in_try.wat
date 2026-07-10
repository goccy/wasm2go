;; Regression: a single-exit loop whose TRY BODY contains a br_table that exits
;; the loop. The structured emitter would open `wlN: for {}` for the loop and,
;; for the br_table arm that leaves the loop, emit `break wlN` — but that break
;; sits inside the try region's `func() *wasmExc { … }()` closure, where the
;; label is out of scope (Go labels are function-scoped). Before the fix this
;; produced uncompilable Go ("break label not defined"); the emitter must bail
;; to the goto layout instead.
;;
;; run($x): loop increments $i; the try body calls $t (throws only when $x==7),
;; then br_table on $i: 1 -> continue the loop, otherwise -> exit. catch sets
;; $r=42. So run(0) exits with $r=0 after i reaches 2; run(7) throws on the
;; first iteration and catches -> 42.
(module
  (tag $e (param i32))
  (func $t (param i32)
    local.get 0
    i32.const 7
    i32.eq
    if
      i32.const 99
      throw $e
    end)
  (func (export "run") (param $x i32) (result i32)
    (local $r i32)
    (local $i i32)
    block $exit
      loop $lp
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        try
          local.get $x
          call $t
          local.get $i
          br_table $exit $lp $exit
        catch $e
          i32.const 42
          local.set $r
          br $exit
        end
      end
    end
    local.get $r))
