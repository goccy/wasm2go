(module
  ;; A pure-Go FALLBACK function whose body calls a TRANSFORMED
  ;; function in another chunk, next to a transformed sibling that
  ;; calls the same remote from asm. The fallback body's Go-level
  ;; reference and the sibling's spelled asm CALL then target one
  ;; remote symbol from one package — the shape that must never
  ;; produce a //go:linkname pull of an asm-referenced symbol (the
  ;; compiler would emit a DUPOK ABI0 wrapper under the remote name
  ;; that can shadow the remote TEXT at link time, depending on
  ;; package load order).

  ;; leaf: the remote transformed callee. It recurses on a countdown
  ;; so the inliner cannot fold the call away in its callers: the
  ;; depth-1 inline keeps the inner recursive call as a real CALL to
  ;; leaf's own symbol, which is what the callers below must reach
  ;; across chunks.
  (func $leaf (param $a i64) (param $n i32) (result i64)
    (local $y i64)
    (local.set $y (i64.mul (local.get $a) (i64.const 0x5851f42d4c957f2d)))
    (local.set $y (i64.add (local.get $y) (i64.const 0x14057b7ef767814f)))
    (local.set $y (i64.xor (local.get $y) (i64.shr_u (local.get $y) (i64.const 33))))
    (local.set $y (i64.mul (local.get $y) (i64.const 0xff51afd7ed558ccd)))
    (local.set $y (i64.xor (local.get $y) (i64.shr_u (local.get $y) (i64.const 29))))
    (local.set $y (i64.add (local.get $y) (i64.rotl (local.get $a) (i64.const 5))))
    (local.set $y (i64.or (local.get $y) (i64.const 1)))
    (if (result i64) (i32.eqz (local.get $n))
      (then (local.get $y))
      (else (call $leaf (local.get $y) (i32.sub (local.get $n) (i32.const 1))))))

  ;; sibling: transformed; CALLs leaf from asm (spelled remote symbol).
  (func $sibling (param $a i64) (param $b i64) (result i64)
    (local $z i64)
    (local.set $z (i64.add (call $leaf (local.get $a) (i32.const 2)) (local.get $b)))
    (local.set $z (i64.xor (local.get $z) (i64.shr_u (local.get $z) (i64.const 11))))
    (local.set $z (i64.mul (local.get $z) (i64.const 5)))
    (i64.add (local.get $z) (i64.const 42)))

  ;; widecaller: too many i64 params for the register ABI, so it keeps
  ;; its pure Go body (sig fallback) — and that body calls leaf.
  (func $widecaller
      (param i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
      (result i64)
    (i64.add (call $leaf (local.get 0) (i32.const 1))
    (i64.add (local.get 1)
    (i64.add (local.get 2)
    (i64.add (local.get 3)
    (i64.add (local.get 4)
    (i64.add (local.get 5)
    (i64.add (local.get 6)
    (i64.add (local.get 7)
    (i64.add (local.get 8)
    (i64.add (local.get 9)
    (i64.add (local.get 10) (local.get 11)))))))))))))

  (func (export "fallbackcaller") (param $a i64) (param $b i64) (result i64)
    (i64.add
      (call $sibling (local.get $a) (local.get $b))
      (call $widecaller
        (local.get $a) (local.get $b) (local.get $a) (local.get $b)
        (local.get $a) (local.get $b) (local.get $a) (local.get $b)
        (local.get $a) (local.get $b) (local.get $a) (local.get $b))))
)
