(module
  ;; Cross-chunk direct calls made from direct-asm-retained bodies.
  ;; Unlike cg_crosscall.wat, every op here lowers to native
  ;; instructions (no rotl/rotr/div, which become helper CALLs the
  ;; direct-asm emitter's ForbidCalls refuses), so the retained
  ;; functions actually emit via internal/asmgen and their
  ;; cross-chunk CALL operands are exercised. Bodies are padded past
  ;; the tiny multi-package chunk budgets the tests use, so each
  ;; function lands in its own chunk package.

  ;; leafA: a long dependent i64 chain of native-lowering ops.
  (func $leafA (param $a i64) (param $b i64) (result i64)
    (local $x i64)
    (local.set $x (i64.add (local.get $a) (local.get $b)))
    (local.set $x (i64.mul (local.get $x) (i64.const 31)))
    (local.set $x (i64.xor (local.get $x) (i64.const 0x9e3779b97f4a7c15)))
    (local.set $x (i64.add (local.get $x) (i64.shr_u (local.get $x) (i64.const 7))))
    (local.set $x (i64.mul (local.get $x) (i64.const 0x100000001b3)))
    (local.set $x (i64.xor (local.get $x) (i64.shl (local.get $x) (i64.const 13))))
    (local.set $x (i64.add (local.get $x) (i64.const 12345)))
    (local.set $x (i64.sub (local.get $x) (i64.shl (local.get $a) (i64.const 17))))
    (local.set $x (i64.xor (local.get $x) (i64.shr_u (local.get $b) (i64.const 9))))
    (local.set $x (i64.mul (local.get $x) (i64.const 7)))
    (i64.add (local.get $x) (i64.shr_s (local.get $x) (i64.const 3))))

  ;; leafB: a different long chain.
  (func $leafB (param $a i64) (result i64)
    (local $y i64)
    (local.set $y (i64.mul (local.get $a) (i64.const 0x5851f42d4c957f2d)))
    (local.set $y (i64.add (local.get $y) (i64.const 0x14057b7ef767814f)))
    (local.set $y (i64.xor (local.get $y) (i64.shr_u (local.get $y) (i64.const 33))))
    (local.set $y (i64.mul (local.get $y) (i64.const 0xff51afd7ed558ccd)))
    (local.set $y (i64.xor (local.get $y) (i64.shr_u (local.get $y) (i64.const 29))))
    (local.set $y (i64.add (local.get $y) (i64.shl (local.get $a) (i64.const 5))))
    (local.set $y (i64.sub (local.get $y) (i64.const 999)))
    (local.set $y (i64.or (local.get $y) (i64.const 1)))
    (i64.mul (local.get $y) (i64.const 3)))

  ;; mid combines both leaves; retained for direct-asm, so its two
  ;; cross-chunk calls come out of the asmgen emitter.
  (func $mid (param $a i64) (param $b i64) (result i64)
    (local $z i64)
    (local.set $z (i64.add
      (call $leafA (local.get $a) (local.get $b))
      (call $leafB (local.get $a))))
    (local.set $z (i64.xor (local.get $z) (i64.shr_u (local.get $z) (i64.const 11))))
    (local.set $z (i64.mul (local.get $z) (i64.const 5)))
    (local.set $z (i64.add (local.get $z) (i64.shr_u (local.get $b) (i64.const 21))))
    (local.set $z (i64.sub (local.get $z) (i64.shl (local.get $a) (i64.const 2))))
    (local.set $z (i64.xor (local.get $z) (i64.const 0x0f0f0f0f0f0f0f0f)))
    (i64.add (local.get $z) (i64.const 42)))

  ;; wide: enough i64 params to overflow the register ABI, so this
  ;; function keeps its pure Go body (sig fallback) while its callers
  ;; are transformed — a direct-asm caller's CALL then resolves
  ;; against the ABI0 wrapper the gcasmABI0Keep anchor forces out.
  (func $wide
      (param i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
      (result i64)
    (i64.add (local.get 0)
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

  (func (export "crosscall_da") (param $a i64) (param $b i64) (result i64)
    (i64.add
      (i64.add
        (call $mid (local.get $a) (local.get $b))
        (call $leafB (local.get $b)))
      (call $wide
        (local.get $a) (local.get $b) (local.get $a) (local.get $b)
        (local.get $a) (local.get $b) (local.get $a) (local.get $b)
        (local.get $a) (local.get $b) (local.get $a) (local.get $b))))
)
