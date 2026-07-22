;; cg_atomics.wat — threads-proposal atomics in a single agent: loads,
;; stores, every RMW family incl. subword lanes, cmpxchg, fence, notify,
;; and a zero-timeout wait. Results are observable values, so the fixture
;; harness can diff them against wazero (threads feature enabled).
(module
  (memory 1 1 shared)
  (func (export "rmw32") (result i32)
    (i32.atomic.store (i32.const 16) (i32.const 100))
    (drop (i32.atomic.rmw.add (i32.const 16) (i32.const 5)))
    (drop (i32.atomic.rmw.sub (i32.const 16) (i32.const 1)))
    (drop (i32.atomic.rmw.and (i32.const 16) (i32.const 0xff)))
    (drop (i32.atomic.rmw.or (i32.const 16) (i32.const 0x100)))
    (drop (i32.atomic.rmw.xor (i32.const 16) (i32.const 0x1)))
    (i32.atomic.load (i32.const 16)))
  (func (export "rmw64") (result i64)
    (i64.atomic.store (i32.const 24) (i64.const 4000000000))
    (drop (i64.atomic.rmw.add (i32.const 24) (i64.const 4000000000)))
    (i64.atomic.load (i32.const 24)))
  (func (export "xchg") (result i32)
    (i32.atomic.store (i32.const 32) (i32.const 7))
    ;; old value (7) + new value (9) observed
    (i32.add (i32.atomic.rmw.xchg (i32.const 32) (i32.const 9))
             (i32.atomic.load (i32.const 32))))
  (func (export "cmpxchg") (result i32)
    (i32.atomic.store (i32.const 40) (i32.const 5))
    (drop (i32.atomic.rmw.cmpxchg (i32.const 40) (i32.const 5) (i32.const 6)))  ;; hits
    (drop (i32.atomic.rmw.cmpxchg (i32.const 40) (i32.const 5) (i32.const 7)))  ;; misses
    (i32.atomic.load (i32.const 40)))
  (func (export "subword") (result i32)
    ;; byte lanes at 48..51: store 0xAA at 49, add 1 at lane, read back word
    (i32.atomic.store (i32.const 48) (i32.const 0))
    (i32.atomic.store8 (i32.const 49) (i32.const 0xaa))
    (drop (i32.atomic.rmw8.add_u (i32.const 49) (i32.const 1)))
    (drop (i32.atomic.rmw16.xchg_u (i32.const 50) (i32.const 0x1234)))
    (i32.atomic.load (i32.const 48)))
  (func (export "subword_cmpxchg") (result i32)
    (i32.atomic.store8 (i32.const 56) (i32.const 3))
    (drop (i32.atomic.rmw8.cmpxchg_u (i32.const 56) (i32.const 3) (i32.const 9)))
    (i32.atomic.load8_u (i32.const 56)))
  (func (export "wait_notify") (result i32)
    (i32.atomic.store (i32.const 64) (i32.const 1))
    ;; not-equal (expected 0, actual 1) => 1; notify returns 0 woken
    (i32.add
      (memory.atomic.wait32 (i32.const 64) (i32.const 0) (i64.const 0))
      (memory.atomic.notify (i32.const 64) (i32.const 5))))
  (func (export "fenced_load") (result i32)
    (i32.atomic.store (i32.const 72) (i32.const 42))
    (atomic.fence)
    (i32.atomic.load (i32.const 72)))
  (func (export "store_neg") (result i32)
    ;; Negative constant operands: the inline-atomic emitter renders the
    ;; store value through an unsigned cast, which must be a runtime
    ;; conversion — `uint32(-1)` as a constant expression fails to
    ;; compile. Locks the force-hoist of atomic-store value operands.
    (i32.atomic.store (i32.const 80) (i32.const -1))
    (i64.atomic.store (i32.const 88) (i64.const -0x8000000000000000))
    (i32.add
      (i32.atomic.load (i32.const 80))
      (i32.wrap_i64 (i64.atomic.load (i32.const 88)))))
)
