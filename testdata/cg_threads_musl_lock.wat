;; musl's 2-int internal lock (__lock/__unlock in src/thread/__lock.c): the
;; futex word at l[0] and a WAITERS COUNTER at l[1]. The unlock side reads the
;; counter with a PLAIN load to decide whether to notify, and the waiter spins
;; on the futex word with PLAIN loads between futex waits. wasm's memory model
;; gives plain accesses hardware-like coherence, so this is legal wasm — the
;; translated Go must preserve it or malloc/stdio locks (and everything else
;; built on __lock) can skip wakes and strand a thread forever.
(module
  (import "wasi" "thread-spawn" (func $spawn (param i32) (result i32)))
  (memory 1 4 shared)
  ;; 16: futex word / 20: waiters / 24: shared counter / 32: agent-done
  (func $lock
    (block $have
      (br_if $have
        (i32.eqz (i32.atomic.rmw.cmpxchg (i32.const 16) (i32.const 0) (i32.const 1))))
      (loop $retry
        (if (i32.ne (i32.atomic.rmw.xchg (i32.const 16) (i32.const 2)) (i32.const 0))
          (then
            ;; __wait: waiters++, wait while the PLAIN load still sees 2, waiters--
            (drop (i32.atomic.rmw.add (i32.const 20) (i32.const 1)))
            (block $awake (loop $w
              (br_if $awake (i32.ne (i32.load (i32.const 16)) (i32.const 2)))
              (drop (memory.atomic.wait32 (i32.const 16) (i32.const 2) (i64.const -1)))
              (br $w)))
            (drop (i32.atomic.rmw.sub (i32.const 20) (i32.const 1)))
            (br $retry))))))
  (func $unlock
    ;; a_store(l, 0) then wake ONLY IF the PLAIN load of waiters is nonzero
    (i32.atomic.store (i32.const 16) (i32.const 0))
    (if (i32.ne (i32.load (i32.const 20)) (i32.const 0))
      (then (drop (memory.atomic.notify (i32.const 16) (i32.const 1))))))
  (func $bump (param $n i32)
    (local $i i32)
    (block $done (loop $l
      (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
      (call $lock)
      (i32.store (i32.const 24) (i32.add (i32.load (i32.const 24)) (i32.const 1)))
      (call $unlock)
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $l))))
  (func (export "wasi_thread_start") (param $tid i32) (param $arg i32)
    (call $bump (i32.const 50000))
    (i32.atomic.store (i32.const 32) (i32.const 1)))
  (func (export "run") (result i32)
    (local $i i32)
    (drop (call $spawn (i32.const 0)))
    (call $bump (i32.const 50000))
    (block $got (loop $wait
      (br_if $got (i32.eq (i32.atomic.load (i32.const 32)) (i32.const 1)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $got (i32.ge_u (local.get $i) (i32.const 2000000000)))
      (br $wait)))
    (call $lock)
    (i32.load (i32.const 24))))
