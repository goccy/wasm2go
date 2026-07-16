;; A Drepper-style futex mutex (0=free,1=locked,2=locked+waiters) hammered from
;; both the main thread and an agent — the exact handoff wasi-libc's
;; pthread_mutex does. If the unlock's exchange ever fails to observe a
;; waiter's 1->2 transition, one side sleeps forever and the test times out.
(module
  (import "wasi" "thread-spawn" (func $spawn (param i32) (result i32)))
  (memory 1 4 shared)
  ;; 16: mutex word / 24: shared counter / 32: agent-done flag
  (func $lock
    (block $acquired
      ;; fast path
      (br_if $acquired
        (i32.eqz (i32.atomic.rmw.cmpxchg offset=12 (i32.const 4) (i32.const 0) (i32.const 1))))
      (loop $retry
        ;; mark contended and wait while it stays 2
        (if (i32.ne (i32.atomic.rmw.xchg offset=12 (i32.const 4) (i32.const 2)) (i32.const 0))
          (then
            (drop (memory.atomic.wait32 offset=12 (i32.const 4) (i32.const 2) (i64.const -1)))
            (br $retry))))))
  (func $unlock
    (if (i32.ne (i32.atomic.rmw.xchg offset=12 (i32.const 4) (i32.const 0)) (i32.const 1))
      (then (drop (memory.atomic.notify offset=12 (i32.const 4) (i32.const 1))))))
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
    ;; wait for the agent to finish (bounded spin: a wedged agent FAILS)
    (block $got (loop $wait
      (br_if $got (i32.eq (i32.atomic.load (i32.const 32)) (i32.const 1)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $got (i32.ge_u (local.get $i) (i32.const 2000000000)))
      (br $wait)))
    (call $lock)
    (i32.load (i32.const 24))))
