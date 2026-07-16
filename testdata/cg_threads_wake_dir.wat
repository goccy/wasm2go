;; main->agent futex wake direction. The agent parks in memory.atomic.wait32;
;; the MAIN thread (the primary Module, not a clone) stores + notifies. The
;; reverse direction (agent notifies, main waits) is what cg_threads.wat
;; already covers — this one is what a C mutex handoff does when the main
;; thread unlocks while an agent sleeps on the futex.
(module
  (import "wasi" "thread-spawn" (func $spawn (param i32) (result i32)))
  (memory 1 4 shared)
  ;; 16: futex word / 24: agent result flag
  (func (export "wasi_thread_start") (param $tid i32) (param $arg i32)
    ;; park until the futex word becomes nonzero (wait while == 0)
    (block $awake
      (loop $again
        (br_if $awake (i32.ne (i32.atomic.load (i32.const 16)) (i32.const 0)))
        ;; wait(addr=16, expected=0, timeout=-1) -> 0 ok / 1 not-equal
        (drop (memory.atomic.wait32 (i32.const 16) (i32.const 0) (i64.const -1)))
        (br $again)))
    (i32.atomic.store (i32.const 24) (i32.const 7777)))
  (func (export "run") (result i32)
    (local $i i32)
    (drop (call $spawn (i32.const 0)))
    ;; give the agent a moment to reach the wait (spin ~1M iterations)
    (block $b (loop $l
      (br_if $b (i32.ge_u (local.get $i) (i32.const 2000000)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $l)))
    ;; publish and wake
    (i32.atomic.store (i32.const 16) (i32.const 1))
    (drop (memory.atomic.notify (i32.const 16) (i32.const 1)))
    ;; wait for the agent's answer (bounded spin so a hang FAILS, not wedges)
    (local.set $i (i32.const 0))
    (block $got (loop $wait
      (br_if $got (i32.ne (i32.atomic.load (i32.const 24)) (i32.const 0)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $got (i32.ge_u (local.get $i) (i32.const 500000000)))
      (br $wait)))
    (i32.atomic.load (i32.const 24))))
