;; cg_threads_m64.wat — the shared-memory wasi_thread_spawn scenario of
;; cg_threads.wat on a memory64: i64 addressing throughout, an i64 start_arg
;; (a linear-memory pointer), and memory.size/grow in i64 pages. Exercises the
;; goroutine-backed spawn, cross-goroutine _m64 atomics on shared memory64,
;; and the wait/notify parking lot with 64-bit effective addresses.
(module
  (import "wasi" "thread-spawn" (func $thread_spawn (param i64) (result i32)))
  (memory (export "memory") i64 1 2 shared)

  ;; wasi-libc's thread entry: called on a fresh agent with (tid, arg).
  ;; arg is the address of the counter to bump — an i64 pointer here.
  (func (export "wasi_thread_start") (param $tid i32) (param $arg i64)
    (drop (i32.atomic.rmw.add (local.get $arg) (i32.const 1)))
    (drop (memory.atomic.notify (local.get $arg) (i32.const -1))))

  ;; Spawn n agents on counter address 64 and spin-wait (with a bounded
  ;; atomic wait, so a lost notify shows up as a timeout, not a hang)
  ;; until the counter reaches n. Returns the final counter.
  (func (export "spawn_and_join") (param $n i32) (result i32)
    (local $i i32)
    (i32.atomic.store (i64.const 64) (i32.const 0))
    (block $spawned
      (loop $spawn
        (br_if $spawned (i32.ge_s (local.get $i) (local.get $n)))
        (drop (call $thread_spawn (i64.const 64)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $spawn)))
    (block $done
      (loop $wait
        (br_if $done (i32.ge_s (i32.atomic.load (i64.const 64)) (local.get $n)))
        ;; wait while the counter still holds its current value (1s cap)
        (drop (memory.atomic.wait32 (i64.const 64)
                                    (i32.atomic.load (i64.const 64))
                                    (i64.const 1000000000)))
        (br $wait)))
    (i32.atomic.load (i64.const 64)))

  ;; memory.grow on a shared memory must not relocate: the pointer other
  ;; agents deref stays valid. Returns new size in bytes plus the sentinel
  ;; written before the grow.
  (func (export "grow_shared") (result i64)
    (i32.atomic.store (i64.const 128) (i32.const 0xbeef))
    (drop (memory.grow (i64.const 1)))
    ;; data written before the grow must still be there, and the new size visible
    (i64.add (i64.mul (memory.size) (i64.const 65536))
             (i64.extend_i32_u (i32.atomic.load (i64.const 128))))))
