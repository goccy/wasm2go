;; Cross-thread visibility of PLAIN stores published via atomics — the
;; cg_threads_visibility.wat scenario on a shared memory64: the main thread
;; writes a value with a normal (i64-addressed) store, then publishes with an
;; atomic store (release); the spawned thread spins on an atomic load
;; (acquire) and must then observe the plain store.
(module
  (import "wasi" "thread-spawn" (func $spawn (param i64) (result i32)))
  (memory i64 1 4 shared)
  ;; addr 16: plain payload / addr 20: atomic flag / addr 24: agent's answer flag
  (func (export "wasi_thread_start") (param $tid i32) (param $arg i64)
    ;; spin until the flag publishes
    (block $done
      (loop $spin
        (br_if $done (i32.eq (i32.atomic.load (i64.const 20)) (i32.const 1)))
        (br $spin)))
    ;; read the PLAIN store and publish the answer atomically
    (i32.atomic.store (i64.const 24) (i32.load (i64.const 16))))
  (func (export "run") (result i32)
    (drop (call $spawn (i64.const 0)))
    ;; plain store, then release-publish
    (i32.store (i64.const 16) (i32.const 4242))
    (i32.atomic.store (i64.const 20) (i32.const 1))
    ;; wait for the agent's answer
    (block $got
      (loop $wait
        (br_if $got (i32.ne (i32.atomic.load (i64.const 24)) (i32.const 0)))
        (br $wait)))
    (i32.atomic.load (i64.const 24))))
