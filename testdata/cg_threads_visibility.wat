;; Cross-thread visibility of PLAIN stores published via atomics: the main
;; thread writes a value with a normal store, then publishes with an atomic
;; store (release); the spawned thread spins on an atomic load (acquire) and
;; must then observe the plain store. This is the C/C++ mutex fast-path shape
;; (musl pthread_mutex uses a_cas/a_store around plain critical-section data).
(module
  (import "wasi" "thread-spawn" (func $spawn (param i32) (result i32)))
  (memory 1 4 shared)
  ;; addr 16: plain payload / addr 20: atomic flag / addr 24: agent's answer flag
  (func (export "wasi_thread_start") (param $tid i32) (param $arg i32)
    ;; spin until the flag publishes
    (block $done
      (loop $spin
        (br_if $done (i32.eq (i32.atomic.load (i32.const 20)) (i32.const 1)))
        (br $spin)))
    ;; read the PLAIN store and publish the answer atomically
    (i32.atomic.store (i32.const 24) (i32.load (i32.const 16))))
  (func (export "run") (result i32)
    (drop (call $spawn (i32.const 0)))
    ;; plain store, then release-publish
    (i32.store (i32.const 16) (i32.const 4242))
    (i32.atomic.store (i32.const 20) (i32.const 1))
    ;; wait for the agent's answer
    (block $got
      (loop $wait
        (br_if $got (i32.ne (i32.atomic.load (i32.const 24)) (i32.const 0)))
        (br $wait)))
    (i32.atomic.load (i32.const 24))))
