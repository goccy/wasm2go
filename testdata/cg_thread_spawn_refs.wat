;; cg_thread_spawn_refs.wat — the wasi-threads thread-spawn import is
;; exported and sits in an element segment, reached through call_indirect.
;; Each spawned agent bumps the counter at its start_arg.
(module
  (import "wasi" "thread-spawn" (func $thread_spawn (param i32) (result i32)))
  (memory (export "memory") 1 2 shared)

  (type $spawn (func (param i32) (result i32)))
  (table 1 funcref)
  (elem (i32.const 0) $thread_spawn)

  (export "spawn" (func $thread_spawn))

  (func (export "wasi_thread_start") (param $tid i32) (param $arg i32)
    (drop (i32.atomic.rmw.add (local.get $arg) (i32.const 1))))

  ;; calls slot 0 of the table, which holds the import
  (func (export "spawnViaTable") (param i32) (result i32)
    (call_indirect (type $spawn) (local.get 0) (i32.const 0)))

  (func (export "count") (result i32)
    (i32.atomic.load (i32.const 64)))
)
