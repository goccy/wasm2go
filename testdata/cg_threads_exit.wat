;; cg_threads_exit.wat — a thread of the guest ends the instance with
;; proc_exit while the main thread runs on. run spawns a thread, which calls
;; proc_exit(7), and then calls fd_write with nothing to write, again and
;; again: the instance's end reaches it there. join spawns the same thread
;; and waits for it the way pthread_join does, on a word of the memory that
;; nothing changes: the instance's end reaches the wait.
(module
  (import "wasi" "thread-spawn" (func $thread_spawn (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1 1 shared)

  (func (export "wasi_thread_start") (param $tid i32) (param $arg i32)
    (call $proc_exit (i32.const 7)))

  (func (export "run")
    (drop (call $thread_spawn (i32.const 0)))
    (loop $write
      (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 64)))
      (br $write)))

  (func (export "join") (result i32)
    (drop (call $thread_spawn (i32.const 0)))
    (memory.atomic.wait32 (i32.const 128) (i32.const 0) (i64.const -1))))
