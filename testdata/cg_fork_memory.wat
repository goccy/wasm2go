;; cg_fork_memory.wat — a memory64 guest whose memory a host forks
;; (ForkMemory): it reads, writes, fills and grows its memory, and attaches
;; and detaches System V shared memory segments through
;; wasip1_posix_extension's ipc_shmat and ipc_shmdt.
(module
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i64)))
  (import "wasip1_posix_extension" "ipc_shmat"
    (func $ipc_shmat (param i32 i64 i64 i32) (result i32)))
  (import "wasip1_posix_extension" "ipc_shmdt"
    (func $ipc_shmdt (param i64) (result i32)))

  (memory (export "memory") i64 4)
  (data (i64.const 1024) "fork")

  (func (export "shmat") (param i32 i64 i64 i32) (result i32)
    (call $ipc_shmat (local.get 0) (local.get 1) (local.get 2) (local.get 3)))
  (func (export "shmdt") (param i64) (result i32)
    (call $ipc_shmdt (local.get 0)))
  (func (export "peek") (param i64) (result i32)
    (i32.load8_u (local.get 0)))
  (func (export "poke") (param i64 i32)
    (i32.store8 (local.get 0) (local.get 1)))
  ;; fill(at, value, n)
  (func (export "fill") (param i64 i32 i64)
    (memory.fill (local.get 0) (local.get 1) (local.get 2)))
  (func (export "grow") (param i64) (result i64)
    (memory.grow (local.get 0)))
)
