;; wasip1_mem64_imports.wat — a memory64 module that imports every name
;; WasiStubs binds for a memory64 guest, each with its wasm64 signature:
;; every argument of a standard import widened to i64 (as the wasm2go port
;; of wasi-libc declares them; proc_raise, which that C library no longer
;; declares, the same way). Its translation must compile against the *64
;; bindings of WasiStubs. touch calls every import once so none of them can
;; be dropped as unused; nothing runs it.
(module
  (import "wasi_snapshot_preview1" "args_get"
    (func $args_get (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "args_sizes_get"
    (func $args_sizes_get (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "environ_get"
    (func $environ_get (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "environ_sizes_get"
    (func $environ_sizes_get (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "clock_res_get"
    (func $clock_res_get (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "clock_time_get"
    (func $clock_time_get (param i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close"
    (func $fd_close (param i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_fdstat_get"
    (func $fd_fdstat_get (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_fdstat_set_flags"
    (func $fd_fdstat_set_flags (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_filestat_get"
    (func $fd_filestat_get (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_filestat_set_size"
    (func $fd_filestat_set_size (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_filestat_set_times"
    (func $fd_filestat_set_times (param i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_prestat_get"
    (func $fd_prestat_get (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_prestat_dir_name"
    (func $fd_prestat_dir_name (param i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_readdir"
    (func $fd_readdir (param i64 i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_renumber"
    (func $fd_renumber (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_seek"
    (func $fd_seek (param i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_sync"
    (func $fd_sync (param i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_tell"
    (func $fd_tell (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_filestat_get"
    (func $path_filestat_get (param i64 i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_filestat_set_times"
    (func $path_filestat_set_times (param i64 i64 i64 i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_link"
    (func $path_link (param i64 i64 i64 i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i64 i64 i64 i64 i64 i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_readlink"
    (func $path_readlink (param i64 i64 i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_remove_directory"
    (func $path_remove_directory (param i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_rename"
    (func $path_rename (param i64 i64 i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_symlink"
    (func $path_symlink (param i64 i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_unlink_file"
    (func $path_unlink_file (param i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i64)))
  (import "wasi_snapshot_preview1" "random_get"
    (func $random_get (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sched_yield"
    (func $sched_yield (result i32)))
  (import "wasi_snapshot_preview1" "fd_advise"
    (func $fd_advise (param i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_allocate"
    (func $fd_allocate (param i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_datasync"
    (func $fd_datasync (param i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_fdstat_set_rights"
    (func $fd_fdstat_set_rights (param i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_pread"
    (func $fd_pread (param i64 i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_pwrite"
    (func $fd_pwrite (param i64 i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_create_directory"
    (func $path_create_directory (param i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_raise"
    (func $proc_raise (param i64) (result i32)))


  (memory (export "memory") i64 1)

  (func (export "touch")
    (drop (call $args_get (i64.const 0) (i64.const 0)))
    (drop (call $args_sizes_get (i64.const 0) (i64.const 0)))
    (drop (call $environ_get (i64.const 0) (i64.const 0)))
    (drop (call $environ_sizes_get (i64.const 0) (i64.const 0)))
    (drop (call $clock_res_get (i64.const 0) (i64.const 0)))
    (drop (call $clock_time_get (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_close (i64.const 0)))
    (drop (call $fd_fdstat_get (i64.const 0) (i64.const 0)))
    (drop (call $fd_fdstat_set_flags (i64.const 0) (i64.const 0)))
    (drop (call $fd_filestat_get (i64.const 0) (i64.const 0)))
    (drop (call $fd_filestat_set_size (i64.const 0) (i64.const 0)))
    (drop (call $fd_filestat_set_times (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_prestat_get (i64.const 0) (i64.const 0)))
    (drop (call $fd_prestat_dir_name (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_read (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_readdir (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_renumber (i64.const 0) (i64.const 0)))
    (drop (call $fd_seek (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_sync (i64.const 0)))
    (drop (call $fd_tell (i64.const 0) (i64.const 0)))
    (drop (call $fd_write (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $path_filestat_get (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $path_filestat_set_times (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $path_link (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $path_open (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $path_readlink (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $path_remove_directory (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $path_rename (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $path_symlink (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $path_unlink_file (i64.const 0) (i64.const 0) (i64.const 0)))
    (call $proc_exit (i64.const 0))
    (drop (call $random_get (i64.const 0) (i64.const 0)))
    (drop (call $sched_yield))
    (drop (call $fd_advise (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_allocate (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_datasync (i64.const 0)))
    (drop (call $fd_fdstat_set_rights (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_pread (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_pwrite (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $path_create_directory (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $proc_raise (i64.const 0)))
  )
)
