;; wasip1_mem64_imports.wat — a memory64 module that imports every
;; wasi_snapshot_preview1 name WasiStubs binds (all the Perl interpreter
;; uses, and the rest: fd_pread, the legacy sock_* imports, ...), each with
;; its wasm64 signature: every argument of a standard import widened to i64
;; (as the wasm2go port of wasi-libc declares them; proc_raise, which that
;; C library no longer declares, the same way), and for a non-standard one
;; an i64 for every pointer, long and size_t and an i32 for every int and
;; unsigned of its C declaration. Its translation must compile against the
;; *64 bindings of WasiStubs. touch calls every import once so none of them
;; can be dropped as unused; nothing runs it.
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
  (import "wasi_snapshot_preview1" "poll_oneoff"
    (func $poll_oneoff (param i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i64)))
  (import "wasi_snapshot_preview1" "random_get"
    (func $random_get (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sched_yield"
    (func $sched_yield (result i32)))
  (import "wasi_snapshot_preview1" "sock_accept"
    (func $sock_accept (param i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_shutdown"
    (func $sock_shutdown (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_spawn"
    (func $proc_spawn (param i64 i64 i64 i32 i32 i32 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_wait"
    (func $proc_wait (param i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_wait_any"
    (func $proc_wait_any (param i32 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "pipe"
    (func $pipe (param i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_dup"
    (func $fd_dup (param i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_dupfd"
    (func $fd_dupfd (param i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_lock"
    (func $fd_lock (param i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_dup2"
    (func $fd_dup2 (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_cloexec"
    (func $fd_cloexec (param i32 i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_open"
    (func $sock_open (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "sock_connect_addr"
    (func $sock_connect_addr (param i32 i64 i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "sock_bind_addr"
    (func $sock_bind_addr (param i32 i64 i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "sock_resolve"
    (func $sock_resolve (param i64 i32 i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_host_by_name"
    (func $sock_host_by_name (param i64 i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_reverse_addr"
    (func $sock_reverse_addr (param i64 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_service"
    (func $sock_service (param i64 i32 i32 i32 i64 i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_listen"
    (func $sock_listen (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "sock_name"
    (func $sock_name (param i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_addr_to_host"
    (func $sock_addr_to_host (param i64 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_addr_from_host"
    (func $sock_addr_from_host (param i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_sendto_addr"
    (func $sock_sendto_addr (param i32 i64 i32 i32 i64 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_recvfrom_addr"
    (func $sock_recvfrom_addr (param i32 i64 i32 i32 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_timeout"
    (func $sock_timeout (param i32 i32 i32 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_setopt"
    (func $sock_setopt (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "sock_getopt"
    (func $sock_getopt (param i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_socketpair"
    (func $sock_socketpair (param i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_chmod"
    (func $path_chmod (param i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_chmod"
    (func $fd_chmod (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_access"
    (func $path_access (param i64 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_filestat_ext"
    (func $path_filestat_ext (param i64 i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_filestat_ext"
    (func $fd_filestat_ext (param i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_umask"
    (func $proc_umask (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open_mode"
    (func $path_open_mode (param i32 i64 i32 i32 i64 i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_create_directory_mode"
    (func $path_create_directory_mode (param i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_chdir"
    (func $proc_chdir (param i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_flock"
    (func $fd_flock (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "host_numbering"
    (func $host_numbering (result i32)))
  (import "wasi_snapshot_preview1" "host_number_at"
    (func $host_number_at (param i32 i32 i64 i32 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "fd_ioctl"
    (func $fd_ioctl (param i32 i32 i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_ids"
    (func $proc_ids (param i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_groups"
    (func $proc_groups (param i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_user_by_id"
    (func $proc_user_by_id (param i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_user_at"
    (func $proc_user_at (param i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_group_at"
    (func $proc_group_at (param i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_user_by_name"
    (func $proc_user_by_name (param i64 i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_group_by_id"
    (func $proc_group_by_id (param i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_group_by_name"
    (func $proc_group_by_name (param i64 i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_setids"
    (func $proc_setids (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_setgroups"
    (func $proc_setgroups (param i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_path"
    (func $fd_path (param i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_chown"
    (func $path_chown (param i64 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_chown"
    (func $fd_chown (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_mkfifo"
    (func $path_mkfifo (param i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_getpgid"
    (func $proc_getpgid (param i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_setpgid"
    (func $proc_setpgid (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_setsid"
    (func $proc_setsid (param i64) (result i32)))
  (import "wasi_snapshot_preview1" "tty_getattr"
    (func $tty_getattr (param i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "tty_setattr"
    (func $tty_setattr (param i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "tty_speed"
    (func $tty_speed (param i64 i32 i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "tty_control"
    (func $tty_control (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "tty_pgrp"
    (func $tty_pgrp (param i32 i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "tty_name"
    (func $tty_name (param i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_priority"
    (func $proc_priority (param i32 i32 i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_uname"
    (func $proc_uname (param i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_setenv"
    (func $proc_setenv (param i64 i32 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "clock_zone"
    (func $clock_zone (param i64 i32 i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_syslog_open"
    (func $proc_syslog_open (param i64 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_syslog"
    (func $proc_syslog (param i32 i32 i32 i64 i32 i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_syslog_close"
    (func $proc_syslog_close (result i32)))
  (import "wasi_snapshot_preview1" "proc_signal_register"
    (func $proc_signal_register (param i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_signal_dispositions"
    (func $proc_signal_dispositions (param i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_signal_take"
    (func $proc_signal_take (param i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_signal_ignored"
    (func $proc_signal_ignored (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_itimer"
    (func $proc_itimer (param i32 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_terminate"
    (func $proc_terminate (param i32)))
  (import "wasi_snapshot_preview1" "proc_fork"
    (func $proc_fork (param i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_kill"
    (func $proc_kill (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_closefrom"
    (func $fd_closefrom (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exec"
    (func $proc_exec (param i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exec_next"
    (func $proc_exec_next (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_times"
    (func $proc_times (param i64) (result i32)))
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
  (import "wasi_snapshot_preview1" "sock_recv"
    (func $sock_recv (param i64 i64 i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_send"
    (func $sock_send (param i64 i64 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "path_filestat_mode"
    (func $path_filestat_mode (param i64 i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_socket"
    (func $sock_socket (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "sock_connect"
    (func $sock_connect (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "sock_bind"
    (func $sock_bind (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "sock_recvfrom"
    (func $sock_recvfrom (param i32 i64 i32 i32 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_sendto"
    (func $sock_sendto (param i32 i64 i32 i32 i32 i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_getsockname"
    (func $sock_getsockname (param i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_getpeername"
    (func $sock_getpeername (param i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_pair"
    (func $sock_pair (param i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_getaddrinfo"
    (func $sock_getaddrinfo (param i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sock_reverse"
    (func $sock_reverse (param i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "sys_syscall"
    (func $sys_syscall (param i64 i64 i32 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "ipc_get"
    (func $ipc_get (param i32 i32 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "ipc_ctl"
    (func $ipc_ctl (param i32 i32 i32 i32 i64 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "ipc_semop"
    (func $ipc_semop (param i32 i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "ipc_msgsnd"
    (func $ipc_msgsnd (param i32 i64 i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "ipc_msgrcv"
    (func $ipc_msgrcv (param i32 i64 i64 i64 i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "ipc_shmcopy"
    (func $ipc_shmcopy (param i32 i64 i64 i64 i32) (result i32)))

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
    (drop (call $poll_oneoff (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (call $proc_exit (i64.const 0))
    (drop (call $random_get (i64.const 0) (i64.const 0)))
    (drop (call $sched_yield))
    (drop (call $sock_accept (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $sock_shutdown (i64.const 0) (i64.const 0)))
    (drop (call $proc_spawn (i64.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $proc_wait (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $proc_wait_any (i32.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $pipe (i64.const 0)))
    (drop (call $fd_dup (i32.const 0) (i64.const 0)))
    (drop (call $fd_dupfd (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $fd_lock (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $fd_dup2 (i32.const 0) (i32.const 0)))
    (drop (call $fd_cloexec (i32.const 0) (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sock_open (i32.const 0) (i32.const 0)))
    (drop (call $sock_connect_addr (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0)))
    (drop (call $sock_bind_addr (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0)))
    (drop (call $sock_resolve (i64.const 0) (i32.const 0) (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sock_host_by_name (i64.const 0) (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sock_reverse_addr (i64.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sock_service (i64.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sock_listen (i32.const 0) (i32.const 0)))
    (drop (call $sock_name (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sock_addr_to_host (i64.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sock_addr_from_host (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sock_sendto_addr (i32.const 0) (i64.const 0) (i32.const 0) (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sock_recvfrom_addr (i32.const 0) (i64.const 0) (i32.const 0) (i32.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $sock_timeout (i32.const 0) (i32.const 0) (i32.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $sock_setopt (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $sock_getopt (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sock_socketpair (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $path_chmod (i64.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $fd_chmod (i32.const 0) (i32.const 0)))
    (drop (call $path_access (i64.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $path_filestat_ext (i64.const 0) (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $fd_filestat_ext (i32.const 0) (i64.const 0)))
    (drop (call $proc_umask (i32.const 0)))
    (drop (call $path_open_mode (i32.const 0) (i64.const 0) (i32.const 0) (i32.const 0) (i64.const 0) (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $path_create_directory_mode (i64.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $proc_chdir (i64.const 0) (i32.const 0)))
    (drop (call $fd_flock (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $host_numbering))
    (drop (call $host_number_at (i32.const 0) (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_ioctl (i32.const 0) (i32.const 0) (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $proc_ids (i64.const 0)))
    (drop (call $proc_groups (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $proc_user_by_id (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $proc_user_at (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $proc_group_at (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $proc_user_by_name (i64.const 0) (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $proc_group_by_id (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $proc_group_by_name (i64.const 0) (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $proc_setids (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $proc_setgroups (i64.const 0) (i32.const 0)))
    (drop (call $fd_path (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $path_chown (i64.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $fd_chown (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $path_mkfifo (i64.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $proc_getpgid (i32.const 0) (i64.const 0)))
    (drop (call $proc_setpgid (i32.const 0) (i32.const 0)))
    (drop (call $proc_setsid (i64.const 0)))
    (drop (call $tty_getattr (i32.const 0) (i64.const 0)))
    (drop (call $tty_setattr (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $tty_speed (i64.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $tty_control (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $tty_pgrp (i32.const 0) (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $tty_name (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $proc_priority (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $proc_uname (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $proc_setenv (i64.const 0) (i32.const 0) (i64.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $clock_zone (i64.const 0) (i32.const 0) (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $proc_syslog_open (i64.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $proc_syslog (i32.const 0) (i32.const 0) (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0) (i32.const 0)))
    (drop (call $proc_syslog_close))
    (drop (call $proc_signal_register (i64.const 0)))
    (drop (call $proc_signal_dispositions (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $proc_signal_take (i64.const 0)))
    (drop (call $proc_signal_ignored (i32.const 0)))
    (drop (call $proc_itimer (i32.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (call $proc_terminate (i32.const 0))
    (drop (call $proc_fork (i64.const 0)))
    (drop (call $proc_kill (i32.const 0) (i32.const 0)))
    (drop (call $fd_closefrom (i32.const 0)))
    (drop (call $proc_exec (i32.const 0) (i64.const 0)))
    (drop (call $proc_exec_next (i32.const 0)))
    (drop (call $proc_times (i64.const 0)))
    (drop (call $fd_advise (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_allocate (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_datasync (i64.const 0)))
    (drop (call $fd_fdstat_set_rights (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_pread (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $fd_pwrite (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $path_create_directory (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $proc_raise (i64.const 0)))
    (drop (call $sock_recv (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $sock_send (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $path_filestat_mode (i64.const 0) (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sock_socket (i32.const 0) (i32.const 0)))
    (drop (call $sock_connect (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $sock_bind (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $sock_recvfrom (i32.const 0) (i64.const 0) (i32.const 0) (i32.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $sock_sendto (i32.const 0) (i64.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sock_getsockname (i32.const 0) (i64.const 0)))
    (drop (call $sock_getpeername (i32.const 0) (i64.const 0)))
    (drop (call $sock_pair (i64.const 0)))
    (drop (call $sock_getaddrinfo (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sock_reverse (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $sys_syscall (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $ipc_get (i32.const 0) (i32.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $ipc_ctl (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $ipc_semop (i32.const 0) (i64.const 0) (i64.const 0)))
    (drop (call $ipc_msgsnd (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0)))
    (drop (call $ipc_msgrcv (i32.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i64.const 0)))
    (drop (call $ipc_shmcopy (i32.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i32.const 0)))
  )
)
