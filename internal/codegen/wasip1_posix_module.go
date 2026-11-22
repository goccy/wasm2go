package codegen

import (
	"fmt"

	"github.com/goccy/wasm2go/internal/wasm"
)

// The host imports of wasm2go's wasi runtime come in two modules:
//
//   - wasi_snapshot_preview1, WASI's own functions;
//   - wasip1_posix_extension, the POSIX functions WASI preview1 does not have: the
//     ones of posixImports, served by WasiStubs.
//
// One WasiStubs answers both: the two share the instance's descriptors,
// processes and signals. So a module that imports from wasip1_posix_extension gets no
// interface or constructor parameter of its own for it: its imports become
// methods of the wasi_snapshot_preview1 interface, which NewWASI — or the
// embedder's implementation passed to NewWithWASI — provides.
const (
	wasiModule  = "wasi_snapshot_preview1"
	posixModule = "wasip1_posix_extension"
)

// posixImports are the imports of wasip1_posix_extension. A memory64 module
// binds each to its *64 method, as it does wasi_snapshot_preview1's.
var posixImports = map[string]bool{
	"clock_zone":                 true,
	"fd_chmod":                   true,
	"fd_chown":                   true,
	"fd_cloexec":                 true,
	"fd_closefrom":               true,
	"fd_dup":                     true,
	"fd_dup2":                    true,
	"fd_dupfd":                   true,
	"fd_filestat_ext":            true,
	"fd_flock":                   true,
	"fd_ioctl":                   true,
	"fd_lock":                    true,
	"fd_path":                    true,
	"host_number_at":             true,
	"host_numbering":             true,
	"path_access":                true,
	"path_chmod":                 true,
	"path_chown":                 true,
	"path_create_directory_mode": true,
	"path_filestat_ext":          true,
	"path_mkfifo":                true,
	"path_open_mode":             true,
	"pipe":                       true,
	"proc_group_at":              true,
	"proc_group_by_id":           true,
	"proc_group_by_name":         true,
	"proc_groups":                true,
	"proc_ids":                   true,
	"proc_itimer":                true,
	"proc_kill":                  true,
	"proc_priority":              true,
	"proc_setgroups":             true,
	"proc_setids":                true,
	"proc_signal_dispositions":   true,
	"proc_signal_register":       true,
	"proc_signal_take":           true,
	"proc_spawn":                 true,
	"proc_syslog":                true,
	"proc_syslog_close":          true,
	"proc_syslog_open":           true,
	"proc_terminate":             true,
	"proc_times":                 true,
	"proc_umask":                 true,
	"proc_uname":                 true,
	"proc_user_at":               true,
	"proc_user_by_id":            true,
	"proc_user_by_name":          true,
	"proc_wait":                  true,
	"proc_wait_any":              true,
	"sock_bind_addr":             true,
	"sock_connect_addr":          true,
	"sock_listen":                true,
	"sock_name":                  true,
	"sock_open":                  true,
	"sock_host_by_name":          true,
	"sock_recvfrom_addr":         true,
	"sock_resolve":               true,
	"sock_reverse_addr":          true,
	"sock_sendto_addr":           true,
	"sock_service":               true,
	"sock_getopt":                true,
	"sock_setopt":                true,
	"sock_socketpair":            true,
	"sock_timeout":               true,

	"proc_chdir":  true,
	"proc_setenv": true,

	"ipc_ctl":    true,
	"ipc_get":    true,
	"ipc_msgrcv": true,
	"ipc_msgsnd": true,
	"ipc_semop":  true,
	"ipc_shmat":  true,
	"ipc_shmdt":  true,
}

// wasiReleasedPosixImports are the imports of wasip1_posix_extension that
// are served under wasi_snapshot_preview1 as well. Every other import of
// wasip1_posix_extension is served under wasip1_posix_extension only.
var wasiReleasedPosixImports = map[string]bool{
	"fd_dup":     true,
	"fd_dup2":    true,
	"path_chmod": true,
	"pipe":       true,
	"proc_spawn": true,
	"proc_wait":  true,
}

// servingModule returns the import module whose implementation answers an
// import of mod: wasi_snapshot_preview1's for wasip1_posix_extension (see above), the
// module itself for any other.
func servingModule(mod string) string {
	if mod == posixModule {
		return wasiModule
	}
	return mod
}

// servedByWASI reports whether an import of mod is answered by the wasi
// runtime: one of wasi_snapshot_preview1 or of wasip1_posix_extension.
func servedByWASI(mod string) bool { return servingModule(mod) == wasiModule }

// importModuleError reports a function import the wasi runtime does not
// serve under the module it names: a name wasip1_posix_extension does not have,
// or an import of wasip1_posix_extension named under wasi_snapshot_preview1
// (other than the ones of wasiReleasedPosixImports).
func importModuleError(imp wasm.Import) error {
	if imp.Kind != wasm.ImportFunc {
		return nil
	}
	switch imp.Module {
	case posixModule:
		if !posixImports[imp.Name] {
			return fmt.Errorf("import %s.%s: %s has no function %q", imp.Module, imp.Name, posixModule, imp.Name)
		}
	case wasiModule:
		if posixImports[imp.Name] && !wasiReleasedPosixImports[imp.Name] {
			return fmt.Errorf("import %s.%s: %q is a function of %s, not of %s", imp.Module, imp.Name, imp.Name, posixModule, wasiModule)
		}
	}
	return nil
}
