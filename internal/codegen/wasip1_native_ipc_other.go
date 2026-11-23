//go:build (!linux && !darwin) || 386 || arm || mips || mipsle || mips64 || mips64le || ppc64 || ppc64le || s390x

package codegen

import "errors"

// The System V IPC of HostIPC where the runtime does not reach the host's
// (a system other than Linux and darwin, or an architecture of Linux whose
// structures are not the guest's): every call fails with
// errors.ErrUnsupported.

func (hostIPC) Get(kind IPCKind, key int32, arg uint64, flags int32) (int32, error) {
	return -1, errors.ErrUnsupported
}

func (hostIPC) Control(kind IPCKind, id, num, cmd int32, arg uint64, buf []byte) (int64, error) {
	return -1, errors.ErrUnsupported
}

func (hostIPC) Semop(id int32, ops []byte) error { return errors.ErrUnsupported }

func (hostIPC) Msgsnd(id int32, msg []byte, flags int32) error { return errors.ErrUnsupported }

func (hostIPC) Msgrcv(id int32, msg []byte, typ int64, flags int32) (int, error) {
	return -1, errors.ErrUnsupported
}

func (hostIPC) ShmAttach(id int32, at []byte, flags int32) error { return errors.ErrUnsupported }

func (hostIPC) ShmDetach(at []byte) error { return errors.ErrUnsupported }
