//go:build darwin || linux

package codegen

import (
	"syscall"
	"testing"
	"time"
)

// An instance that has been sent SIGKILL is on its way to its end: until
// its guest has taken the signal none of its calls blocks, however many it
// makes, and it starts no command. The embedder that killed it can end its
// commands and close its descriptors while the guest is still running.

// killedInstance forks an instance of w with a registered guest and posts
// SIGKILL to it.
func killedInstance(t *testing.T, w *WasiStubs) (*WasiStubs, *Module) {
	t.Helper()
	instances, modules := sharedWaiters(t, w, 1)
	instances[0].PostSignal(wasiSIGKILL)
	return instances[0], modules[0]
}

func TestKill_NoCallBlocksWhileSIGKILLIsPending(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, _ := newTestPipe(t, w, m)
	child, cm := killedInstance(t, w)
	// More than one call: the first one is interrupted by any signal.
	for round := 0; round < 3; round++ {
		result := make(chan int32, 1)
		go func() {
			_, rc := fdReadString(child, cm, readFd, 16)
			result <- rc
		}()
		select {
		case rc := <-result:
			if rc != _wasiEINTR {
				t.Fatalf("read %d of a killed process rc=%d, want EINTR", round, rc)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("read %d of a killed process blocks", round)
		}
	}
	// Once the guest has the signal the host holds nothing back.
	takeSignals(t, child, cm)
	result := make(chan int32, 1)
	go func() {
		_, rc := fdReadString(child, cm, readFd, 16)
		result <- rc
	}()
	select {
	case rc := <-result:
		t.Fatalf("a read with no input returned %d after the signal was taken", rc)
	case <-time.After(100 * time.Millisecond):
	}
	child.PostSignal(wasiSIGTERM)
	<-result
}

func TestKill_AKilledProcessStartsNoCommand(t *testing.T) {
	w, _ := newProcTestStubs(t)
	child, cm := killedInstance(t, w)
	pathOff := writeCStr(cm, 1000, "/bin/sh")
	argvOff := writeArgv(cm, 2000, 3000, []string{"/bin/sh", "-c", "exit 0"})
	if rc := child.Proc_spawn(cm, pathOff, argvOff, 0, -1, -1, -1, 0, 4000); rc != -_wasiEINTR {
		t.Fatalf("Proc_spawn of a killed process rc=%d, want -EINTR", rc)
	}
}

func TestKill_KillCommandsEndsAndReapsTheCommands(t *testing.T) {
	w, _ := newProcTestStubs(t)
	// The commands have no stream the runtime copies.
	w.stdin, w.stdout, w.stderr = nil, nil, nil
	child, cm := sharedWaiters(t, w, 1)
	running := spawnTestCommand(t, child[0], cm[0], "/bin/sh", "-c", "exec sleep 600")
	ended := spawnTestCommand(t, child[0], cm[0], "/bin/sh", "-c", "exit 3")
	child[0].mu.Lock()
	hostPID := child[0].procs[running].cmd.Process.Pid
	hasEnded := child[0].procs[ended].done
	child[0].mu.Unlock()
	select {
	case <-hasEnded:
	case <-time.After(10 * time.Second):
		t.Fatal("the short command does not end")
	}

	done := make(chan struct{})
	go func() {
		child[0].KillCommands()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("KillCommands does not return")
	}
	// The host has no such process any more, not even a zombie.
	if err := syscall.Kill(hostPID, 0); err != syscall.ESRCH {
		t.Fatalf("the command is still a process of the host after KillCommands: kill(pid, 0) = %v", err)
	}
	// The instance can still wait for both.
	const statusOff int32 = 7000
	if rc := child[0].Proc_wait(cm[0], running, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait of the killed command rc=%d", rc)
	}
	if status := int32(readU32(cm[0].memory, int(statusOff))); status != wasiSIGKILL {
		t.Fatalf("status of the killed command = %#x, want death by SIGKILL", status)
	}
	if rc := child[0].Proc_wait(cm[0], ended, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait of the command that had ended rc=%d", rc)
	}
	if status := int32(readU32(cm[0].memory, int(statusOff))); status != 3<<8 {
		t.Fatalf("status of the command that had ended = %#x, want exit 3", status)
	}
}

// A command whose output the runtime copies has not ended, for the guest,
// while a process it left behind holds that output open. KillCommands does
// not wait for that: the command is dead and off the host's process table
// soon after.
func TestKill_KillCommandsDoesNotWaitForCopiedStreams(t *testing.T) {
	w, _ := newProcTestStubs(t)
	child, cm := sharedWaiters(t, w, 1)
	pid := spawnTestCommand(t, child[0], cm[0], "/bin/sh", "-c", "sleep 3 & exec sleep 600")
	child[0].mu.Lock()
	hostPID := child[0].procs[pid].cmd.Process.Pid
	child[0].mu.Unlock()
	start := time.Now()
	child[0].KillCommands()
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("KillCommands took %v: it waited for the command's output to end", took)
	}
	deadline := time.Now().Add(10 * time.Second)
	for syscall.Kill(hostPID, 0) != syscall.ESRCH {
		if time.Now().After(deadline) {
			t.Fatal("the killed command is still a process of the host")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestKill_CloseDescriptorsLeavesTheSignalsInPlace(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	child, cm := killedInstance(t, w)
	if err := child.CloseDescriptors(); err != nil {
		t.Fatalf("CloseDescriptors: %v", err)
	}
	if _, rc := fdReadString(child, cm, readFd, 16); rc != _wasiEBADF {
		t.Fatalf("read of a closed descriptor rc=%d, want EBADF", rc)
	}
	// The parent's descriptors are its own.
	if rc := fdWriteString(w, m, writeFd, "x"); rc != _wasiESUCCESS {
		t.Fatalf("the parent's write rc=%d", rc)
	}
	// The signal is still the guest's to take.
	if mask := takeSignals(t, child, cm); mask&signalMask(wasiSIGKILL) == 0 {
		t.Fatalf("taken signals = %#x: SIGKILL is gone", mask)
	}
}
