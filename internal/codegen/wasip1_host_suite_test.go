//go:build darwin || linux

package codegen

import "testing"

// What a guest sees of pipes, sockets, files, readiness, signals and
// commands does not depend on whose descriptors it has: the tests of that
// behaviour, written for a guest with descriptors of its own, hold as they
// are for a guest whose descriptors are the host process's. They are run
// again here on such a guest (newTestStubs makes one while hostSuite is
// set).
//
// Left out are the tests of what differs by design — which number a new
// descriptor gets, that a duplicate is another descriptor of the host, that
// closing a standard descriptor closes the process's, where the root
// directory has its number, and the tests that look inside the entries of
// the table — those of an in-memory filesystem, whose files are not
// descriptors of the host in any guest, and those that pin down an answer
// the host gives its own way (TestHostDescriptors_SocketsAnswerAsTheHost
// has these): what poll says of a socket that is neither connected nor
// listening, and the error of a datagram sent without a destination.
func TestHostDescriptors_BehaviourOfAGuestWithItsOwnDescriptorsHolds(t *testing.T) {
	hostSuite = true
	defer func() { hostSuite = false }()
	for _, tc := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"SocketFamily_UnixStream", TestSocketFamily_UnixStream},
		{"SocketFamily_UnixDatagram", TestSocketFamily_UnixDatagram},
		{"SocketFamily_Pairs", TestSocketFamily_Pairs},
		{"SocketFamily_IPv6", TestSocketFamily_IPv6},
		{"SocketFamily_NonBlockingConnect", TestSocketFamily_NonBlockingConnect},
		{"SocketFamily_BlockingConnectIsInterruptible", TestSocketFamily_BlockingConnectIsInterruptible},
		{"SocketFamily_Policies", TestSocketFamily_Policies},
		{"Socket_ServerAndClientInOneInstance", TestSocket_ServerAndClientInOneInstance},
		{"Socket_ListenWithoutBindPicksAPort", TestSocket_ListenWithoutBindPicksAPort},
		{"Socket_ListeningIsSubjectToTheNetworkPolicy", TestSocket_ListeningIsSubjectToTheNetworkPolicy},
		{"Socket_PollReportsAListenerOnlyWithAConnectionWaiting", TestSocket_PollReportsAListenerOnlyWithAConnectionWaiting},
		{"Socket_NonBlockingAcceptAndRead", TestSocket_NonBlockingAcceptAndRead},
		{"Socket_SignalInterruptsAccept", TestSocket_SignalInterruptsAccept},
		{"Socket_ForkedInstanceAcceptsOnTheSharedListener", TestSocket_ForkedInstanceAcceptsOnTheSharedListener},
		{"Socket_BoundSocketConnectsFromItsAddress", TestSocket_BoundSocketConnectsFromItsAddress},
		{"Socket_Options", TestSocket_Options},
		{"Socket_Pair", TestSocket_Pair},
		{"Socket_PeerNameUntilTheConnectionIsOver", TestSocket_PeerNameUntilTheConnectionIsOver},
		{"Socket_AcceptingOption", TestSocket_AcceptingOption},
		{"Socket_Timeouts", TestSocket_Timeouts},
		{"Socket_NonBlockingSendTakesWhatFits", TestSocket_NonBlockingSendTakesWhatFits},
		{"Socket_ReceiveFlags", TestSocket_ReceiveFlags},
		{"Socket_SendFlags", TestSocket_SendFlags},
		{"Socket_EveryProcessBlockedInAcceptTakesItsSignal", TestSocket_EveryProcessBlockedInAcceptTakesItsSignal},
		{"Datagram_SendToAndReceiveFrom", TestDatagram_SendToAndReceiveFrom},
		{"Datagram_ReadinessNonBlockingAndSignals", TestDatagram_ReadinessNonBlockingAndSignals},
		{"Datagram_IsSubjectToTheNetworkPolicy", TestDatagram_IsSubjectToTheNetworkPolicy},
		{"Datagram_PeekLeavesTheDatagram", TestDatagram_PeekLeavesTheDatagram},
		{"Wasi_PollEmptyPipeWaitsForTimeout", TestWasi_PollEmptyPipeWaitsForTimeout},
		{"Wasi_PollPipeWithInput", TestWasi_PollPipeWithInput},
		{"Wasi_PollBlocksUntilInput", TestWasi_PollBlocksUntilInput},
		{"Wasi_PollPipeAtEndOfInput", TestWasi_PollPipeAtEndOfInput},
		{"Wasi_PollRegularFileBesideIdlePipe", TestWasi_PollRegularFileBesideIdlePipe},
		{"Wasi_PollFdSubscriptionsPreemptTimeout", TestWasi_PollFdSubscriptionsPreemptTimeout},
		{"Wasi_PollTimesOutBesideABlockedWriter", TestWasi_PollTimesOutBesideABlockedWriter},
		{"Wasi_PollTimesOutBesideABlockedReader", TestWasi_PollTimesOutBesideABlockedReader},
		{"Wasi_PipeEndsHaveOneDirection", TestWasi_PipeEndsHaveOneDirection},
		{"Wasi_FilesHaveTheAccessTheyWereOpenedWith", TestWasi_FilesHaveTheAccessTheyWereOpenedWith},
		{"Wasi_PipeIsWritableOnlyWhileItHasRoom", TestWasi_PipeIsWritableOnlyWhileItHasRoom},
		{"Wasi_BlockingWriteWaitsForRoomAndIsEndedByASignal", TestWasi_BlockingWriteWaitsForRoomAndIsEndedByASignal},
		{"Wasi_WriteToAClosedPipeIsEPIPEAndPostsSIGPIPE", TestWasi_WriteToAClosedPipeIsEPIPEAndPostsSIGPIPE},
		{"Wasi_WriteReportsItsFailure", TestWasi_WriteReportsItsFailure},
		{"Signal_EveryProcessBlockedWritingOnePipeTakesItsSignal", TestSignal_EveryProcessBlockedWritingOnePipeTakesItsSignal},
		{"Signal_EveryProcessBlockedReadingOnePipeTakesItsSignal", TestSignal_EveryProcessBlockedReadingOnePipeTakesItsSignal},
		{"Signal_EveryProcessPollingOnePipeTakesItsSignal", TestSignal_EveryProcessPollingOnePipeTakesItsSignal},
		{"Signal_InterruptsSleep", TestSignal_InterruptsSleep},
		{"Signal_PendingSignalEndsTheNextBlockingCallAtOnce", TestSignal_PendingSignalEndsTheNextBlockingCallAtOnce},
		{"Signal_InterruptsPollOnAnIdlePipe", TestSignal_InterruptsPollOnAnIdlePipe},
		{"Signal_InterruptsBlockingPipeRead", TestSignal_InterruptsBlockingPipeRead},
		{"Signal_PendingSignalLeavesACallThatNeedNotWaitAlone", TestSignal_PendingSignalLeavesACallThatNeedNotWaitAlone},
		{"Signal_NeverInterruptsRegularFileRead", TestSignal_NeverInterruptsRegularFileRead},
		{"Signal_InterruptsWaitForAProcess", TestSignal_InterruptsWaitForAProcess},
		{"Signal_ChildEndPostsSIGCHLD", TestSignal_ChildEndPostsSIGCHLD},
		{"Signal_InterruptsWaitingFlock", TestSignal_InterruptsWaitingFlock},
		{"Signal_CloseAllEndsDelivery", TestSignal_CloseAllEndsDelivery},
		{"Kill_NoCallBlocksWhileSIGKILLIsPending", TestKill_NoCallBlocksWhileSIGKILLIsPending},
		{"Kill_AKilledProcessStartsNoCommand", TestKill_AKilledProcessStartsNoCommand},
		{"Kill_KillCommandsEndsAndReapsTheCommands", TestKill_KillCommandsEndsAndReapsTheCommands},
		{"Kill_CloseDescriptorsLeavesTheSignalsInPlace", TestKill_CloseDescriptorsLeavesTheSignalsInPlace},
		{"Wasi_FilestatReportsLinksAndIdentity", TestWasi_FilestatReportsLinksAndIdentity},
		{"Wasi_FilestatReportsAccessAndChangeTimes", TestWasi_FilestatReportsAccessAndChangeTimes},
		{"Wasi_FilestatExtReportsModeAndOwner", TestWasi_FilestatExtReportsModeAndOwner},
		{"Wasi_ChmodByPathAndDescriptor", TestWasi_ChmodByPathAndDescriptor},
		{"Wasi_CreationModeAppliesUmask", TestWasi_CreationModeAppliesUmask},
		{"Wasi_CreateThroughDanglingSymlinkUnderLooseUmask", TestWasi_CreateThroughDanglingSymlinkUnderLooseUmask},
		{"Wasi_FlockExcludesOtherOpens", TestWasi_FlockExcludesOtherOpens},
		{"Wasi_FlockIsVisibleToOtherProcesses", TestWasi_FlockIsVisibleToOtherProcesses},
		{"Wasi_FileTypes", TestWasi_FileTypes},
		{"FilestatExtBlocksAndDevice", TestFilestatExtBlocksAndDevice},
		{"Wasi_PathChmodAndFilestatMode", TestWasi_PathChmodAndFilestatMode},
		{"Wasi_ProcSpawnWait", TestWasi_ProcSpawnWait},
		{"Wasi_ProcSpawnExitCode", TestWasi_ProcSpawnExitCode},
		{"Wasi_ProcSpawnNotFound", TestWasi_ProcSpawnNotFound},
		{"Wasi_ProcWaitWNOHANG", TestWasi_ProcWaitWNOHANG},
		{"Wasi_PipeCapture", TestWasi_PipeCapture},
		{"Wasi_ForkSharesFileOffset", TestWasi_ForkSharesFileOffset},
		{"Wasi_ProcKillSpawned", TestWasi_ProcKillSpawned},
	} {
		t.Run(tc.name, tc.run)
	}
}
