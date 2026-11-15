package helpers

// The reservation runtime memory.grow consults lives in the generated
// package (the memreserve files of internal/codegen/sharedimage). These
// stand in for it, as a build whose memory is no reservation, so that the
// helpers compile and test on their own; the codegen embeds helpers.go
// alone and never this file.

const memReserved = false

const (
	memReserveGuard = 1<<32 + 1<<16
	memReserveMax   = 1 << 47
)

type memReservation struct{}

func memProtect(mem []byte, from, to uint64, rw bool) error { return nil }

func memOpen(m *Module, accessible, ceiling uint64) ([]byte, error) { return nil, nil }

func memEnter() bool { return false }

func memFaultTrap(m *Module, r any) any { return r }
