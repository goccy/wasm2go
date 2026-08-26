package helpers

// spinRelaxColdCalls mirrors the declaration in the wasip1_native.go
// runtime template so this package compiles (and its tests run) on its
// own. Only helpers.go is embedded and extracted into generated
// output; there the generated base package supplies the counter from
// the template, so the two declarations never meet.
var spinRelaxColdCalls uint32
