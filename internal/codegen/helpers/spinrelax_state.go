package helpers

// spinRelaxColdCalls mirrors the declaration in the wasip1_native.go
// runtime template so this package compiles (and its tests run) on its
// own. Only helpers.go is embedded and extracted into generated
// output; there the generated base package supplies the counter from
// the template, so the two declarations never meet.
var spinRelaxColdCalls uint32

// spinAgents mirrors the runtime template's live spawned-agent gauge
// (threadLaunch maintains it, spinRelax reads it), for the same reason.
var spinAgents int32

// spinOversubscribed mirrors the template's flag derived from spinAgents.
var spinOversubscribed uint32
