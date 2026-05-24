package codegen

import _ "embed"

//go:embed helpers/helpers.go
var helpersSrcBytes string

func init() {
	helpersSrc = helpersSrcBytes
}
