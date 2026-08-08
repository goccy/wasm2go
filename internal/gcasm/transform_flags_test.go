package gcasm

import "testing"

func TestWritesFlags(t *testing.T) {
	for _, yes := range []string{
		"ADDQ\t$1, AX", "SUBL\tBX, AX", "CMPQ\tAX, BX", "TESTB\tAL, AL",
		"ANDL\t$3, CX", "ORQ\tAX, BX", "XORL\tAX, AX", "NEGQ\tAX",
		"SHLQ\t$2, AX", "SHRL\t$1, BX", "INCQ\tAX", "DECL\tBX",
	} {
		if !writesFlags(yes) {
			t.Errorf("%q should write flags", yes)
		}
	}
	for _, no := range []string{
		"CMOVQEQ\tAX, BX", "SETEQ\tAL",
		"SARXQ\tCX, AX, BX", "SHRXQ\tCX, AX, BX", "SHLXQ\tCX, AX, BX",
		"MOVQ\tAX, BX", "LEAQ\t8(AX), BX", "JMP\t42",
	} {
		if writesFlags(no) {
			t.Errorf("%q should not write flags", no)
		}
	}
}

func TestReadsFlags(t *testing.T) {
	for _, yes := range []string{
		"JEQ\t42", "JNE\t42", "JLS\t42", "JHI\t42",
		"SETEQ\tAL", "CMOVQNE\tAX, BX", "ADCQ\tAX, BX", "SBBQ\tAX, BX",
	} {
		if !readsFlags(yes) {
			t.Errorf("%q should read flags", yes)
		}
	}
	for _, no := range []string{
		"JMP\t42", "MOVQ\tAX, BX", "ADDQ\t$1, AX",
	} {
		if readsFlags(no) {
			t.Errorf("%q should not read flags", no)
		}
	}
}
