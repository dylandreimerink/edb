package main

import (
	"fmt"
	"os"

	prompt "github.com/c-bata/go-prompt"
	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/emulator"
)

var (
	vm        *emulator.VM
	programs  []gobpfld.BPFProgram
	progName  []string
	progDwarf []*DET
)

func main() {
	var err error
	vm, err = emulator.NewVM(emulator.DefaultVMSettings())
	if err != nil {
		panic(err)
	}

	// Temporary, until we have a generic way to provide a context
	attachCtx()

	fmt.Println("Type 'help' for list of commands.")

	if len(os.Args) > 1 {
		executor("load " + os.Args[1])
	}

	p := prompt.New(
		executor,
		completer,
		prompt.OptionTitle("eBPF debugger"),
		prompt.OptionPrefix("(edb) "),
	)
	p.Run()
}

// Temporary, until we have a generic way to provide a context
func attachCtx() {
	pkt := emulator.ByteMemory{Backing: []byte{
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, // dst mac
		0x7, 0x8, 0x9, 0x10, 0x11, 0x12, // src mac
		0x08, 0x00, // proto = ETH_P_IP
		0x12, 0x23, 0x34, 0x45, // Additional
	}}

	data := &emulator.MemoryPtr{
		Name:   "pkt",
		Memory: &pkt,
		Offset: 0,
	}
	dataEnd := &emulator.MemoryPtr{
		Name:   "pkt",
		Memory: &pkt,
		Offset: int64(pkt.Size()) - 1,
	}

	ctx := &emulator.MemoryPtr{
		Name: "ctx",
		Memory: &emulator.ValueMemory{Mapping: []emulator.RegisterValue{
			data, data, data, data,
			dataEnd, dataEnd, dataEnd, dataEnd,
		}},
	}

	vm.Registers.R1 = ctx
}

// TODOs:
// - Memory modification
// - Breakpoints
// - Dynamic CTX
// - Map inspection
// - Map modification
