package main

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/emulator"
)

var cmdMemory = Command{
	Name:    "memory",
	Aliases: []string{"mem"},
	Summary: "Show the contents of memory",
	Exec:    listMemoryExec,
}

func listMemoryExec(args []string) {
	auxMem := make([]emulator.Memory, 0)

	for _, r := range []emulator.RegisterValue{
		vm.Registers.R0,
		vm.Registers.R1,
		vm.Registers.R2,
		vm.Registers.R3,
		vm.Registers.R4,
		vm.Registers.R5,
		vm.Registers.R6,
		vm.Registers.R7,
		vm.Registers.R8,
		vm.Registers.R9,
	} {
		ptr, ok := r.(*emulator.MemoryPtr)
		if !ok {
			continue
		}

		exists := false
		for _, m := range auxMem {
			if m == ptr.Memory {
				exists = true
				break
			}
		}
		if !exists {
			auxMem = append(auxMem, ptr.Memory)
		}
	}

	loopValueMem := func(valMem *emulator.ValueMemory, print func(val emulator.RegisterValue, index, size int)) {
		var lastVal emulator.RegisterValue
		for i, val := range valMem.Mapping {
			if val == lastVal || val == nil {
				continue
			}

			switch val := val.(type) {
			case *emulator.MemoryPtr:
				exists := false
				for _, m := range auxMem {
					if m == val.Memory {
						exists = true
						break
					}
				}
				if !exists {
					auxMem = append(auxMem, val.Memory)
				}
			}

			size := 0
			for j := i; j < len(valMem.Mapping); j++ {
				if valMem.Mapping[j] == val {
					size++
					continue
				}
				break
			}

			print(val, i, size)
			lastVal = val
		}
	}

	for sf, valMem := range vm.StackFrames {
		first := true
		loopValueMem(&vm.StackFrames[sf], func(val emulator.RegisterValue, i, size int) {
			if first {
				fmt.Printf("fp%d:\n", sf)
				first = false
			}
			fmt.Printf(
				"%s %s = %s\n",
				blue(fmt.Sprintf(
					"fp%d-%-3d",
					sf,
					len(valMem.Mapping)-i,
				)),
				green(fmt.Sprintf("(u%d)", size*8)),
				yellow(val.String()),
			)
		})
		if !first {
			fmt.Println()
		}
	}

	for i := 0; i < len(auxMem); i++ {
		mem := auxMem[i]

		switch mem := mem.(type) {
		case *emulator.ValueMemory:
			first := true

			loopValueMem(mem, func(val emulator.RegisterValue, index, size int) {
				if first {
					fmt.Printf("%s:\n", mem.Name())
					first = false
				}
				fmt.Printf(
					"%s %s = %s\n",
					blue(fmt.Sprintf(
						"%s%+d",
						mem.Name(),
						index,
					)),
					green(fmt.Sprintf("(u%d)", size*8)),
					yellow(val.String()),
				)
			})
			if !first {
				fmt.Println()
			}

		case *emulator.ByteMemory:
			fmt.Printf("%s:\n", mem.Name())
			fmt.Print(blue("0000 "))
			for j := 0; j < mem.Size(); j++ {
				fmt.Printf("%02X ", mem.Backing[j])
				if j%16 == 15 {
					fmt.Printf("\n%s ", blue(fmt.Sprintf("%04X", j+1)))
				} else if j%8 == 7 {
					fmt.Print(" ")
				}
			}
			fmt.Print("\n\n")
		}
	}
}
