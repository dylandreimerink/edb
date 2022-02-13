package debug

import (
	"fmt"

	"github.com/dylandreimerink/mimic"
)

var cmdRegisters = Command{
	Name:    "registers",
	Aliases: []string{"r", "regs"},
	Summary: "Show registers",
	Exec:    registersExec,
}

func registersExec(args []string) {
	fmt.Print("Registers:\n")

	var r mimic.Registers
	if process != nil {
		r = process.Registers
	}

	fmt.Printf("%s = %s", blue(" PC"), yellow(fmt.Sprintf("%d", r.PC)))
	if process != nil {
		if len(process.Program.Instructions) > r.PC {
			fmt.Printf(" -> %s", yellow(fmt.Sprint(process.Program.Instructions[r.PC])))
		}
	}
	fmt.Print("\n")

	printReg := func(name string, value uint64) {
		fmt.Printf("%s = %s / %s",
			blue(name),
			yellow(fmt.Sprintf("0x%016X", value)),
			yellow(fmt.Sprint(int64(value))),
		)

		entry, offset, found := process.VM.MemoryController.GetEntry(uint32(value))
		if found {
			fmt.Printf(" -> <%s+%d>", green(entry.Name), offset)

			if vmMem, ok := entry.Object.(mimic.VMMem); ok {
				rng := make([]byte, 8)
				err := vmMem.Read(offset, rng)
				if err == nil {
					fmt.Print("(...")
					for _, b := range rng {
						fmt.Printf("%02X", b)
					}
					fmt.Print("...)")
				}
			}
		}

		fmt.Print("\n")
	}

	printReg(" r0", r.R0)
	printReg(" r1", r.R1)
	printReg(" r2", r.R2)
	printReg(" r3", r.R3)
	printReg(" r4", r.R4)
	printReg(" r5", r.R5)
	printReg(" r6", r.R6)
	printReg(" r7", r.R7)
	printReg(" r8", r.R8)
	printReg(" r9", r.R9)
	printReg("r10", r.R10)
}
