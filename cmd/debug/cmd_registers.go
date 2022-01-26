package debug

import (
	"fmt"
)

var cmdRegisters = Command{
	Name:    "registers",
	Aliases: []string{"r", "regs"},
	Summary: "Show registers",
	Exec:    registersExec,
}

func registersExec(args []string) {
	fmt.Print("Registers:\n")

	r := vm.Registers
	fmt.Printf("%s = %s", blue(" PC"), yellow(fmt.Sprintf("%d", r.PC)))
	if len(vm.Programs) > r.PI {
		if len(vm.Programs[r.PI]) > r.PC {
			fmt.Printf(" -> %s", yellow(vm.Programs[r.PI][r.PC].String()))
		}
	}
	fmt.Print("\n")

	// TODO add program name, as soon as we have that available
	fmt.Printf("%s = %s\n", blue(" PI"), yellow(fmt.Sprintf("%d", r.PI)))
	fmt.Printf("%s = %s\n", blue(" SF"), yellow(fmt.Sprintf("%d", r.SF)))
	fmt.Printf("%s = %s\n", blue(" r0"), yellow(r.R0.String()))
	fmt.Printf("%s = %s\n", blue(" r1"), yellow(r.R1.String()))
	fmt.Printf("%s = %s\n", blue(" r2"), yellow(r.R2.String()))
	fmt.Printf("%s = %s\n", blue(" r3"), yellow(r.R3.String()))
	fmt.Printf("%s = %s\n", blue(" r4"), yellow(r.R4.String()))
	fmt.Printf("%s = %s\n", blue(" r5"), yellow(r.R5.String()))
	fmt.Printf("%s = %s\n", blue(" r6"), yellow(r.R6.String()))
	fmt.Printf("%s = %s\n", blue(" r7"), yellow(r.R7.String()))
	fmt.Printf("%s = %s\n", blue(" r8"), yellow(r.R8.String()))
	fmt.Printf("%s = %s\n", blue(" r9"), yellow(r.R9.String()))
	fmt.Printf("%s = %s\n", blue("r10"), yellow((&r.R10).String()))
}
