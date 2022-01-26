package debug

import (
	"fmt"
	"strconv"
)

var cmdListInstructions = Command{
	Name:    "list-instructions",
	Aliases: []string{"li"},
	Summary: "Lists the instructions of the program",
	Exec:    listInstructionExec,
}

func listInstructionExec(args []string) {
	if len(vm.Programs) <= vm.Registers.PI {
		printRed("No program loaded at index '%d'\n", vm.Registers.PI)
		return
	}

	program := vm.Programs[vm.Registers.PI]

	const windowsize = 9
	start := vm.Registers.PC - windowsize
	end := vm.Registers.PC + windowsize

	var err error
	if len(args) >= 1 {
		start, err = strconv.Atoi(args[0])
		if err != nil {
			printRed("invalid start: %s\n", err)
			return
		}
	}

	if len(args) >= 2 {
		end, err = strconv.Atoi(args[1])
		if err != nil {
			printRed("invalid end: %s\n", err)
			return
		}
	}

	if start < 0 {
		start = 0
	}
	if end > len(program) {
		end = len(program)
	}

	if end <= start {
		printRed("'end' must be bigger than 'start'\n")
		return
	}

	// TODO BTF line annotation
	indexPadSize := len(strconv.Itoa(end))
	for i := start; i < end; i++ {
		if i == vm.Registers.PC {
			fmt.Print(yellow(" => "))
		} else {
			fmt.Print("    ")
		}

		fmt.Print(blue(fmt.Sprintf("%*d ", indexPadSize, i)))
		fmt.Println(program[i].String())
	}
}
