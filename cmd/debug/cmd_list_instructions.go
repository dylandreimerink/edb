package debug

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

var cmdListInstructions = Command{
	Name:    "list-instructions",
	Aliases: []string{"li"},
	Summary: "Lists the instructions of the program",
	Exec:    listInstructionExec,
}

func listInstructionExec(args []string) {
	var program *ebpf.ProgramSpec

	// If we have a running process, use its current program
	if process != nil {
		program = process.Program
	} else {
		programs := vm.GetPrograms()
		if entrypoint < len(programs) {
			program = programs[entrypoint]
		}
	}

	if program == nil {
		printRed("Invalid entrypoint or no programs loaded yet\n")
		return
	}

	pc := 0
	if process != nil {
		pc = process.Registers.PC
	}

	const windowsize = 9
	start := pc - windowsize
	end := pc + windowsize

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
	if end > len(program.Instructions) {
		end = len(program.Instructions)
	}

	if end <= start {
		printRed("'end' must be bigger than 'start'\n")
		return
	}

	var lastLine string

	indexPadSize := len(strconv.Itoa(end))
	for i := start; i < end; i++ {
		inst := program.Instructions[i]

		if inst.Symbol() != "" {
			fmt.Print("<", yellow(inst.Symbol()), ">:\n")
		}

		var curLine string
		if inst.Line() != "" {
			curLine = inst.Line()
		}
		if curLine != lastLine && curLine != "" {
			line := strings.TrimSpace(curLine)
			fmt.Print("   ", strings.Repeat(" ", indexPadSize), "; ")
			fmt.Println(green(line))
			lastLine = curLine
		}

		if i == pc {
			fmt.Print(yellow(" => "))
		} else {
			fmt.Print("    ")
		}

		fmt.Print(blue(fmt.Sprintf("%*d ", indexPadSize, i)))
		fmt.Println(inst)
	}
}
