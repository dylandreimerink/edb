package debug

import "fmt"

var cmdContinueAll = Command{
	Name:    "continue-all",
	Aliases: []string{"ca"},
	Summary: "Continue execution of the program for all contexts",
	Description: "This command will continue execution of the program, if the program exits, the VM will be reset " +
		"and the next context loaded, just like a real program would. Execution halts when no more contexts are " +
		"available or a breakpoint is hit",
	Exec: continueAllExec,
}

func continueAllExec(args []string) {
	if len(vm.Programs) <= vm.Registers.PI {
		printRed("No program loaded at index '%d'\n", vm.Registers.PI)
		return
	}

	// TODO if the breakpoint type is line oriented, don't break until we have at least progressed past the
	//   	current line (1 line can take up multiple instructions)

	for {
		stop, err := vm.Step()
		if err != nil {
			printRed("%s\n", err)
			break
		}

		if stop {
			if curCtx+1 < len(contexts) {
				curCtx++
				vm.Reset()
				vm.Registers.PI = entrypoint
				vm.Registers.R1 = contexts[curCtx].MemPtr
				continue
			}

			fmt.Println("All contexts executed")

			return
		}

		for i, bp := range breakpoints {
			if !bp.ShouldBreak(vm) {
				continue
			}

			fmt.Printf("Hit breakpoint '%d'\n", i)

			switch bp.(type) {
			case *InstructionBreakpoint:
				listInstructionExec(nil)
			default:
				listLinesExec(nil)
			}

			return
		}
	}
}
