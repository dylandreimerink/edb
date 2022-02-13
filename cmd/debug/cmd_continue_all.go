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
	if process == nil {
		cmdReset.Exec(nil)
	}

	// TODO if the breakpoint type is line oriented, don't break until we have at least progressed past the
	//   	current line (1 line can take up multiple instructions)

	for {
		stop, err := process.Step()
		if err != nil {
			printRed("%s\n", err)
			break
		}

		if stop {
			if curCtx+1 < len(contexts) {
				err = process.Cleanup()
				if err != nil {
					printRed("%s\n", err)
					break
				}

				curCtx++
				process, err = vm.NewProcess(entrypoint, contexts[curCtx])
				if err != nil {
					printRed("%s\n", err)
					break
				}

				continue
			}

			fmt.Println("All contexts executed")

			return
		}

		for i, bp := range breakpoints {
			if !bp.ShouldBreak(process) {
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
