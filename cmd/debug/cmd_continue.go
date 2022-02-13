package debug

import "fmt"

var cmdContinue = Command{
	Name:    "continue",
	Aliases: []string{"c"},
	Summary: "Continue execution of the program until it exits or a breakpoint is hit",
	Exec:    continueExec,
}

func continueExec(args []string) {
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
			fmt.Println("Program exited")
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
