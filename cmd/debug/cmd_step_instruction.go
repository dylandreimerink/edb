package debug

import (
	"fmt"
)

var cmdStepInstruction = Command{
	Name:    "step-instruction",
	Aliases: []string{"si"},
	Summary: "Step through the program one instruction a time",
	Exec:    stepInstructionExec,
}

func stepInstructionExec(args []string) {
	if process == nil {
		cmdReset.Exec(nil)
	}

	stop, err := process.Step()
	if err != nil {
		printRed("%s\n", err)
	}

	if stop {
		fmt.Println("Program exited")
		return
	}

	listInstructionExec(nil)
}
