package main

import "fmt"

var cmdStepInstruction = Command{
	Name:     "step-instruction",
	Aliasses: []string{"si"},
	Summary:  "Step through the program one instruction a time",
	Exec:     stepInstructionExec,
}

func stepInstructionExec(args []string) {
	stop, err := vm.Step()
	if err != nil {
		printRed("%s\n", err)
	}

	if stop {
		fmt.Println("Program exited")
		return
	}

	listInstructionExec(nil)
}
