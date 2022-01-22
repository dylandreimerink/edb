package main

import "fmt"

var cmdStep = Command{
	Name:     "step",
	Aliasses: []string{"s"},
	Summary:  "Step through the program one line a time",
	Exec:     stepExec,
}

func stepExec(args []string) {
	if len(vm.Programs) <= vm.Registers.PI {
		printRed("No program loaded at index '%d'\n", vm.Registers.PI)
		return
	}

	startLine := getBTFLine()
	for {
		stop, err := vm.Step()
		if err != nil {
			printRed("%s\n", err)
			break
		}

		if stop {
			fmt.Println("Program exited")
			return
		}

		curLine := getBTFLine()
		if curLine == nil || startLine == nil || curLine.LineNumber != startLine.LineNumber {
			break
		}
	}

	listLinesExec(nil)
}
