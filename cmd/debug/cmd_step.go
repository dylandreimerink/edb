package debug

import "fmt"

var cmdStep = Command{
	Name:    "step",
	Aliases: []string{"s"},
	Summary: "Step through the program one line a time",
	Exec:    stepExec,
}

func stepExec(args []string) {
	if process == nil {
		cmdReset.Exec(nil)
	}

	startLine := getCurBTFLine()
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

		curLine := getCurBTFLine()
		if curLine == "" || startLine == "" || curLine != startLine {
			break
		}
	}

	listLinesExec(nil)
}
