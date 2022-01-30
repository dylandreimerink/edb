package debug

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
)

var cmdList = Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Summary: "Lists the lines of the source code",
	Exec:    listLinesExec,
}

func listLinesExec(args []string) {
	if len(vm.Programs) <= vm.Registers.PI {
		printRed("No program loaded at index '%d'\n", vm.Registers.PI)
		return
	}

	btfLine := getCurBTFLine()

	if btfLine == nil {
		fmt.Println(yellow("Program has no BTF, can't list lines, showing instruction instread"))
		listInstructionExec(nil)
		return
	}

	// TODO cache files
	f, err := os.Open(btfLine.FileName)
	if err != nil {
		// TODO fall back to just BTF in case we can't open the original source file
		printRed("error open source: %s\n", err)
		return
	}
	defer f.Close()

	s := bufio.NewScanner(f)

	const windowsize = 9
	start := int(btfLine.LineNumber) - windowsize
	if start < 0 {
		start = 0
	}
	end := int(btfLine.LineNumber + windowsize)

	// Scan up to the start of the line
	i := 1
	for s.Scan() && i < start {
		i++
	}

	indexPadSize := len(strconv.Itoa(end))
	for i = i + 1; i < end; i++ {
		if !s.Scan() {
			break
		}

		if i == int(btfLine.LineNumber) {
			fmt.Print(yellow(" => "))
		} else {
			fmt.Print("    ")
		}

		fmt.Print(blue(fmt.Sprintf("%*d ", indexPadSize, i)))
		fmt.Println(s.Text())
	}
}
