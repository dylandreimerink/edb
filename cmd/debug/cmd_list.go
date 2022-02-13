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
	file := getCurBTFFilename()

	if file == "" {
		fmt.Println(yellow("Program has no BTF, can't list lines, showing instruction instread"))
		listInstructionExec(nil)
		return
	}

	// TODO cache files
	f, err := os.Open(file)
	if err != nil {
		// TODO fall back to just BTF in case we can't open the original source file
		printRed("error open source: %s\n", err)
		return
	}
	defer f.Close()

	s := bufio.NewScanner(f)

	const windowsize = 9
	start := getCurBTFLineNumber() - windowsize
	if start < 0 {
		start = 0
	}
	end := getCurBTFLineNumber() + windowsize

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

		if i == getCurBTFLineNumber() {
			fmt.Print(yellow(" => "))
		} else {
			fmt.Print("    ")
		}

		fmt.Print(blue(fmt.Sprintf("%*d ", indexPadSize, i)))
		fmt.Println(s.Text())
	}
}
