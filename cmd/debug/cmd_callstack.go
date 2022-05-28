package debug

import (
	"debug/dwarf"
	"fmt"
)

var cmdCallsStack = Command{
	Name:    "callstack",
	Aliases: []string{"cs"},
	Summary: "Print out the current callstack",
	Exec:    callStackCmd,
}

func callStackCmd(args []string) {
	if process == nil {
		printRed("No program loaded")
		return
	}

	det := progDwarf[process.Program.Name]

	programScopes := det.PCToScope[process.Program.Name]
	if process.Registers.PC >= len(programScopes) {
		return
	}

	node := programScopes[process.Registers.PC]

	fmt.Print(green(fmt.Sprintf("%s:%d ", getCurBTFFilename(), getCurBTFLineNumber())))

	for ; node != nil; node = node.Parent {
		if !(node.Entry.Tag == dwarf.TagInlinedSubroutine || node.Entry.Tag == dwarf.TagSubprogram) {
			continue
		}

		name := det.Val(node.Entry, dwarf.AttrName)
		if name == nil {
			continue
		}

		fmt.Print(yellow(fmt.Sprintf("<%s>\n", name.(string))))

		fileIdx := det.Val(node.Entry, dwarf.AttrCallFile)
		if fileIdx == nil {
			continue
		}

		file := det.Files[fileIdx.(int64)]
		line, _ := det.Val(node.Entry, dwarf.AttrCallLine).(int64)
		col, _ := det.Val(node.Entry, dwarf.AttrCallColumn).(int64)

		fmt.Print(green(fmt.Sprintf("%s:%d:%d ", file.Name, line, col)))

	}
}
