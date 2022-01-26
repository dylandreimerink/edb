package debug

import (
	"debug/dwarf"
	"fmt"
)

var cmdLocals = Command{
	Name:    "locals",
	Aliases: []string{"lv"},
	Summary: "Lists the local variables",
	Exec:    listLocalVarsExec,
}

// TODO make the locals command actually display the value of the local. In theory we should be able to get this from
// the location info encoded in the DWARF, but last time I tried this on -O0 code it returned offset into the stack
// frame which didn't correspond with the correct variables.

func listLocalVarsExec(args []string) {
	if len(vm.Programs) <= vm.Registers.PI {
		printRed("No program loaded at index '%d'\n", vm.Registers.PI)
		return
	}

	det := progDwarf[vm.Registers.PI]

	btfFunc := getBTFFunc()
	subProg := det.SubPrograms[btfFunc.Type.GetName()]
	fbAttr := subProg.Entry.AttrField(dwarf.AttrFrameBase)
	if fbAttr == nil {
		panic("sub prog missing frame base")
	}

	for _, child := range subProg.Children {
		e := child.Entry
		switch e.Tag {
		case dwarf.TagVariable:
			fmt.Print(
				green("  (var) "),
				e.AttrField(dwarf.AttrName).Val,
				" ",
			)
		case dwarf.TagFormalParameter:
			fmt.Print(
				green("(param) "),
				e.AttrField(dwarf.AttrName).Val,
				" ",
			)
		default:
			continue
		}

		fmt.Println(blue(dwarfTypeName(child)))
	}
}
