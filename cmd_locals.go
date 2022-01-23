package main

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
