package main

import (
	"fmt"
	"strconv"
)

var cmdMap = Command{
	Name:        "map",
	Aliasses:    []string{"maps"},
	Summary:     "Map related operations",
	Description: "",
	Subcommands: []Command{
		{
			Name:     "list",
			Aliasses: []string{"ls"},
			Summary:  "Lists all loaded maps",
			Exec:     listMapsExec,
		},
	},
}

func listMapsExec(args []string) {
	indexPadSize := len(strconv.Itoa(len(vm.Maps)))
	for i, m := range vm.Maps {
		fmt.Print(blue(fmt.Sprintf("%*d ", indexPadSize, i)))
		fmt.Printf("%s:\n", m.GetName())
		// TODO print Key and Value types from BTF
		def := m.GetDef()
		fmt.Printf("        Type: %s\n", def.Type)
		fmt.Printf("    Key size: %d bytes\n", def.KeySize)
		fmt.Printf("  Value size: %d bytes\n", def.ValueSize)
		fmt.Printf(" Max entries: %d\n", def.MaxEntries)
		fmt.Printf("       Flags: %s\n\n", def.Flags)
	}
}
