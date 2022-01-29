package debug

import (
	"fmt"
	"strconv"

	"github.com/dylandreimerink/gobpfld/emulator"
)

var cmdMap = Command{
	Name:        "map",
	Aliases:     []string{"maps"},
	Summary:     "Map related operations",
	Description: "",
	Subcommands: []Command{
		{
			Name:    "list",
			Aliases: []string{"ls"},
			Summary: "Lists all loaded maps",
			Exec:    listMapsExec,
		},
		{
			Name:    "read-all",
			Summary: "Reads and displays all keys and values",
			Exec:    mapReadAllExec,
			Args: []CmdArg{{
				Name:     "map name|map index",
				Required: true,
			}},
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

func mapReadAllExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'map name|map index'\n")
		return
	}

	nameOrID := args[0]
	id, err := strconv.Atoi(nameOrID)
	if err != nil {
		id = -1
		for i, m := range vm.Maps {
			if m.GetName() == nameOrID {
				break
			}
			id = i
		}
		if id == -1 {
			printRed("No map with name '%s' exists, use 'maps list' to see valid options\n", nameOrID)
			return
		}
	}
	if id < 0 || len(vm.Maps) <= id {
		printRed("No map with id '%d' exists, use 'maps list' to see valid options\n", id)
		return
	}

	m := vm.Maps[id]
	ks := int(m.GetDef().KeySize)
	vs := int(m.GetDef().ValueSize)
	for _, k := range m.Keys() {
		v, err := m.Lookup(k)
		if err != nil {
			printRed("Error while looking up key '%s': %s\n", k, err)
			return
		}

		kPtr, ok := k.(emulator.PointerValue)
		if !ok {
			printRed("Error map key of type '%T' is not a emulator.PointerValue\n", k)
			return
		}
		kVal, err := kPtr.ReadRange(0, ks)
		if err != nil {
			printRed("Error read range key: %s\n", err)
			return
		}
		vPtr, ok := v.(emulator.PointerValue)
		if !ok {
			printRed("Error map value of type '%T' is not a emulator.PointerValue\n", v)
			return
		}
		vVal, err := vPtr.ReadRange(0, vs)
		if err != nil {
			printRed("Error read range key: %s\n", err)
			return
		}

		// TODO turn key and value bytes into printable structures using BTF Type info

		fmt.Printf("%s = %s\n",
			blue(fmt.Sprintf("%0*X", ks, kVal)),
			yellow(fmt.Sprintf("%0*X", vs, vVal)),
		)
	}
}
