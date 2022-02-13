package debug

import (
	"fmt"
	"math"
	"strconv"

	"github.com/dylandreimerink/mimic"
)

var cmdMemory = Command{
	Name:    "memory",
	Aliases: []string{"mem"},
	Summary: "Show the contents of memory",
	Subcommands: []Command{
		{
			Name:    "list",
			Aliases: []string{"ls"},
			Summary: "List all memory objects and their addresses",
			Exec:    listMemoryExec,
		},
		{
			Name:    "read",
			Summary: "Read the contents of a specific virtual address",
			Args: []CmdArg{{
				Name:     "memory block name|memory address",
				Required: true,
			}},
			Exec: readMemoryExec,
			// TODO add second argument, allowing the user to specify a range of memory to inspect
		},
		{
			Name:    "read-all",
			Summary: "Read and show the whole contents of addressable memory",
			Exec:    readAllMemoryExec,
		},
	},
}

func listMemoryExec(args []string) {
	memoryEntries := vm.MemoryController.GetAllEntries()

	for _, entry := range memoryEntries {
		fmt.Print(blue(fmt.Sprintf("[0x%08X - 0x%08X]", entry.Addr, entry.Addr+entry.Size)))
		fmt.Printf("(%s) -> (%T)(%p)\n", entry.Name, entry.Object, entry.Object)
	}
}

func readMemoryExec(args []string) {
	if len(args) < 1 {
		printRed("missing required argument 'memory block name|memory address'\n")
		return
	}

	var (
		entry  mimic.MemoryEntry
		offset = uint32(math.MaxUint32)
	)

	if num, err := strconv.ParseInt(args[0], 0, 64); err == nil {
		fmt.Println(num)
		var found bool
		entry, offset, found = process.VM.MemoryController.GetEntry(uint32(num))
		if !found {
			printRed("unable to find memory entry for '%s'\n", args[0])
			return
		}
	} else {
		memoryEntries := vm.MemoryController.GetAllEntries()

		for _, e := range memoryEntries {
			if e.Name == args[0] {
				entry = e
				break
			}
		}
	}

	if entry.Object == nil {
		printRed("unable to find memory entry for '%s'\n", args[0])
		return
	}

	fmt.Printf("%s:\n", green(entry.Name))
	fmt.Print(blue(fmt.Sprintf("0x%08X ", entry.Addr)))

	// If obj implements stringer, print the string
	if str, ok := entry.Object.(fmt.Stringer); ok {
		fmt.Println(str)
		return
	}

	if vmMem, ok := entry.Object.(mimic.VMMem); ok {
		mem := make([]byte, entry.Size)
		err := vmMem.Read(0, mem)
		if err != nil {
			printRed("%s\n", err)
			return
		}

		for j := 0; j < len(mem); j++ {
			// Color 8 bytes of the offset green
			if j >= int(offset) && j < int(offset)+8 {
				fmt.Print(green(fmt.Sprintf("%02X ", mem[j])))
			} else {
				fmt.Printf("%02X ", mem[j])
			}

			if j%16 == 15 {
				fmt.Printf("\n%s ", blue(fmt.Sprintf("0x%08X", entry.Addr+uint32(j))))
			} else if j%8 == 7 {
				fmt.Print(" ")
			}
		}
		fmt.Print("\n\n")
		return
	}

	// Not a stringer, not VMMem, just print the type and pointer
	fmt.Printf("-> (%T)(%p)\n\n", entry.Object, entry.Object)
}

func readAllMemoryExec(args []string) {
	memoryEntries := vm.MemoryController.GetAllEntries()

	for _, entry := range memoryEntries {
		fmt.Printf("%s:\n", green(entry.Name))
		fmt.Print(blue(fmt.Sprintf("0x%08X ", entry.Addr)))

		// If obj implements stringer, print the string
		if str, ok := entry.Object.(fmt.Stringer); ok {
			fmt.Println(str)
			continue
		}

		if vmMem, ok := entry.Object.(mimic.VMMem); ok {
			mem := make([]byte, entry.Size)
			err := vmMem.Read(0, mem)
			if err != nil {
				printRed("%s\n", err)
				return
			}

			for j := 0; j < len(mem); j++ {
				fmt.Printf("%02X ", mem[j])
				if j%16 == 15 {
					fmt.Printf("\n%s ", blue(fmt.Sprintf("0x%08X", entry.Addr+uint32(j))))
				} else if j%8 == 7 {
					fmt.Print(" ")
				}
			}
			fmt.Print("\n\n")
			continue
		}

		// Not a stringer, not VMMem, just print the type and pointer
		fmt.Printf("-> (%T)(%p)\n\n", entry.Object, entry.Object)
	}
}
