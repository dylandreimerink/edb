package debug

import (
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/dylandreimerink/mimic"
)

var cmdLoad = Command{
	Name:        "load",
	Aliases:     nil,
	Summary:     "Load an ELF file",
	Description: "This command parses the ELF file and loads all programs and maps contained within",
	Exec:        loadExec,
	Args: []CmdArg{
		{
			Name:     "ELF file path",
			Required: true,
		},
	},
	CustomCompletion: fileCompletion,
}

func loadExec(args []string) {
	if len(args) == 0 {
		printRed("At least one argument required\n")
		helpCmd.Exec([]string{"load"})
		return
	}

	coll, err := ebpf.LoadCollectionSpec(args[0])
	if err != nil {
		printRed("load collection: %s\n", err)
		return
	}

	// ef, err := elf.NewFile(bytes.NewReader(eb))
	// if err != nil {
	// 	printRed("elf new file: %s\n", err)
	// 	return
	// }

	// Make a sorted list of map names so they always are inserted in the same order between debugging sessions.
	// This repeatability makes using numeric indexes in macros possible
	elfMapNames := make([]string, 0, len(coll.Maps))
	for name := range coll.Maps {
		elfMapNames = append(elfMapNames, name)
	}
	sort.Strings(elfMapNames)

	for _, name := range elfMapNames {
		spec := coll.Maps[name]
		m, err := mimic.MapSpecToLinuxMap(spec)
		if err != nil {
			printRed("error map spec to linux map: %s\n", err)
			return
		}

		err = vmEmulator.AddMap(m)
		if err != nil {
			printRed("error add map to emulator: %s\n", err)
			return
		}

		fmt.Printf("loaded map '%s'\n", name)
	}

	// Make a sorted list of program names so they always are inserted in the same order between debugging sessions.
	// This repeatability makes using numeric indexes in macros possible
	elfProgNames := make([]string, 0, len(coll.Programs))
	for name := range coll.Programs {
		elfProgNames = append(elfProgNames, name)
	}
	sort.Strings(elfProgNames)

	for _, name := range elfProgNames {
		prog := coll.Programs[name]

		progIndex, err := vm.AddProgram(prog)
		if err != nil {
			printRed("vm add program: %s\n", err)
			return
		}

		// det, err := newDET(ef, name)
		// if err != nil {
		// 	printRed("new det: %s\n", err)
		// 	return
		// }

		// progDwarf = append(progDwarf, det)

		fmt.Printf("Loaded program '%s' at program index %d\n", name, progIndex)
	}

	// If we are not in the middle of program execution, reset the VM.
	// We do this to set the context of the program(R1)
	if process == nil || (process.Registers.PC == 0 && vm.GetPrograms()[entrypoint].Name == process.Program.Name) {
		cmdReset.Exec(nil)
	}
}
