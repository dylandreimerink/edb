package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/dylandreimerink/edb/elf"
	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/ebpf"
	"github.com/dylandreimerink/gobpfld/emulator"
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

	f, err := os.Open(args[0])
	if err != nil {
		printRed("error file open: %s\n", err)
		return
	}
	defer f.Close()

	fb := bufio.NewReader(f)
	eb, err := io.ReadAll(fb)
	if err != nil {
		printRed("read file: %s\n", err)
		return
	}

	ef, err := elf.NewFile(bytes.NewReader(eb))
	if err != nil {
		printRed("elf new file: %s\n", err)
		return
	}

	elf, err := gobpfld.LoadProgramFromELF(bytes.NewReader(eb), gobpfld.ELFParseSettings{TruncateNames: true})
	if err != nil {
		printRed("error load ELF: %s\n", err)
		return
	}

	mapIds := make(map[string]int)
	for name, m := range elf.Maps {
		m, err := emulator.AbstractMapToVM(gobpfld.AbstractMap{
			Name:        m.GetName(),
			Definition:  m.GetDefinition(),
			BTF:         m.GetBTF(),
			BTFMapType:  m.GetBTFMapType(),
			InitialData: m.GetInitialData(),
		})
		if err != nil {
			printRed("error abstract map to vm: %s\n", err)
			return
		}

		if am, ok := m.(*emulator.ArrayMap); ok {
			am.InitialDataBO = elf.ByteOrder
		}

		id, err := vm.AddMap(m)
		if err != nil {
			printRed("error add abstract map: %s\n", err)
			return
		}
		mapIds[name] = id

		fmt.Printf("loaded map '%s' at index %d\n", name, id)
	}

	for name, prog := range elf.Programs {
		ap := prog.GetAbstractProgram()

		for mapName, offsets := range ap.MapFDLocations {
			mapID, found := mapIds[mapName]
			if !found {
				printRed(
					"error program '%s' requires map named '%s' which is not defined in the file\n",
					name,
					mapName,
				)
				return
			}

			// For every location the program needs the map fd, insert it
			for _, offset := range offsets {
				instIndex := offset / uint64(ebpf.BPFInstSize)
				inst := &ap.Instructions[instIndex]

				// BPF_PSEUDO_MAP_FD_VALUE is set if this is an access into a global data section.
				// In this case, imm of the first inst contains the offset which must be moved to the second inst
				if inst.GetSourceReg() == ebpf.BPF_PSEUDO_MAP_FD_VALUE {
					inst2 := &ap.Instructions[instIndex+1]
					inst2.Imm = inst.Imm
				} else {
					inst.SetSourceReg(ebpf.BPF_PSEUDO_MAP_FD)
				}

				inst.Imm = int32(mapID)
			}
		}

		err = vm.AddRawProgram(ap.Instructions)
		if err != nil {
			printRed("add program: %s\n", err)
			return
		}

		det, err := newDET(ef, name)
		if err != nil {
			printRed("new det: %s\n", err)
			return
		}

		progName = append(progName, name)
		programs = append(programs, prog)
		progDwarf = append(progDwarf, det)

		fmt.Printf("Loaded program '%s' at program index %d\n", name, len(vm.Programs)-1)
	}

	// If we are not in the middle of program execution, reset the VM.
	// We do this to set the context of the program(R1)
	if vm.Registers.PC == 0 && vm.Registers.PI == entrypoint {
		cmdReset.Exec(nil)
	}
}
