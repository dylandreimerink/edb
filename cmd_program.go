package main

import (
	"fmt"
	"strconv"
)

var cmdProgram = Command{
	Name:    "program",
	Aliases: []string{"prog"},
	Summary: "Program related commands",
	Subcommands: []Command{
		{
			Name:    "list",
			Summary: "List all loaded programs",
			Description: "This command lists all loaded programs, the " + blue("blue") + " number indicates the " +
				"program index, the " + yellow("yellow") + " arrow indicates the current program, which can changed " +
				"during execution due to tailcalls, and the " + green("green") + " arrow indicates the entrypoint program " +
				"which can be changed using the 'program set' command.\n" +
				"\n" +
				"Note: No green arrow is displayed if the current program and entry program are the same.",
			Aliases: []string{"ls"},
			Exec:    listProgramsExec,
		},
		{
			Name:    "set",
			Summary: "Sets the entrypoint program",
			Exec:    setProgramEntrypointExec,
			Args: []CmdArg{
				{
					Name: "program index|program name",
				},
			},
		},
	},
}

func listProgramsExec(args []string) {
	indexPadSize := len(strconv.Itoa(len(progName)))
	for i, name := range progName {
		if i == vm.Registers.PI {
			fmt.Print(yellow(" => "))
		} else if i == entrypoint {
			fmt.Print(green(" => "))
		} else {
			fmt.Print("    ")
		}

		fmt.Print(blue(fmt.Sprintf("%*d ", indexPadSize, i)))
		fmt.Printf("%s (%s)\n", name, programs[i].GetAbstractProgram().ProgramType)
	}
}

func setProgramEntrypointExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'program index|program name'\n")
		return
	}

	success := func(id int) {
		entrypoint = id
		fmt.Printf("Entrypoint program set to '%s' (%d)\n", progName[entrypoint], entrypoint)

		if vm.Registers.PC == 0 {
			fmt.Printf("Program counter at 0, changed current program\n")
			vm.Registers.PI = entrypoint
		} else {
			fmt.Printf("Program mid execution, current program unchanged, execute 'reset' to go to entrypoint\n")
		}
	}

	nameOrID := args[0]
	if id, err := strconv.Atoi(nameOrID); err == nil {
		if len(programs) <= id {
			printRed("No program with id '%d' exists, use 'programs list' to see valid options\n", id)
			return
		}

		success(id)
		return
	}

	for id, name := range progName {
		if name == nameOrID {
			success(id)
			return
		}
	}

	printRed("No program with name '%s' exists, use 'programs list' to see valid options\n", nameOrID)
}
