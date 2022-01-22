package main

import (
	"fmt"
	"strconv"
)

var cmdPrograms = Command{
	Name:     "programs",
	Aliasses: []string{"progs"},
	Summary:  "Show programs",
	Exec:     programsExec,
}

func programsExec(args []string) {
	indexPadSize := len(strconv.Itoa(len(progName)))
	for i, name := range progName {
		if i == vm.Registers.PI {
			fmt.Print(yellow(" => "))
		} else {
			fmt.Print("    ")
		}

		fmt.Print(blue(fmt.Sprintf("%*d ", indexPadSize, i)))
		fmt.Printf("%s (%s)\n", name, programs[i].GetAbstractProgram().ProgramType)
	}
}
