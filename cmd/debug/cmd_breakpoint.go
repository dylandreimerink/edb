package debug

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/dylandreimerink/mimic"
	"github.com/go-delve/delve/pkg/locspec"
)

var cmdBreakpoint = Command{
	Name:    "breakpoint",
	Aliases: []string{"b", "br", "bp", "break"},
	Summary: "Commands related to breakpoints",
	Subcommands: []Command{
		{
			Name:    "list",
			Aliases: []string{"ls"},
			Summary: "List all breakpoints",
			Exec:    listBreakpointsExec,
		},
		{
			Name:    "set",
			Aliases: []string{"add"},
			Summary: "Set a new breakpoint",
			Exec:    setBreakpointExec,
			Args: []CmdArg{
				{
					Name:     "loc spec",
					Required: true,
				},
				// TODO add conditional
			},
			// TODO add custom suggestions for locspec
		},
		{
			Name:    "enable",
			Summary: "Enable a breakpoint",
			Exec:    enableBreakpointExec,
			Args: []CmdArg{{
				Name:     "breakpoint id",
				Required: true,
			}},
			// TODO add custom suggestions, list disabled breakpoints
		},
		{
			Name:    "disable",
			Summary: "Disable a breakpoint",
			Exec:    disableBreakpointExec,
			Args: []CmdArg{{
				Name:     "breakpoint id",
				Required: true,
			}},
			// TODO add custom suggestions, list enabled breakpoints
		},
		// TODO add delete breakpoint?
	},
}

func listBreakpointsExec(args []string) {
	indexPadSize := len(strconv.Itoa(len(breakpoints)))
	for i, bp := range breakpoints {
		if bp.Enabled() {
			fmt.Print(blue(fmt.Sprintf("%*d ", indexPadSize, i)))
		} else {
			fmt.Print(blueStrike(fmt.Sprintf("%*d ", indexPadSize, i)))
		}

		var inst string
		switch bp := bp.(type) {
		case *InstructionBreakpoint:
			inst = fmt.Sprintf("%s:%d\n", bp.Program.Name, bp.ProgramCounter)
		case *FileLineBreakpoint:
			inst = fmt.Sprintf("%s:%d\n", bp.File, bp.Line)
		default:
			inst = fmt.Sprintf("%v\n", bp)
		}

		if bp.Enabled() {
			fmt.Print(inst)
		} else {
			fmt.Print(whiteStrike(inst))
		}
	}
}

func setBreakpointExec(args []string) {
	if len(args) < 1 {
		printRed("Missing {loc spec} argument\n\n")
		fmt.Println("Usage:")
		helpExec([]string{"breakpoint", "set"})
		return
	}

	instOrLineSpec := args[0]

	spec, err := locspec.Parse(instOrLineSpec)
	if err != nil {
		printRed("Invalid loc spec: %s\n", err)
		return
	}

	var bp Breakpoint

	switch spec := spec.(type) {
	case *locspec.RegexLocationSpec:
		printRed("Regex locspec not (yet) supported by edb")
		return

	case *locspec.AddrLocationSpec:
		// TODO if only the instruction number is specified i.e "*123", just use the current program, makes sense for
		// 		single program debugging sessions(likely most of them)

		parts := strings.Split(spec.AddrExpr, ":")
		if len(parts) != 2 {
			printRed("Invalid address locspec, must be formatted like " +
				"*<program name|program index>:<instruction number>\n")
			return
		}

		var progSpec *ebpf.ProgramSpec

		id, err := strconv.Atoi(parts[0])
		if err == nil {
			programs := vm.GetPrograms()
			if len(programs) > id {
				progSpec = programs[id]
			}
		} else {
			for _, prog := range vm.GetPrograms() {
				if parts[0] == prog.Name {
					progSpec = prog
					break
				}
			}
		}

		if progSpec == nil {
			printRed("Unknown program name or index '%s', execute 'program list' to get valid options\n", parts[0])
			return
		}

		inst, err := strconv.Atoi(parts[1])
		if err != nil {
			printRed("Invalid instruction number: %s\n", err)
			return
		}

		bp = &InstructionBreakpoint{
			Program:        progSpec,
			ProgramCounter: inst,
		}

	case *locspec.LineLocationSpec:
		filename := getCurBTFFilename()
		if filename == "" {
			printRed("Unable to find current file")
			return
		}

		bp = &FileLineBreakpoint{
			File: filename,
			Line: spec.Line,
		}

	case *locspec.OffsetLocationSpec:
		inst := process.Registers.PC + spec.Offset

		if inst < 0 {
			printRed("Instruction number can't be negative\n")
			return
		}

		bp = &InstructionBreakpoint{
			Program:        process.Program,
			ProgramCounter: inst,
		}

	case *locspec.NormalLocationSpec:
		printRed("Unsupported locspec type '%T'", spec)
		return

	default:
		printRed("Unsupported locspec type '%T'", spec)
		return
	}

	bp.Enable()
	breakpoints = append(breakpoints, bp)
	fmt.Printf("Added breakpoint with id '%d'\n", len(breakpoints)-1)
}

func enableBreakpointExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'breakpoint id'\n")
		return
	}

	id, err := strconv.Atoi(args[0])
	if err != nil {
		printRed("%s\n", err)
		return
	}

	if len(breakpoints) <= id {
		printRed("No breakpoint with id '%d' exists, use 'breakpoint list' to see valid options\n", id)
		return
	}

	breakpoints[id].Enable()
	fmt.Printf("Breakpoint '%d' is enabled\n", id)
}

func disableBreakpointExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'breakpoint id'\n")
		return
	}

	id, err := strconv.Atoi(args[0])
	if err != nil {
		printRed("%s\n", err)
		return
	}

	if len(breakpoints) <= id {
		printRed("No breakpoint with id '%d' exists, use 'breakpoint list' to see valid options\n", id)
		return
	}

	breakpoints[id].Disable()
	fmt.Printf("Breakpoint '%d' is disabled\n", id)
}

type Breakpoint interface {
	ShouldBreak(process *mimic.Process) bool
	Enabled() bool
	Enable()
	Disable()
}

type abstractBreakpoint struct {
	enabled bool
}

func (ab *abstractBreakpoint) Enabled() bool {
	return ab.enabled
}

func (ab *abstractBreakpoint) Enable() {
	ab.enabled = true
}

func (ab *abstractBreakpoint) Disable() {
	ab.enabled = false
}

// InstructionBreakpoint breaks only on an exact PI + PC combo
type InstructionBreakpoint struct {
	abstractBreakpoint
	Program        *ebpf.ProgramSpec
	ProgramCounter int
}

func (ib *InstructionBreakpoint) ShouldBreak(process *mimic.Process) bool {
	if !ib.enabled {
		return false
	}

	return process.Program.Name == ib.Program.Name && process.Registers.PC == ib.ProgramCounter
}

// FileLineBreakpoint breaks when on a specific file or line, no matter the program
type FileLineBreakpoint struct {
	abstractBreakpoint
	File string
	Line int
}

func (fl *FileLineBreakpoint) ShouldBreak(process *mimic.Process) bool {
	if !fl.enabled {
		return false
	}

	file := getCurBTFFilename()
	if file == "" {
		return false
	}

	return file == fl.File && getCurBTFLineNumber() == fl.Line
}

// // FileFuncBreakpoint breaks when entering a specific function in a specific line
// type FileFuncBreakpoint struct {
// 	abstractBreakpoint
// 	File string
// 	Func string
// }

// // RegexFuncBreakpoint breaks when entering a function matching the regex
// type RegexFuncBreakpoint struct {
// 	abstractBreakpoint
// 	Regex *regexp.Regexp
// }
