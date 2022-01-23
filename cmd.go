package main

import (
	"debug/dwarf"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	prompt "github.com/c-bata/go-prompt"
	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/ebpf"
	"github.com/lithammer/fuzzysearch/fuzzy"
	"github.com/mgutz/ansi"
)

type CmdFn func(args []string)
type CompletionFn func(args []string) []prompt.Suggest

type CmdArg struct {
	Name     string
	Required bool
}

type Command struct {
	Name             string
	Summary          string
	Description      string
	Aliases          []string
	Exec             CmdFn
	Args             []CmdArg
	Subcommands      []Command
	CustomCompletion CompletionFn
}

var (
	rootCommands []Command

	red    = ansi.ColorFunc("red")
	blue   = ansi.ColorFunc("blue")
	green  = ansi.ColorFunc("green")
	yellow = ansi.ColorFunc("yellow")
)

func init() {
	rootCommands = []Command{
		helpCmd,
		{
			Name:    "exit",
			Aliases: []string{"q", "quit"},
			Summary: "Exits the debugger",
			Exec: func(args []string) {
				os.Exit(0)
			},
		},
		{
			Name:    "clear",
			Summary: "Clear the screen",
			Exec: func(args []string) {
				fmt.Print("\033[2J")
			},
		},
		cmdLoad,
		cmdCtx,
		cmdProgram,
		cmdReset,
		cmdRegisters,
		cmdStepInstruction,
		cmdListInstructions,
		cmdStep,
		cmdList,
		cmdMap,
		cmdLocals,
		cmdMemory,
	}
}

// fmt.Printf but in red
func printRed(format string, args ...interface{}) {
	if len(args) == 0 {
		fmt.Print(red(format))
		return
	}

	fmt.Print(red(fmt.Sprintf(format, args...)))
}

func getBTFLine() *gobpfld.BTFLine {
	btf := programs[vm.Registers.PI].GetAbstractProgram().BTF

	rawOffset := vm.Registers.PC * ebpf.BPFInstSize

	var lastLine *gobpfld.BTFLine
	for i, line := range btf.Lines {
		// Ignore line number zero, it is not valid
		if line.LineNumber == 0 {
			continue
		}

		// Return the current line if we find an exact match
		if line.InstructionOffset == uint32(rawOffset) {
			return &btf.Lines[i]
		}

		// If we have overshot the offset, return the last line (best approximation)
		if line.InstructionOffset > uint32(rawOffset) {
			return lastLine
		}

		lastLine = &btf.Lines[i]
	}

	return nil
}

var lastArgs []string

func executor(in string) {
	in = strings.TrimSpace(in)

	quoted := false
	args := strings.FieldsFunc(in, func(r rune) bool {
		if r == '"' {
			quoted = !quoted
		}
		return !quoted && r == ' '
	})
	for i, arg := range args {
		args[i] = strings.Trim(arg, "\"")
	}

	if len(args) == 0 {
		if len(lastArgs) == 0 {
			helpCmd.Exec(nil)
			return
		}

		args = lastArgs
	}

	lastArgs = args

	var cmd Command
	cmdList := rootCommands
	// Copy slice header, which we intend to modify
	modArgs := args
	for {
		var found bool
		cmd, found = commandMap(cmdList)[modArgs[0]]
		if !found {
			printRed("'%s' is not a valid command\n\n", strings.Join(args, " "))
			fmt.Println("Usage:")
			helpExec(args)
			return
		}

		modArgs = modArgs[1:]

		// If this command has sub commands and we also have more arguments, continue resolving
		if len(cmd.Subcommands) > 0 && len(modArgs) > 0 {
			cmdList = cmd.Subcommands
			continue
		}

		// If a command has no Exec, we are not meant to execute it, rater a subcommand, so show help
		if cmd.Exec == nil {
			printRed("'%s' is missing a {sub-command}\n\n", strings.Join(args, " "))
			fmt.Println("Usage:")
			helpExec(args)
			return
		}

		// If there are no more arguments or no more sub commands, execute the current command and exit

		cmd.Exec(modArgs)
		return
	}
}

func completer(in prompt.Document) []prompt.Suggest {
	inText := strings.TrimSpace(in.Text)

	if inText == "" {
		return nil
	}

	quoted := false
	args := strings.FieldsFunc(inText, func(r rune) bool {
		if r == '"' {
			quoted = !quoted
		}
		return !quoted && r == ' '
	})
	for i, arg := range args {
		args[i] = strings.Trim(arg, "\"")
	}

	var cmd Command
	cmdList := rootCommands
	// Copy slice header, which we intend to modify
	modArgs := args
	for {
		if len(modArgs) == 0 {
			break
		}

		var found bool
		cmd, found = commandMap(cmdList)[modArgs[0]]
		if !found {
			break
		}

		// If this command has sub commands and we also have more arguments, continue resolving
		if len(cmd.Subcommands) > 0 && len(modArgs) > 0 {
			modArgs = modArgs[1:]
			cmdList = cmd.Subcommands
			continue
		}

		// If a command has no Exec, we are not meant to execute it, rater a subcommand, so show help
		if cmd.CustomCompletion != nil {
			return cmd.CustomCompletion(modArgs[1:])
		}

		break
	}

	cmds := make([]string, len(cmdList))
	for i, cmd := range cmdList {
		cmds[i] = cmd.Name
	}

	search := ""
	if len(modArgs) > 0 {
		search = modArgs[0]
	}

	var suggestions []prompt.Suggest
	cmdMap := commandMap(cmdList)

	ranks := fuzzy.RankFind(search, cmds)
	sort.Sort(ranks)

	for _, rank := range ranks {
		cmd, found := cmdMap[rank.Target]
		if !found {
			continue
		}

		suggestions = append(suggestions, prompt.Suggest{
			Text:        cmd.Name,
			Description: cmd.Summary,
		})
	}

	return suggestions
}

func getBTFFunc() gobpfld.BTFFunc {
	var curFunc gobpfld.BTFFunc

	btf := programs[vm.Registers.PI].GetAbstractProgram().BTF
	for i := range btf.Funcs {
		// If this is the last element
		if i+1 >= len(btf.Funcs) {
			curFunc = btf.Funcs[i]
			break
		}

		ipc := int(btf.Funcs[i].InstructionOffset) / ebpf.BPFInstSize
		npc := int(btf.Funcs[i+1].InstructionOffset) / ebpf.BPFInstSize
		if ipc <= vm.Registers.PC && npc > vm.Registers.PC {
			curFunc = btf.Funcs[i]
			break
		}
	}

	return curFunc
}

func dwarfTypeName(node *EntryNode) string {
	det := progDwarf[vm.Registers.PI]

	e := node.Entry
	if attrType := e.AttrField(dwarf.AttrType); attrType != nil {
		entryType := det.EntitiesByOffset[attrType.Val.(dwarf.Offset)]

		attrName := entryType.Entry.AttrField(dwarf.AttrName)
		if attrName != nil {
			return attrName.Val.(string)
		}

		switch entryType.Entry.Tag {
		case dwarf.TagPointerType:
			return "*" + dwarfTypeName(entryType)
		default:
			panic(fmt.Sprintf("can't find name for %s", entryType.Entry.Tag))
		}
	}

	return ""
}

func fileCompletion(args []string) []prompt.Suggest {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	pathDir := path
	// If it is a directory, show the contents of the directory
	if stat, err := os.Stat(path); err != nil || stat.IsDir() {
		pathDir = filepath.Dir(path)
	}

	// pathDir := filepath.Dir(path)
	dir, err := os.ReadDir(pathDir)
	if err != nil {
		return nil
	}

	fileNames := make([]string, len(dir))
	for i, file := range dir {
		if file.IsDir() {
			fileNames[i] = file.Name() + "/"
		} else {
			fileNames[i] = file.Name()
		}
	}

	pathDir, file := filepath.Split(path)

	ranks := fuzzy.RankFind(file, fileNames)
	sort.Sort(ranks)

	var suggestion []prompt.Suggest
	for _, rank := range ranks {
		var text string
		if pathDir == "" {
			text = rank.Target
		} else {
			text = fmt.Sprintf("%s%s", pathDir, rank.Target)
		}
		suggestion = append(suggestion, prompt.Suggest{
			Text: text,
		})
	}

	return suggestion
}
