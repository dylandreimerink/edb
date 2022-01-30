package debug

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

	blueStrike  = ansi.ColorFunc("blue+s")
	whiteStrike = ansi.ColorFunc("white+s")
)

func init() {
	// TODO sort and group root commands by function, the way delve does it.
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
		cmdBreakpoint,
		cmdContinue,
		cmdContinueAll,
		cmdMacro,
		// TODO add `files` command to list all source files of all or a specific program
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

func getCurBTFLine() *gobpfld.BTFLine {
	return getBTFLine(vm.Registers.PI, vm.Registers.PC)
}

func getBTFLine(programID, instruction int) *gobpfld.BTFLine {
	btf := programs[programID].GetAbstractProgram().BTF
	if btf == nil || len(btf.Lines) == 0 {
		return nil
	}

	rawOffset := instruction * ebpf.BPFInstSize

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

// TODO add a context mechanism, there are situations which can result in infinite loops which currently block
// user input. The only way to stop the program is externally. All commands should accept a context.Context and check
// it periodically and handle cancels, for example from a ctrl-c which is currently ignored until a command is done.
// This could also be combined with a timeout, commands are not exected to run for more than a few seconds. Which
// is a backup in case the user doesn't know about ctrl-c.
// (how would we handle explicitly long running commands? continue-all for example? runtime/file based config?)

func executor(in string) {
	in = strings.TrimSpace(in)

	// Split by space, but keep spaces within quotes("")
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

	// If the input string starts with a comment, don't actually execute
	if strings.HasPrefix(in, "#") || strings.HasPrefix(in, "//") {
		// But if we are recording a macro, add it to the list of commands
		if macroState.rec {
			macroState.recCommands = append(macroState.recCommands, in)
		}
		return
	}

	// Show help if no args were given and non have been executed before
	if len(args) == 0 {
		if len(lastArgs) == 0 {
			helpCmd.Exec(nil)
			return
		}

		// Repeat the last command, this is really helpful if you have to execute it a bunch of times
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

		// TODO return an indication from Exec to save as macro or not. So commands which are invalid are not recorded.

		// If macro recording is enabled, record the full command.
		if macroState.rec {
			// FIXME this is a temporary hack, as soon as commands can tell us to ignore a command for recording
			// we should use that instread and make `macro start` ignore its own addition to the macro
			if !(len(args) >= 2 && args[0] == "macro" && args[1] == "start") {
				// Don't record the `macro start` command in the actual macro
				macroState.recCommands = append(macroState.recCommands, in)
			}
		}

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

	cmds := make([]string, 0, len(cmdList))
	for _, cmd := range cmdList {
		cmds = append(cmds, cmd.Name)
		cmds = append(cmds, cmd.Aliases...)
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
			Text:        rank.Target,
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
