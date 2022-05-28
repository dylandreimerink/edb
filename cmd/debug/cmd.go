package debug

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	prompt "github.com/c-bata/go-prompt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/dylandreimerink/mimic"
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
	gray   = ansi.ColorFunc("8")
	cyan   = ansi.ColorFunc("cyan")

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

func getCurBTFLine() string {
	var (
		spec *ebpf.ProgramSpec
		inst int
	)
	if process != nil {
		spec = process.Program
		inst = process.Registers.PC
	}

	return getBTFLine(spec, inst)
}

func getBTFLine(spec *ebpf.ProgramSpec, instruction int) string {
	if spec == nil {
		return ""
	}

	// Walk up, until we found the nearest not empty line
	var line string
	for i := instruction; line == "" && i >= 0; i-- {
		src := spec.Instructions[i].Source()
		if src != nil {
			line = src.String()
		}
	}

	return line
}

func getCurBTFFilename() string {
	var (
		spec *ebpf.ProgramSpec
		inst int
	)
	if process != nil {
		spec = process.Program
		inst = process.Registers.PC
	}

	return getBTFFilename(spec, inst)
}

func getBTFFilename(spec *ebpf.ProgramSpec, instruction int) string {
	if spec == nil {
		return ""
	}

	// Walk up, until we found the nearest not empty filename
	var filename string
	for i := instruction; filename == "" && i >= 0; i-- {
		src := spec.Instructions[i].Source()
		if lineInfo, ok := src.(*btf.Line); ok {
			filename = lineInfo.FileName()
		}
	}

	return filename
}

func getCurBTFLineNumber() int {
	var (
		spec *ebpf.ProgramSpec
		inst int
	)
	if process != nil {
		spec = process.Program
		inst = process.Registers.PC
	}

	return getBTFLineNumber(spec, inst)
}

func getBTFLineNumber(spec *ebpf.ProgramSpec, instruction int) int {
	if spec == nil {
		return 0
	}

	var lineNumber int
	for i := instruction; lineNumber == 0 && i >= 0; i-- {
		src := spec.Instructions[i].Source()
		if lineInfo, ok := src.(*btf.Line); ok {
			lineNumber = int(lineInfo.LineNumber())
		}
	}

	return lineNumber
}

func startProcess() error {
	var ctx mimic.Context
	if len(contexts) > curCtx {
		ctx = contexts[curCtx]
	}

	var err error
	process, err = vm.NewProcess(entrypoint, ctx)
	if err != nil {
		return err
	}

	// TODO make the current CPU ID configurable
	err = process.SetCPUID(0)
	if err != nil {
		return err
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
