package debug

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	prompt "github.com/c-bata/go-prompt"
	"github.com/lithammer/fuzzysearch/fuzzy"
)

var cmdMacro = Command{
	Name:    "macro",
	Aliases: []string{"mc"},
	Summary: "Macros allow you to execute a series of commands",
	Description: "You might encounter a situation in which you would like to combine multiple commands so you can " +
		"repeately execute them by pressing <enter>. Macros can also be useful if you find that you have to do a lot " +
		"of setup work for a specific program(loading the ELF, changing entrypoint, setting map values). In such " +
		"cases being able to execute a macro from a file can save a lot of time.",
	Subcommands: []Command{
		{
			Name:    "list",
			Aliases: []string{"ls"},
			Summary: "List all loaded macros",
			Exec:    listMacroExec,
		},
		{
			Name:    "show",
			Summary: "Shows the commands in a macro",
			Exec:    showMacroExec,
			Args: []CmdArg{{
				Name:     "name",
				Required: true,
			}},
			CustomCompletion: macroCompletion,
		},
		{
			Name:    "start",
			Summary: "Start recording a macro",
			Exec:    startRecordingMacroExec,
			Args: []CmdArg{{
				Name:     "name",
				Required: true,
			}},
		},
		{
			Name:    "stop",
			Summary: "Stop recording a macro",
			Exec:    stopRecordingMacroExec,
		},
		{
			Name:    "save",
			Summary: "Save a macro to a file",
			Exec:    saveMacroExec,
			Args: []CmdArg{
				{
					Name:     "macro name",
					Required: true,
				},
				{
					Name:     "file path",
					Required: false,
				},
			},
			CustomCompletion: func(args []string) []prompt.Suggest {
				if len(args) == 1 {
					return macroCompletion(args)
				}
				return fileCompletion(args[1:])
			},
		},
		{
			Name:    "load",
			Summary: "Load macro(s) from a file",
			Exec:    loadMacroExec,
			Args: []CmdArg{
				{
					Name:     "file path",
					Required: true,
				},
			},
			CustomCompletion: fileCompletion,
		},
		{
			Name:    "un-load",
			Summary: "Unloads a macro, permanently deleting it if not saved",
			Exec:    unloadMacroExec,
			Args: []CmdArg{
				{
					Name:     "name",
					Required: true,
				},
			},
			CustomCompletion: macroCompletion,
		},
		{
			Name:    "exec",
			Summary: "Execute a macro",
			Exec:    execMacroExec,
			Args: []CmdArg{
				{
					Name:     "name",
					Required: true,
				},
			},
			CustomCompletion: macroCompletion,
		},
		{
			Name:    "run",
			Summary: "Parses a macro file and runs all macros within",
			Description: "This command runs the macros in a file but doesn't load them. The purpose of this is to " +
				"allow a user to create a sort of init macro which loads a set of permanent macro files or just sets " +
				"up the session",
			Exec: runMacroExec,
			Args: []CmdArg{
				{
					Name:     "file path",
					Required: true,
				},
			},
			CustomCompletion: fileCompletion,
		},
		{
			Name:    "set",
			Summary: "Sets a line within a macro",
			Description: "Set a new line or overwrite an existing one, allows you to quickly modify a loaded macro" +
				"in case any mistakes were made during recording",
			Exec: setMacroExec,
			Args: []CmdArg{
				{
					Name:     "name",
					Required: true,
				},
				{
					Name:     "line number",
					Required: true,
				},
				{
					Name:     "line",
					Required: true,
				},
			},
			CustomCompletion: func(args []string) []prompt.Suggest {
				if len(args) < 2 {
					return macroCompletion(args)
				}
				return nil
			},
		},
		{
			Name:    "del",
			Summary: "Deletes a line from a macro",
			Description: "delete an existing line from a macro, allows you to quickly modify a loaded macro" +
				"in case any mistakes were made during recording",
			Exec: delMacroExec,
			Args: []CmdArg{
				{
					Name:     "name",
					Required: true,
				},
				{
					Name:     "line number",
					Required: true,
				},
			},
			CustomCompletion: func(args []string) []prompt.Suggest {
				if len(args) < 2 {
					return macroCompletion(args)
				}
				return nil
			},
		},
	},
}

var macroState = struct {
	loadedMacros map[string]*Macro

	rec         bool
	recName     string
	recCommands []string
}{
	loadedMacros: make(map[string]*Macro),
}

type Macro struct {
	File     string
	Saved    bool
	Commands []string
}

func listMacroExec(args []string) {
	for name, m := range macroState.loadedMacros {
		fmt.Printf("%s(%d)", blue(name), len(m.Commands))
		if m.File != "" {
			fmt.Printf(" - %s", m.File)
		}

		if m.Saved {
			fmt.Printf(" [%s]\n", green("saved"))
		} else {
			fmt.Printf(" [%s]\n", red("not-saved"))
		}
	}
}

func showMacroExec(args []string) {
	if len(args) < 1 || args[0] == "" {
		printRed("Missing required argument 'name'\n")
		return
	}

	m, found := macroState.loadedMacros[args[0]]
	if !found {
		printRed("No macro with name '%s' exists, use 'macro list' to see valid options\n", args[0])
		return
	}

	indexPadSize := len(strconv.Itoa(len(m.Commands)))
	for i, c := range m.Commands {
		// Color comments green
		if strings.HasPrefix(c, "#") {
			c = green(c)
		}

		fmt.Printf("%s %s\n",
			blue(fmt.Sprintf("%*d", indexPadSize, i)),
			c,
		)
	}
}

func runMacroExec(args []string) {
	if len(args) < 1 || args[0] == "" {
		printRed("Missing required argument 'file path'\n")
		return
	}

	filePath := args[0]
	f, err := os.Open(args[0])
	if err != nil {
		printRed("Error while opening file: %s\n", err)
		return
	}
	defer f.Close()

	mf, err := parseMacroFile(f)
	if err != nil {
		printRed("Error while parsing file: %s\n", err)
		return
	}

	for _, m := range mf.Macros() {
		runMacro(&Macro{
			File:     filePath,
			Saved:    false,
			Commands: m.Commands,
		})
	}

	// The executor will overwrite the lastArgs with the last actual command executed.
	// Change it back to the run macro command so we can run the macro file multiple times just by pressing
	// <enter> again.
	lastArgs = []string{"macro", "run", filePath}
}

func runMacro(macro *Macro) {
	for _, command := range macro.Commands {
		printCmd := command
		// If the command is a comment, color it green to make it visually distinct from an actual command
		if strings.HasPrefix(printCmd, "#") {
			printCmd = green(printCmd)
		}

		// Display the commend, with edb prefix to mimic prefix we get while prompting
		fmt.Printf("%s %s\n", blue("(edb)"), printCmd)
		// Execute the command
		executor(command)
	}
}

func execMacroExec(args []string) {
	if len(args) < 1 || args[0] == "" {
		printRed("Missing required argument 'name'\n")
		return
	}

	macro, found := macroState.loadedMacros[args[0]]
	if !found {
		printRed("No macro with name '%s' exists, use 'macro list' to see valid options\n", args[0])
		return
	}

	runMacro(macro)

	// The executor will overwrite the lastArgs with the last actual command executed.
	// Change it back to the execute macro command so we can execute the macro multiple times just by pressing
	// <enter> again.
	lastArgs = []string{"macro", "exec", args[0]}
}

func setMacroExec(args []string) {
	if len(args) < 1 || args[0] == "" {
		printRed("Missing required argument 'name'\n")
		return
	}

	if len(args) < 2 || args[1] == "" {
		printRed("Missing required argument 'line number'\n")
		return
	}

	if len(args) < 3 {
		printRed("Missing required argument 'line'\n")
		return
	}

	macro, found := macroState.loadedMacros[args[0]]
	if !found {
		printRed("No macro with name '%s' exists, use 'macro list' to see valid options\n", args[0])
		return
	}

	lineNum, err := strconv.Atoi(args[1])
	if err != nil {
		printRed("Invalid line number: %s\n", args[1])
		return
	}

	if lineNum < 0 {
		printRed("Line number can't be negative")
		return
	}

	lineArgs := args[2:]

	// Any quotes are lost during argument parsing, if any arguments contain spaces, meaning they were input with
	// quotes, re-add them.
	for i, arg := range lineArgs {
		if strings.Contains(arg, " ") {
			lineArgs[i] = fmt.Sprintf(`"%s"`, arg)
		}
	}

	line := strings.Join(lineArgs, " ")

	// Macro is modified, mark it as unsaved
	macro.Saved = false

	// Append if lineNum is greater the existing
	if lineNum >= len(macro.Commands) {
		macro.Commands = append(macro.Commands, line)
	} else {
		// Overwrite otherwise
		macro.Commands[lineNum] = line
	}

	// Show the edited macro afterwards as user feedback
	showMacroExec([]string{args[0]})
}

func delMacroExec(args []string) {
	if len(args) < 1 || args[0] == "" {
		printRed("Missing required argument 'name'\n")
		return
	}

	if len(args) < 2 || args[1] == "" {
		printRed("Missing required argument 'line number'\n")
		return
	}

	macro, found := macroState.loadedMacros[args[0]]
	if !found {
		printRed("No macro with name '%s' exists, use 'macro list' to see valid options\n", args[0])
		return
	}

	lineNum, err := strconv.Atoi(args[1])
	if err != nil {
		printRed("Invalid line number: %s\n", args[1])
		return
	}

	if lineNum < 0 {
		printRed("Line number can't be negative\n")
		return
	}

	if lineNum >= len(macro.Commands) {
		printRed("Line number out of bounds\n")
		showMacroExec([]string{args[0]})
		return
	}

	// Macro is modified, mark it as unsaved
	macro.Saved = false

	// Append if lineNum is greater the existing
	if lineNum < len(macro.Commands) {
		// Copy all values after the line to be deleted over the line
		copy(macro.Commands[lineNum:], macro.Commands[lineNum+1:])
		// Shrink slice
		macro.Commands = macro.Commands[:len(macro.Commands)-1]
	}

	// Show the edited macro afterwards as user feedback
	showMacroExec([]string{args[0]})
}

func unloadMacroExec(args []string) {
	if len(args) < 1 || args[0] == "" {
		printRed("Missing required argument 'name'\n")
		return
	}

	_, found := macroState.loadedMacros[args[0]]
	if !found {
		printRed("No macro with name '%s' exists, use 'macro list' to see valid options\n", args[0])
		return
	}

	delete(macroState.loadedMacros, args[0])

	fmt.Println("Macro un-loaded")
}

func startRecordingMacroExec(args []string) {
	if len(args) < 1 || args[0] == "" {
		printRed("Missing required argument 'name'\n")
		return
	}

	name := args[0]
	_, exists := macroState.loadedMacros[name]
	if exists {
		printRed("Macro with name '%s' already\n", name)
		return
	}

	if macroState.rec {
		printRed("Already recording a macro!\n")
		return
	}

	macroState.rec = true
	macroState.recName = name
	macroState.recCommands = nil

	fmt.Println("Macro now recoding")
}

func stopRecordingMacroExec(args []string) {
	if !macroState.rec {
		printRed("Macro recoding already disabled\n")
		return
	}

	macroState.rec = false

	macroState.loadedMacros[macroState.recName] = &Macro{
		Saved:    false,
		Commands: macroState.recCommands,
	}

	fmt.Println("Macro recoding stopped")
}

func saveMacroExec(args []string) {
	if len(args) < 1 || args[0] == "" {
		printRed("Missing required argument 'macro name'\n")
		return
	}

	macroName := args[0]

	macro, found := macroState.loadedMacros[args[0]]
	if !found {
		printRed("No macro with name '%s' exists, use 'macro list' to see valid options\n", macroName)
		return
	}

	if macro.File == "" {
		if len(args) < 2 || args[1] == "" {
			printRed("Macro '%s' has no associated filepath, to save it you have to provide one\n", macroName)
			return
		}
	}

	if len(args) >= 2 && args[1] != "" {
		macro.File = args[1]
	}

	_, err := os.Stat(macro.File)
	exists := err == nil

	f, err := os.OpenFile(macro.File, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		printRed("Error opening file: %s\n", err)
		return
	}
	defer f.Close()

	mf, err := parseMacroFile(f)
	if err != nil {
		printRed("Error parsing file: %s\n", err)
		return
	}

	// If the file already existed, but no magic str was set, this might be a non-macro file like an important config
	// file. To guard users from accidental corruption, only overwrite files which we know to likely be macro files
	if exists && !mf.HasMagic {
		printRed("File already exists but doesn't start with '%s', this might be non-macro file.\n"+
			"If this is a macro file, please add the comment to the start of the file.\n", magicMacroStr)
		return
	}

	// Seek back to the start of the file so we can re-write it later
	_, err = f.Seek(0, 0)
	if err != nil {
		printRed("Error seeking to start of file: %s\n", err)
		return
	}
	// Truncate the whole file
	err = f.Truncate(0)
	if err != nil {
		printRed("Error truncating file: %s\n", err)
		return
	}

	// Overwrite only the macro with the given name in the file
	overwritten := false
	for _, part := range mf.Parts {
		md, ok := part.(*macroDefinition)
		if !ok {
			continue
		}

		if md.Name != macroName {
			continue
		}

		md.Commands = macro.Commands
		overwritten = true
		break
	}

	// If we didn't find a macro, it is new, so append it to the file
	if !overwritten {
		mf.Parts = append(mf.Parts, &macroDefinition{
			Name:     macroName,
			Commands: macro.Commands,
		})
	}

	// Rewrite file
	err = mf.save(f)
	if err != nil {
		printRed("Error writing to file: %s\n", err)
		return
	}

	macro.Saved = true

	fmt.Println("Macro saved to file")
}

func loadMacroExec(args []string) {
	if len(args) < 1 || args[0] == "" {
		printRed("Missing required argument 'file path'\n")
		return
	}

	f, err := os.Open(args[0])
	if err != nil {
		printRed("Error while opening file: %s\n", err)
		return
	}
	defer f.Close()

	mf, err := parseMacroFile(f)
	if err != nil {
		printRed("Error while parsing file: %s\n", err)
		return
	}

	for _, m := range mf.Macros() {
		existingMacro, exists := macroState.loadedMacros[m.Name]
		if exists && !existingMacro.Saved {
			printRed("Macro '%s' not loaded since it would overwrite an unsaved macro of the same name\n", m.Name)
			continue
		}

		macroState.loadedMacros[m.Name] = &Macro{
			File:     args[0],
			Saved:    true,
			Commands: m.Commands,
		}

		fmt.Printf("Macro '%s' loaded\n", m.Name)
	}
}

// macroFile defines the structure of a macro file, which can consist of a part.
// The goal of the file is to preserve comments placed in the file, both inside and outside a macro definition
type macroFile struct {
	// If HasMagic is true, it means the parsed file started with the magicMacroStr.
	// If HasMagic is false, the original file might have been a non-macro file and it should not be overwritten
	// to avoid corrupting files
	HasMagic bool
	Parts    []macroFilePart
}

const magicMacroStr = "# edb macro file, don't remove this comment"

// save doesn't honer the formatting of the original file, just writes a "neat" version
func (mf *macroFile) save(w io.Writer) error {
	// Write magic macro file header
	_, err := fmt.Fprintln(w, magicMacroStr)
	if err != nil {
		return fmt.Errorf("write part: %w", err)
	}

	for _, p := range mf.Parts {
		_, err = fmt.Fprint(w, p.MacroString())
		if err != nil {
			return fmt.Errorf("write part: %w", err)
		}
	}

	return nil
}

// Macros returns all file macros and skips other parts
func (mf *macroFile) Macros() []*macroDefinition {
	var m []*macroDefinition

	for _, p := range mf.Parts {
		mp, ok := p.(*macroDefinition)
		if !ok {
			continue
		}

		m = append(m, mp)
	}

	return m
}

// macroFilePart is any part which can produce a string and may be part of the macro file
type macroFilePart interface {
	MacroString() string
}

// macroDefinition represents the definition of a macro, which is a name, followed by a semicolon(:) and a list of
// other macroFileParts. Namely commands and comments. empty lines are not allowed, they indicate the end of a macro.
type macroDefinition struct {
	Name     string
	Commands []string
}

func (fm *macroDefinition) MacroString() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%s:\n", fm.Name))
	for _, c := range fm.Commands {
		sb.WriteString(" ")
		sb.WriteString(c)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	return sb.String()
}

// Macro comment is a line of comments, starting with a # or //, though only the # version is written back.
// Empty comments are allowed to add spacing of a sort
type macroComment string

func (mc macroComment) MacroString() string {
	return fmt.Sprintf("# %s\n", mc)
}

func parseMacroFile(r io.Reader) (*macroFile, error) {
	br := bufio.NewReader(r)

	var macroFile macroFile
	var curMacroDef *macroDefinition
	firstLine := true
	for {
		line, _, err := br.ReadLine()
		if err != nil {
			// Stop parsing of there are no more lines
			if err == io.EOF {
				break
			}

			return nil, fmt.Errorf("read line: %w", err)
		}

		// Check if the first line of the file contains the magic string. If it doesn't we still want to continue
		// parsing since we don't want users to have to write it when creating a macro file from scratch.
		// But code which overwrites existing files should only do so if the original was marked with the magic str.
		if firstLine {
			firstLine = false
			if string(line) == magicMacroStr {
				macroFile.HasMagic = true
				continue
			}
		}

		lineStr := strings.TrimSpace(string(line))

		// Empty lines are the end of a macro
		if lineStr == "" {
			// If there is a current macro, submit it
			if curMacroDef != nil {
				macroFile.Parts = append(macroFile.Parts, curMacroDef)
				curMacroDef = nil
			}

			continue
		}

		// If it is a comment
		if strings.HasPrefix(lineStr, "#") || strings.HasPrefix(lineStr, "//") {
			lineStr = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(lineStr, "//"), "#"))

			// if the is no current macro, add comment to the file
			if curMacroDef == nil {
				macroFile.Parts = append(macroFile.Parts, macroComment(lineStr))
				continue
			}

			// There is a current macro, make the comment "nice" and add it to the file as a # command which
			// will be interperted as a comment
			curMacroDef.Commands = append(
				curMacroDef.Commands,
				fmt.Sprintf("# %s", strings.TrimSpace(strings.TrimPrefix(lineStr, "#"))),
			)
			continue
		}

		// If new name
		if strings.HasSuffix(lineStr, ":") {
			// If there is a current macro, submit it
			if curMacroDef != nil {
				macroFile.Parts = append(macroFile.Parts, curMacroDef)
			}

			// Make new part with new name
			curMacroDef = &macroDefinition{
				Name: strings.TrimSpace(strings.TrimSuffix(lineStr, ":")),
			}

			continue
		}

		// If there is a definition, add the line as a commend, if outside of a definition discard the line
		if curMacroDef != nil {
			curMacroDef.Commands = append(curMacroDef.Commands, lineStr)
		}
	}

	// If there still is a pending macro, submit it
	if curMacroDef != nil {
		macroFile.Parts = append(macroFile.Parts, curMacroDef)
	}

	return &macroFile, nil
}

func macroCompletion(args []string) []prompt.Suggest {
	var macroNames []string
	for name := range macroState.loadedMacros {
		macroNames = append(macroNames, name)
	}

	if len(args) == 0 {
		var suggestion []prompt.Suggest
		sort.Strings(macroNames)
		for _, name := range macroNames {
			suggestion = append(suggestion, prompt.Suggest{
				Text: name,
			})
		}
		return suggestion
	}

	ranks := fuzzy.RankFind(args[0], macroNames)
	sort.Sort(ranks)

	var suggestion []prompt.Suggest
	for _, rank := range ranks {
		suggestion = append(suggestion, prompt.Suggest{
			Text: rank.Target,
		})
	}

	return suggestion
}
