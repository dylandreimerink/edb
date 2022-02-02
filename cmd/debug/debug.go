package debug

import (
	"fmt"

	prompt "github.com/c-bata/go-prompt"
	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/emulator"
	"github.com/spf13/cobra"
)

var (
	vm *emulator.VM

	curCtx   int
	contexts []Context

	entrypoint  int
	programs    []gobpfld.BPFProgram
	progName    []string
	progDwarf   []*DET
	breakpoints []Breakpoint
)

func DebugCmd() *cobra.Command {
	var macroPath string

	debugCmd := &cobra.Command{
		Use:   "debug",
		Short: "debug starts an interactive debug session",
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			vm, err = emulator.NewVM(emulator.DefaultVMSettings())
			if err != nil {
				panic(err)
			}

			if macroPath != "" {
				runMacroExec([]string{macroPath})
			}

			fmt.Println("Type 'help' for list of commands.")

			p := prompt.New(
				executor,
				completer,
				prompt.OptionTitle("eBPF debugger"),
				prompt.OptionPrefix("(edb) "),
				prompt.OptionAddKeyBind(prompt.KeyBind{Key: prompt.ControlC, Fn: func(b *prompt.Buffer) {
					fmt.Println("Ctrl+C disabled, please use the 'quit' or 'exit' command")
				}}),
			)
			p.Run()
		},
	}

	f := debugCmd.Flags()
	f.StringVar(&macroPath, "macro", "", "Path to a macro file which will be executed to setup the session")

	return debugCmd
}
