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

var DebugCmd = &cobra.Command{
	Use:   "debug",
	Short: "debug starts an interactive debug session",
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		vm, err = emulator.NewVM(emulator.DefaultVMSettings())
		if err != nil {
			panic(err)
		}

		fmt.Println("Type 'help' for list of commands.")

		if len(args) > 1 {
			loadExec(args[1:])
		}

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
