package debug

import (
	"fmt"

	prompt "github.com/c-bata/go-prompt"
	"github.com/dylandreimerink/mimic"
	"github.com/spf13/cobra"
)

var (
	vm         *mimic.VM
	vmEmulator *mimic.LinuxEmulator = &mimic.LinuxEmulator{}
	process    *mimic.Process

	curCtx   int
	contexts []mimic.Context

	entrypoint int = 0
	// progDwarf = []*DET{nil}

	breakpoints []Breakpoint
)

func DebugCmd() *cobra.Command {
	var (
		macroPath string
	)

	debugCmd := &cobra.Command{
		Use:   "debug",
		Short: "debug starts an interactive debug session",
		Run: func(cmd *cobra.Command, args []string) {
			vmEmulator = mimic.NewLinuxEmulator()
			vm = mimic.NewVM(mimic.VMOptEmulator(vmEmulator))

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
