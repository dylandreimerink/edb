package cmd

import (
	"fmt"
	"os"

	"github.com/dylandreimerink/edb/cmd/capctx"
	"github.com/dylandreimerink/edb/cmd/debug"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "edb",
	Short: "EDB is a debugger for eBPF programs",
}

func Execute() {
	rootCmd.AddCommand(
		debug.DebugCmd(),
		pcapToCtxCommand,
		capctx.Command(),
		graphCommand(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
