package debug

var cmdReset = Command{
	Name:    "reset",
	Summary: "Reset the registers of the VM",
	Exec: func(args []string) {
		if process != nil {
			err := process.Cleanup()
			if err != nil {
				printRed("%s\n", err)
			}
		}

		// Start a new process
		err := startProcess()
		if err != nil {
			printRed("%s\n", err)
		}
	},
}
