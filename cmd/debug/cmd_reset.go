package debug

var cmdReset = Command{
	Name:    "reset",
	Summary: "Reset the registers of the VM",
	Exec: func(args []string) {
		vm.Reset()
		vm.Registers.PI = entrypoint

		if len(contexts) > curCtx {
			vm.Registers.R1 = contexts[0].MemPtr
		}
	},
}
