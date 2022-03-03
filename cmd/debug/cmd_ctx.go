package debug

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/dylandreimerink/mimic"
)

var cmdCtx = Command{
	Name:    "context",
	Aliases: []string{"ctx"},
	Summary: "Context related commands",
	Subcommands: []Command{
		{
			Name:    "list",
			Summary: "List loaded contexts",
			Aliases: []string{"ls"},
			Exec:    listCtxExec,
		},
		{
			Name:    "load",
			Summary: "Load a context JSON file",
			Description: "eBPF programs are called with 'contexts', which are pointers, typically to kernel memory. " +
				"The context contains the information which the eBPF program can use to make decisions, for XDP programs " +
				"this context contains pointers to a network packet, for TC/Socket filter/cGroup SKB programs the context " +
				"is a __sk_buff socket buffer, kProbes get the host CPU registers, ect.\n" +
				"\n" +
				"Since this debugger runs the eBPF program in the userspace emulator, we need to pass our own context " +
				"to the program. Using this command we can load JSON files containing context data into the debugger.\n" +
				"\n" +
				"TODO: describe the JSON format here",
			Aliases:          []string{"ld"},
			Exec:             loadCtxExec,
			CustomCompletion: fileCompletion,
		},
		{
			Name:    "set",
			Summary: "Sets the current context",
			Description: "This command will the the context to be passed into the the program under test. If the " +
				"current program is running(PC > 0 || PI != entrypoint) the change is stored and the actual R1 " +
				"register updated once program execution is reset",
			Exec: setCtxExec,
			Args: []CmdArg{{
				Name:     "context index",
				Required: true,
			}},
			// TODO add custom suggestions, list contexts
		},
	},
}

func listCtxExec(args []string) {
	indexPadSize := len(strconv.Itoa(len(contexts)))
	for i, ctx := range contexts {
		if i == curCtx {
			fmt.Print(green(" => "))
		} else {
			fmt.Print("    ")
		}

		fmt.Print(blue(fmt.Sprintf("%*d ", indexPadSize, i)))
		fmt.Printf("%s\n", ctx.GetName())
	}
}

func setCtxExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'context index'\n")
		return
	}

	id, err := strconv.Atoi(args[0])
	if err != nil {
		printRed("%s\n", err)
		return
	}

	if len(contexts) <= id {
		printRed("No context with id '%d' exists, use 'context list' to see valid options\n", id)
		return
	}

	curCtx = id
	fmt.Printf("Switched current context to '%d' (%s)\n", id, contexts[id].GetName())

	// If we are not in the middle of program execution, reset the VM.
	if process == nil || process.Registers.PC == 0 {
		if process != nil {
			cmdReset.Exec(nil)
		}

		fmt.Printf("VM reset, new context loaded\n")
	} else {
		fmt.Printf("A program is currently running, context not updated, execute 'reset' to update the context\n")
	}
}

func loadCtxExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'program index|program name'\n")
		return
	}

	f, err := os.Open(args[0])
	if err != nil {
		printRed("error opening file: %s\n", err)
		return
	}

	var ctxs []json.RawMessage

	dec := json.NewDecoder(f)
	err = dec.Decode(&ctxs)
	if err != nil {
		printRed("error decoding context file: %s\n", err)
		return
	}

	for i, ctx := range ctxs {
		context, err := mimic.UnmarshalContextJSON(bytes.NewReader(ctx))
		if err != nil {
			printRed("error decoding context %d in context file: %s\n", i, err)
			return
		}

		contexts = append(contexts, context)
	}

	fmt.Printf("%d contexts were loaded\n", len(ctxs))

	// If we are not in the middle of program execution, reset the VM.
	if process != nil && process.Registers.PC == 0 {
		cmdReset.Exec(nil)
	}
}
