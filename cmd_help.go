package main

import (
	"fmt"
	"strings"
)

var cmdMaps map[*[]Command]map[string]Command

func commandMap(cmds *[]Command) map[string]Command {
	if cmdMaps == nil {
		cmdMaps = make(map[*[]Command]map[string]Command)
	}

	if m, exists := cmdMaps[cmds]; exists {
		return m
	}

	commandMap := make(map[string]Command)
	for _, cmd := range *cmds {
		commandMap[cmd.Name] = cmd
		for _, alias := range cmd.Aliasses {
			commandMap[alias] = cmd
		}
	}
	cmdMaps[cmds] = commandMap
	return commandMap
}

var helpCmd = Command{
	Name:        "help",
	Aliasses:    []string{"h"},
	Summary:     "Show help text / available commands",
	Description: "Show all a summary of all commands or detailed help for the specified command",
	Exec:        helpExec,
	Args: []CmdArg{{
		Name:     "command",
		Required: false,
	}},
}

func helpExec(args []string) {
	printCmds := func(cmds []Command) {
		for _, cmd := range cmds {
			name := cmd.Name
			if len(cmd.Aliasses) > 1 {
				name = fmt.Sprintf("%s (Aliasses: %s)", cmd.Name, strings.Join(cmd.Aliasses, ", "))
			} else if len(cmd.Aliasses) == 1 {
				name = fmt.Sprintf("%s (Alias: %s)", cmd.Name, cmd.Aliasses[0])
			}

			padLen := 40 - len(name)
			if padLen < 0 {
				padLen = 0
			}

			fmt.Printf("  %s %s %s\n", name, strings.Repeat("-", padLen), cmd.Summary)
		}
	}

	var helpCmd func(cmds *[]Command, args []string) bool
	helpCmd = func(cmds *[]Command, args []string) bool {
		cmd, ok := commandMap(cmds)[args[0]]
		if !ok {
			return false
		}

		// Cut the name of the current command
		args = args[1:]

		// If this command has sub commands and we have arguments left, show help for the sub-command instread
		if len(cmd.Subcommands) > 0 && len(args) > 0 {
			// If we were not able to find a sub command for the given args, show the help for this command anyway
			if helpCmd(&cmd.Subcommands, args) {
				return true
			}
		}

		fmt.Printf("%s ", cmd.Name)

		// A command can't have subcommands and arguments since the first arg will be the name of the sub command
		// and all others args for the sub command
		if len(cmd.Subcommands) > 0 {
			fmt.Printf("{sub-command} ")
		} else {
			for _, arg := range cmd.Args {
				if arg.Required {
					fmt.Printf("{%s} ", arg.Name)
				} else {
					fmt.Printf("[%s] ", arg.Name)
				}
			}
		}

		fmt.Printf("- %s\n", cmd.Summary)
		fmt.Println(cmd.Description)

		if len(cmd.Subcommands) > 0 {
			fmt.Println("Sub commands:")
			printCmds(cmd.Subcommands)
		}

		return true
	}

	if len(args) > 0 {
		if helpCmd(&rootCommands, args) {
			return
		}
	}

	fmt.Println("Commands:")
	printCmds(rootCommands)
}
