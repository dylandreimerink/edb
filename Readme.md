# EDB (eBPF debugger)

`edb` is a debugger(like gdb and dlv) for eBPF programs. Normally eBPF programs are loaded into the Linux kernel and then executed, this makes it difficult to understand what is happening or why things go wrong. For normal applications we can use gdb or dlv to inspect programs, but these don't work for the eBPF due to the way eBPF is loaded into the kernel.

`edb` uses userspace eBPF emulation to run eBPF programs instead of loading them into the kernel, this allows us to debug them like any other program. Altho this method is not perfect due to possible differences between the emulator and actual Linux machines, it is better than nothing.

## Installation

**Installation via go** `go install github.com/dylandreimerink/edb@latest`

## Usage

Starting a debug session:
```
EDB is a debugger for eBPF programs

Usage:
  edb [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  debug       debug starts an interactive debug session
  help        Help about any command
  pcap-to-ctx Convert a PCAP(packet capture) file into a context file which can be passed to a XDP eBPF program

Flags:
  -h, --help   help for edb

Use "edb [command] --help" for more information about a command.
```

### Debugger commands

```
Commands:
  help (Alias: h) ------------------------- Show help text / available commands
  exit (Aliases: q, quit) ----------------- Exits the debugger
  clear ----------------------------------- Clear the screen
  load ------------------------------------ Load an ELF file
  context (Alias: ctx) -------------------- Context related commands
  program (Alias: prog) ------------------- Program related commands
  reset ----------------------------------- Reset the registers of the VM
  registers (Aliases: r, regs) ------------ Show registers
  step-instruction (Alias: si) ------------ Step through the program one instruction a time
  list-instructions (Alias: li) ----------- Lists the instructions of the program
  step (Alias: s) ------------------------- Step through the program one line a time
  list (Alias: ls) ------------------------ Lists the lines of the source code
  map (Alias: maps) ----------------------- Map related operations
  locals (Alias: lv) ---------------------- Lists the local variables
  memory (Alias: mem) --------------------- Show the contents of memory
  breakpoint (Aliases: b, br, bp, break) -- Commands related to breakpoints
  continue (Alias: c) --------------------- Continue execution of the program until it exits or a breakpoint is hit
  continue-all (Alias: ca) ---------------- Continue execution of the program for all contexts
```

## Desired features

- Memory modification - we can currently view memory, but there is no way to modify it, would be nice if we could change memory contents.
- Local variable inspection - we already can list local variables, but we have to somehow figure out in which register/memory location its value lives and how to print it based on its type.
- Breakpoints
  - Display markers for breakpoints in `list` and `list-instructions`
  - `breakpoint set {line-ref} {condition (r1=0x1234)}` Conditional breakpoints
  - `breakpoint set-log {line-ref} {message}` - Set Unconditional logging breakpoint
  - `breakpoint set-log {line-ref} {condition (r1=0x1234)} {message}` set conditional logging breakpoint
- `reset-maps` command - resets the contents of the maps
- Load ctx files with cli flag
- `map read {key}` command to read a specific map value
- `map write {key} {value}` command to write a value to a map
- `map delete {key}` command to delete a value from a map
- `source` command to execute a series for commands from a file, to automate complex debugging setups.
- DAP(Debug Adaptor Protocol) support for debugging from VSCode
- C Syntax highlighting (what about when sources are not C? Maybe IDE/Editor integration is a better way to go)
- Actual map backing - We could optionally use actual BPF maps instead of emulated maps. Enabling this option would only be possible on linux since other OS'es won't have actual eBPF support. The big pro is that, in an environment with multiple eBPF programs, you could run 1 in debug mode and still be able to communicate with the eBPF programs loaded in the kernel. Another pro could be (if possible) that an actual userspace program can interact with the eBPF program like it would when loaded in the kernel. 
- Context capture command - We should be able to make an eBPF program for each program type which captures the context that is passed in by the actual kernel, copy it to a PERF buffer or ringbuffer and then turn it into a ctx.json file to be used by the debugger.
- "Live mode/trace mode" - So in theory if we have "context capture command" working, why not directly directly connect its output to a running debugger session? That would be the most "real" experience. If we also combine this with actual eBPF maps as backing, and the only difference would be that the emulated program can't react, it is readonly. It might be a good idea to "trace" execution, so disabling breakpoints but recording all actions the program took, which we can later load into a debug session to inspect. 