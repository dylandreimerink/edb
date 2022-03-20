# EDB (eBPF debugger)

`edb` is a debugger(like gdb and dlv) for eBPF programs. Normally eBPF programs are loaded into the Linux kernel and then executed, this makes it difficult to understand what is happening or why things go wrong. For normal applications we can use gdb or dlv to inspect programs, but these don't work for the eBPF due to the way eBPF is loaded into the kernel.

`edb` uses userspace eBPF [emulation](https://github.com/dylandreimerink/mimic#mimic-ebpf-userspace-emulator) to run eBPF programs instead of loading them into the kernel, this allows us to debug them like any other program. Altho this method is not perfect due to possible differences between the emulator and actual Linux machines, it is better than nothing.

>**WARNING/NOTE** This project is still a work in progress, so is the emulator on which it runs. Not all eBPF programs might run inside the debugger or some features might be missing. Please take a look at the [TODO](#TODO) of this projects and the [TODO](https://github.com/dylandreimerink/mimic#features--todo) of the emulator for a list of missing features.

## Installation

### Clone and install

Currently installing the old-school is the only way to install `edb`. Using `go install` on the URL doesn't work due to our dependency on the replace directives in go.mod 

```bash
git clone https://github.com/dylandreimerink/edb.git
cd edb
go install .
```

### Binary release

`edb` is still in an early stage and is changing quickly, as soon as `edb` is more "stable" we hope to start releasing somewhat polished binaries at a decent interval.

## Usage

```
EDB is a debugger for eBPF programs

Usage:
  edb [command]

Available Commands:
  capture-context Capture program contexts
  completion      Generate the autocompletion script for the specified shell
  debug           debug starts an interactive debug session
  graph           Generate a control-flow graph for an eBPF program
  help            Help about any command
  pcap-to-ctx     Convert a PCAP(packet capture) file into a context file which can be passed to a XDP eBPF program

Flags:
  -h, --help   help for edb

Use "edb [command] --help" for more information about a command.
```

### `edb debug` interactive debugger

Use the `help` command to get a list of all top level commands. You can get more details about a command by passing its name like `help help` or `help program`
```
(edb) help
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
  memory (Alias: mem) --------------------- Show the contents of memory
  breakpoint (Aliases: b, br, bp, break) -- Commands related to breakpoints
  continue (Alias: c) --------------------- Continue execution of the program until it exits or a breakpoint is hit
  continue-all (Alias: ca) ---------------- Continue execution of the program for all contexts
  macro (Alias: mc) ----------------------- Macros allow you to execute a series of commands
```

```
(edb) help context
context {sub-command} - Context related commands

Sub commands:
  list (Alias: ls) ------------------------ List loaded contexts
  load (Alias: ld) ------------------------ Load a context JSON file
  set ------------------------------------- Sets the current context
```

```
(edb) help program
program {sub-command} - Program related commands

Sub commands:
  list (Alias: ls) ------------------------ List all loaded programs
  set ------------------------------------- Sets the entrypoint program
```

```
(edb) help map
map {sub-command} - Map related operations

Sub commands:
  list (Alias: ls) ------------------------ Lists all loaded maps
  read-all -------------------------------- Reads and displays all keys and values
  get ------------------------------------- Get the value of a particular key in a map
  set ------------------------------------- Set a value at a particular spot in a map
  del ------------------------------------- Delete a value from a map with the given key
  push (Alias: enqueue) ------------------- Push/enqueue a value into the map
  pop (Alias: dequeue) -------------------- Pop/dequeue a value from the map, this shows and deletes the value
```

```
(edb) help memory
memory {sub-command} - Show the contents of memory

Sub commands:
  list (Alias: ls) ------------------------ List all memory objects and their addresses
  read ------------------------------------ Read the contents of a specific virtual address
  read-all -------------------------------- Read and show the whole contents of addressable memory
```

```
(edb) help breakpoint
breakpoint {sub-command} - Commands related to breakpoints

Sub commands:
  list (Alias: ls) ------------------------ List all breakpoints
  set (Alias: add) ------------------------ Set a new breakpoint
  enable ---------------------------------- Enable a breakpoint
  disable --------------------------------- Disable a breakpoint
```

```
(edb) help macro
macro {sub-command} - Macros allow you to execute a series of commands
You might encounter a situation in which you would like to combine multiple commands so you can repeately execute them by pressing <enter>. Macros can also be useful if you find that you have to do a lot of setup work for a specific program(loading the ELF, changing entrypoint, setting map values). In such cases being able to execute a macro from a file can save a lot of time.
Sub commands:
  list (Alias: ls) ------------------------ List all loaded macros
  show ------------------------------------ Shows the commands in a macro
  start ----------------------------------- Start recording a macro
  stop ------------------------------------ Stop recording a macro
  save ------------------------------------ Save a macro to a file
  load ------------------------------------ Load macro(s) from a file
  un-load --------------------------------- Unloads a macro, permanently deleting it if not saved
  exec ------------------------------------ Execute a macro
  run ------------------------------------- Parses a macro file and runs all macros within
  set ------------------------------------- Sets a line within a macro
  del ------------------------------------- Deletes a line from a macro
```

### `edb graph`

```
This command reads the provided ELF file and creates a control-flow graph for the given program. The program is broken up into 'blocks' of code by BPF-to-BPF function calls and branching instructions. Red arrows indicate the non-branching path, green arrows indicate the branching path, yellow arrows indicate bpf-to-bpf function calls(which will return and then follow the non-branching path).

If no flags are specified the command will attempt to render the graph as SVG and open it in the browser.

Usage:
  edb graph {ELF} {program name} [flags]

Flags:
  -f, --format string   The output format: dot, svg, pdf or png (default "svg")
  -h, --help            help for graph
  -o, --output string   output to given file path or - for stdout, instread of opening in browser
```
<img src="./img/graph-bpf-to-bpf.png" width="30%" /><img 
src="./img/graph-map-in-map.png" width="30%" /><img 
src="./img/graph-stack.png" width="30%" />

### `edb pcap-to-ctx`
```
Convert a PCAP(packet capture) file into a context file which can be passed to a XDP eBPF program

Usage:
  edb pcap-to-ctx {.pcap input} {.json ctx output} [flags]

Flags:
  -h, --help   help for pcap-to-ctx
```

Usage example:
```bash
tcpdump -i eth0 -w example.pcap
edb pcap-to-ctx example.pcap example.ctx.json
edb debug
Type 'help' for list of commands.
(edb) ctx load example.ctx.json
43 contexts were loaded
(edb) ctx list
 =>  0 2022-01-25 20:11:16.471543 +0000 UTC (xdp_md + 0)
     1 2022-01-25 20:11:16.715942 +0000 UTC (xdp_md + 0)
     2 2022-01-25 20:11:16.717875 +0000 UTC (xdp_md + 0)
     3 2022-01-25 20:11:16.87141 +0000 UTC (xdp_md + 0)
    ...
    41 2022-01-25 20:11:19.120006 +0000 UTC (xdp_md + 0)
    42 2022-01-25 20:11:19.120006 +0000 UTC (xdp_md + 0)
```

### `edb capture-context`


## TODO

A list of features which would be great to have. This debugger relies on a eBPF emulator which lives in a seperate repository and also has its own [TODO](https://github.com/dylandreimerink/gobpfld/blob/master/emulator/todo.md) list which directly impacts the abilities of `edb`. 

Any contributions are welcome. 

- Memory modification - we can currently view memory, but there is no way to modify it, would be nice if we could change memory contents.
- Local variable inspection - we already can list local variables, but we have to somehow figure out in which register/memory location its value lives and how to print it based on its type.
- Breakpoints
  - Display markers for breakpoints in `list` and `list-instructions`
  - `breakpoint set {line-ref} {condition (r1=0x1234)}` Conditional breakpoints
  - `breakpoint set-log {line-ref} {message}` - Set Unconditional logging breakpoint
  - `breakpoint set-log {line-ref} {condition (r1=0x1234)} {message}` set conditional logging breakpoint
- `reset-maps` command - resets the contents of the maps
- `map export` command to export the contents of a map to a file or to a pined map with the same definition. The idea being that you could run your program and then export the output so it can be interpreted by a userspace application.
- Optional kernel verification - It would be nice to attempt to load the program into the kernel to get the verifiers opinion of the program. The debugger might then interpret the verifier log and more clearly show or explain why the program was rejected.
- Choice between Clang/LLVM style assembly and ebpf/asm style assembly
- Debug xlated instructions - The verifier will in some cases changed the actual program instructions(xlated) to add additional runtime checks, by loading a program into the kernel and reading back the xlated instruction we can more closely replicate what actually happens in the kernel.
- Profiling / tracing - This would not be accurate performance wise, but it might be informative to see which code paths get covered the most. So perhaps something more like code-coverage reporting. Another idea is to provide "calibration" data, would work something like: 1. create a BPF program with just a single instruction and benchmark how long execution of that single instruction takes on average(using the BPF test feature), 2. repeat step 1 for each instruction(in the current program or just overall) and store results in a calibration file, 3. use a calibration file (from localhost or a production setup) and apply it to our custom trace to get more realistic profiles.
- DAP(Debug Adaptor Protocol) support for debugging from VSCode
- C Syntax highlighting (what about when sources are not C? Maybe IDE/Editor integration is a better way to go)
- Actual map backing - We could optionally use actual BPF maps instead of emulated maps. Enabling this option would only be possible on linux since other OS'es won't have actual eBPF support. The big pro is that, in an environment with multiple eBPF programs, you could run 1 in debug mode and still be able to communicate with the eBPF programs loaded in the kernel. Another pro could be (if possible) that an actual userspace program can interact with the eBPF program like it would when loaded in the kernel. 
- Context capture command - We should be able to make an eBPF program for each program type which captures the context that is passed in by the actual kernel, copy it to a PERF buffer or ringbuffer and then turn it into a ctx.json file to be used by the debugger.
- "Live mode/trace mode" - So in theory if we have "context capture command" working, why not directly connect its output to a running debugger session? That would be the most "real" experience. If we also combine this with actual eBPF maps as backing, and the only difference would be that the emulated program can't react, it is readonly. It might be a good idea to "trace" execution, so disabling breakpoints but recording all actions the program took, which we can later load into a debug session to inspect. 