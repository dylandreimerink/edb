# EDB (eBPF debugger)

`edb` is a debugger(like gdb and dlv) for eBPF programs. Normally eBPF programs are loaded into the Linux kernel and then executed, this makes it difficult to understand what is happening or why things go wrong. For normal applications we can use gdb or dlv to inspect programs, but these don't work for the eBPF due to the way eBPF is loaded into the kernel.

`edb` uses userspace eBPF emulation to run eBPF programs instead of loading them into the kernel, this allows us to debug them like any other program. Altho this method is not perfect due to possible differences between the emulator and actual Linux machines, it is better than nothing.

## Installation

**Installation via go** `go install github.com/dylandreimerink/edb@latest`

## Usage

Starting a debug session:
```
edb [eBPF ELF file]
```

### Commands

```
Commands:
  help (Alias: h) ------------------------- Show help text / available commands
  exit (Aliasses: q, quit) ---------------- Exits the debugger
  clear ----------------------------------- Clear the screen
  load ------------------------------------ Load an ELF file
  programs (Alias: progs) ----------------- Show programs
  registers (Aliasses: r, regs) ----------- Show registers
  step-instruction (Alias: si) ------------ Step through the program one instruction a time
  list-instructions (Alias: li) ----------- Lists the instructions of the program
  step (Alias: s) ------------------------- Step through the program one line a time
  list (Alias: ls) ------------------------ Lists the lines of the source code
  map (Alias: maps) ----------------------- Map related operations
  locals (Alias: lv) ---------------------- Lists the local variables
  memory (Alias: mem) --------------------- Show the contents of memory
```

## Roadmap

TBD
