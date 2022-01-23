package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/dylandreimerink/gobpfld/emulator"
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
		fmt.Printf("%s (%s)\n", ctx.Name, ctx.MemPtr.String())
	}
}

func setCtxExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'program index|program name'\n")
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
	fmt.Printf("Switched current context to '%d' (%s)\n", id, contexts[id].Name)

	// If we are not in the middle of program execution, reset the VM.
	// We do this to set the context of the program(R1)
	if vm.Registers.PC == 0 && vm.Registers.PI == entrypoint {
		cmdReset.Exec(nil)
		fmt.Printf("VM reset, new context now in R1\n")
	} else {
		fmt.Printf("A program is currently running, R1 not updated, execute 'reset' to update R1\n")
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

	var ctxs []Ctx

	dec := json.NewDecoder(f)
	err = dec.Decode(&ctxs)
	if err != nil {
		printRed("error decoding context file: %s\n", err)
		return
	}

	for i, ctx := range ctxs {
		ptr, err := ctx.ToMemPtr()
		if err != nil {
			printRed("ctx '%d' to ptr error: %s\n", i, err)
			return
		}

		contexts = append(contexts, Context{
			Name:   ctx.Name,
			MemPtr: ptr,
		})
	}

	fmt.Printf("%d contexts were loaded\n", len(ctxs))

	// If we are not in the middle of program execution, reset the VM.
	// We do this to set the context of the program(R1)
	if vm.Registers.PC == 0 && vm.Registers.PI == entrypoint {
		cmdReset.Exec(nil)
	}
}

type Context struct {
	Name   string
	MemPtr *emulator.MemoryPtr
}

type Ctx struct {
	Name string `json:"name"`
	// The name of the data which will be the actual context to be passed
	Ctx string `json:"ctx"`
	// Used during decoding
	RawData map[string]json.RawMessage `json:"data"`
	// Pieces of named data
	Data map[string]CtxData `json:"-"`
}

func (ctx *Ctx) ToMemPtr() (*emulator.MemoryPtr, error) {
	var ptr emulator.MemoryPtr

	mem, found := ctx.Data[ctx.Ctx]
	if !found {
		return nil, fmt.Errorf("ctx has value '%s' but no data object with that name found", ctx.Ctx)
	}

	var err error
	ptr.Memory, err = mem.ToMemory(ctx.Ctx, ctx)
	if err != nil {
		return nil, fmt.Errorf("data object to memory '%s' error: %w", ctx.Ctx, err)
	}

	return &ptr, nil
}

func (ctx *Ctx) UnmarshalJSON(b []byte) error {
	// Use an alias to avoid infinite loop
	type PseudoCtx Ctx
	var pctx PseudoCtx

	err := json.Unmarshal(b, &pctx)
	if err != nil {
		return fmt.Errorf("unmarshal ctx: %w", err)
	}

	*ctx = Ctx(pctx)
	ctx.Data = make(map[string]CtxData)

	type CtxType struct {
		Type string `json:"type"`
	}

	var t CtxType
	for name, raw := range ctx.RawData {
		err = json.Unmarshal(raw, &t)
		if err != nil {
			return fmt.Errorf("unmarshal data '%s': %w", name, err)
		}

		var d CtxData
		switch t.Type {
		case "memory":
			v := &CtxMemory{}
			err = json.Unmarshal(raw, v)
			if err != nil {
				return fmt.Errorf("unmarshal memory '%s': %w", name, err)
			}
			d = v

		case "ptr":
			v := &CtxPtr{}
			err = json.Unmarshal(raw, v)
			if err != nil {
				return fmt.Errorf("unmarshal ptr '%s': %w", name, err)
			}
			d = v

		case "int":
			v := &CtxInt{}
			err = json.Unmarshal(raw, v)
			if err != nil {
				return fmt.Errorf("unmarshal int '%s': %w", name, err)
			}
			d = v

		case "struct":
			v := &CtxStruct{}
			err = json.Unmarshal(raw, v)
			if err != nil {
				return fmt.Errorf("unmarshal struct '%s': %w", name, err)
			}
			d = v

		default:
			return fmt.Errorf("can't decode data type '%s'", t.Type)
		}

		ctx.Data[name] = d
	}

	return nil
}

type CtxData interface {
	ToMemory(name string, ctx *Ctx) (emulator.Memory, error)
}

type CtxMemory struct {
	Value     []byte           `json:"value"`
	ByteOrder binary.ByteOrder `json:"byteorder,omitempty"`
	mem       *emulator.ByteMemory
}

func (cm *CtxMemory) ToMemory(name string, ctx *Ctx) (emulator.Memory, error) {
	if cm.mem != nil &&
		bytes.Equal(cm.mem.Backing, cm.Value) &&
		cm.mem.ByteOrder == cm.ByteOrder &&
		cm.mem.MemName == name {
		return cm.mem, nil
	}

	cm.mem = &emulator.ByteMemory{
		MemName:   name,
		ByteOrder: cm.ByteOrder,
		Backing:   cm.Value,
	}
	return cm.mem, nil
}

func (cm *CtxMemory) UnmarshalJSON(b []byte) error {
	type ctxMem struct {
		Value     string `json:"value"`
		ByteOrder string `json:"byteorder"`
	}
	var m ctxMem

	err := json.Unmarshal(b, &m)
	if err != nil {
		return err
	}

	cm.Value, err = base64.StdEncoding.DecodeString(m.Value)
	if err != nil {
		return fmt.Errorf("base64 decode: '%s' is not valid base64: %w", m.Value, err)
	}

	switch strings.ToLower(m.ByteOrder) {
	case "le", "littleendian", "little endian", "little-endian":
		cm.ByteOrder = binary.LittleEndian
	case "be", "bigendian", "big endian", "big-endian":
		cm.ByteOrder = binary.BigEndian
	default:
		return fmt.Errorf("'%s' is not valid byte order", m.Value)
	}

	return nil
}

type CtxPtr struct {
	MemoryName string `json:"value"`
	Offset     int    `json:"offset"`
	Size       int    `json:"size"`
}

func (cp *CtxPtr) ToPtr(name string, ctx *Ctx) (*emulator.MemoryPtr, error) {
	ctxMem, found := ctx.Data[cp.MemoryName]
	if !found {
		return nil, fmt.Errorf("ptr object '%s' references data object '%s' which doesn't exist", name, cp.MemoryName)
	}

	mem, err := ctxMem.ToMemory(cp.MemoryName, ctx)
	if err != nil {
		return nil, fmt.Errorf("data object '%s' to memory error: %w", cp.MemoryName, err)
	}

	return &emulator.MemoryPtr{
		Memory: mem,
		Offset: int64(cp.Offset),
	}, nil
}

func (cp *CtxPtr) ToMemory(name string, ctx *Ctx) (emulator.Memory, error) {
	bytes, err := sizeToBytes(cp.Size)
	if err != nil {
		return nil, fmt.Errorf("data object '%s': %w", name, err)
	}

	valMem := &emulator.ValueMemory{
		MemName: name,
		Mapping: make([]emulator.RegisterValue, bytes),
	}

	ptr, err := cp.ToPtr(name, ctx)
	if err != nil {
		return nil, err
	}

	for i := 0; i < bytes; i++ {
		valMem.Mapping[i] = ptr
	}

	return valMem, nil
}

type CtxInt struct {
	Value int `json:"value"`
	Size  int `json:"size"`
}

func (ci *CtxInt) ToMemory(name string, ctx *Ctx) (emulator.Memory, error) {
	bytes, err := sizeToBytes(ci.Size)
	if err != nil {
		return nil, fmt.Errorf("data object '%s': %w", name, err)
	}

	valMem := &emulator.ValueMemory{
		MemName: name,
		Mapping: make([]emulator.RegisterValue, bytes),
	}

	imm := emulator.IMMValue(ci.Value)

	for i := 0; i < bytes; i++ {
		valMem.Mapping[i] = &imm
	}

	return valMem, nil
}

type CtxStruct struct {
	FieldNames []string `json:"fields"`
}

func (cs *CtxStruct) ToMemory(name string, ctx *Ctx) (emulator.Memory, error) {
	valMem := &emulator.ValueMemory{
		MemName: name,
		Mapping: make([]emulator.RegisterValue, 0),
	}

	for _, field := range cs.FieldNames {
		ctxField, found := ctx.Data[field]
		if !found {
			return nil, fmt.Errorf("struct object '%s' references data object '%s' which doesn't exist", name, field)
		}

		switch ctxField := ctxField.(type) {
		case *CtxInt:
			bytes, err := sizeToBytes(ctxField.Size)
			if err != nil {
				return nil, fmt.Errorf("int object '%s': %w", field, err)
			}
			intVal := emulator.IMMValue(ctxField.Value)
			for i := 0; i < bytes; i++ {
				valMem.Mapping = append(valMem.Mapping, &intVal)
			}

		case *CtxMemory:
			for _, b := range ctxField.Value {
				intVal := emulator.IMMValue(b)
				valMem.Mapping = append(valMem.Mapping, &intVal)
			}

		case *CtxPtr:
			ptr, err := ctxField.ToPtr(field, ctx)
			if err != nil {
				return nil, err
			}
			bytes, err := sizeToBytes(ctxField.Size)
			if err != nil {
				return nil, fmt.Errorf("int object '%s': %w", field, err)
			}
			for i := 0; i < bytes; i++ {
				valMem.Mapping = append(valMem.Mapping, ptr)
			}

		case *CtxStruct:
			ctxMem, err := ctxField.ToMemory(field, ctx)
			if err != nil {
				return nil, err
			}

			valMem.Mapping = append(valMem.Mapping, ctxMem.(*emulator.ValueMemory).Mapping...)

		default:

		}
	}

	return valMem, nil
}

func sizeToBytes(size int) (int, error) {
	switch size {
	case 8:
		return 1, nil
	case 16:
		return 2, nil
	case 32:
		return 4, nil
	case 64:
		return 8, nil
	}

	return 0, fmt.Errorf("invalid size '%d', must be one of: 8, 16, 32, 64")
}
