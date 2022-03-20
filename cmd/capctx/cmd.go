package capctx

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/perf"
	"github.com/dylandreimerink/edb/analyse"
	"github.com/dylandreimerink/mimic"
	"github.com/spf13/cobra"

	_ "unsafe"
)

func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "capture-context {ELF file} {ctx file}",
		Short: "Capture program contexts",
		Long: "This command modifies the input program, adding instrumentation to it. The instrumented program will " +
			"be loaded into the kernel and pinned in a given dir until this command end. While running this command " +
			"will capture the context and results of helper functions and generate a context file from them.\n\n" +
			"After starting this command, a loader program should unpin the program and attach it.",
		RunE: captureContextRun,
		Args: cobra.ExactArgs(2),
	}

	f := cmd.Flags()
	f.BoolVar(&flagPlainProg, "plain-program", false, "Print the program instruction before instrumenting")
	f.BoolVar(&flagInstProg, "instrumented-program", false, "Print the program instruction after instrumenting")
	f.BoolVar(&flagVerifierLog, "verifier-log", false, "Print the verifier log")
	f.BoolVar(&flagVerifierVerbose, "verifier-verbose", false, "If set, the verbose log is printed, not just the normal log")

	return cmd
}

var (
	flagPlainProg       bool
	flagInstProg        bool
	flagVerifierLog     bool
	flagVerifierVerbose bool
)

const (
	feedbackMap = "ebpf_instrument_map"
	bufferMap   = "ebpf_buffer_map"

	bufferSize = 16384
)

func captureContextRun(cmd *cobra.Command, args []string) error {
	// Load collection from ELF
	spec, err := ebpf.LoadCollectionSpec(args[0])
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}

	for name, prog := range spec.Programs {
		if flagPlainProg {
			fmt.Println(name, " plain:")
			fmt.Println(prog.Instructions)
		}

		err := instrumentProgram(prog)
		if err != nil {
			return fmt.Errorf("instrument program '%s': %w", name, err)
		}

		if flagInstProg {
			fmt.Println(name, " instrumented:")
			fmt.Println(prog.Instructions)
		}

		// Disable BTF since modifying the instructions without modifying the BTF will cause verifier rejection.
		// TODO add BTF rewriting
		prog.BTF = nil

		// Otherwise the kernel verifier might discard our instrumentation
		prog.License = "GPL"
	}

	spec.Maps[feedbackMap] = &ebpf.MapSpec{
		Name:      feedbackMap,
		Type:      ebpf.PerfEventArray,
		ValueSize: 4,
	}
	spec.Maps[bufferMap] = &ebpf.MapSpec{
		Name:       bufferMap,
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  bufferSize,
		MaxEntries: 1,
	}

	opts := &ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: 1, LogSize: 200 * 1 << 20}}
	if flagVerifierVerbose {
		opts.Programs.LogLevel = 2
	}

	holder := typeFromSpec(spec)
	err = spec.LoadAndAssign(holder, opts)
	if err != nil {
		return fmt.Errorf("load and assign: %w", err)
	}
	defer func() {
		err := closeSpecHolder(holder)
		if err != nil {
			fmt.Println(err)
		}
	}()

	var pinDir string
	for i := 0; i < 100; i++ {
		pinDir = fmt.Sprintf("/sys/fs/bpf/edb-instrumented-%d", i)
		_, err = os.Stat(pinDir)

		// If the path is not in use
		var pathErr *os.PathError
		if errors.As(err, &pathErr) && pathErr.Err == syscall.ENOENT {
			break
		}
	}
	fmt.Printf("Pinning instrumented programs and maps in: %s\n", pinDir)

	// Pin the maps and programs so the normal program loader can un-pin them.
	err = pinSpecHolder(holder, pinDir)
	if err != nil {
		return fmt.Errorf("pin programs and maps: %w", err)
	}

	defer func() {
		// Remove pins recursively
		os.RemoveAll(pinDir)
	}()

	m := GetMapByName(holder, feedbackMap)
	if m == nil {
		return fmt.Errorf("can't find feedback map in map holder")
	}

	r, err := perf.NewReader(m, bufferSize)
	if err != nil {
		return fmt.Errorf("new perf reader: %w", err)
	}
	defer m.Close()

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt)

	var ctxs []mimic.Context

	go func() {
		i := 0
		for {
			err := r.Resume()
			if err != nil {
				fmt.Printf("resume: %s", err.Error())
				continue
			}

			record, err := r.Read()
			if err != nil {
				fmt.Printf("pref read: %s", err.Error())
				continue
			}

			ctx, err := decodeFeedback(record.RawSample)
			if err != nil {
				fmt.Printf("decode feedback: %s", err.Error())
				continue
			}

			if ctx != nil {
				ctx.SetName(fmt.Sprintf("%d (%s)", i, time.Now()))
				i++

				ctxs = append(ctxs, ctx)

				fmt.Println(i, "contexts captured")
			}
		}
	}()

	<-sigChan

	ctxFile, err := os.Create(args[1])
	if err != nil {
		return fmt.Errorf("create context file: %w", err)
	}
	defer ctxFile.Close()

	jsonEncoder := json.NewEncoder(ctxFile)
	jsonEncoder.SetIndent("", "  ")
	err = jsonEncoder.Encode(ctxs)
	if err != nil {
		return fmt.Errorf("json encode context: %w", err)
	}

	return nil
}

type specHolder interface{}

func GetMapByName(sh specHolder, name string) *ebpf.Map {
	ht := reflect.TypeOf(sh).Elem()
	hv := reflect.ValueOf(sh).Elem()

	for i := 0; i < ht.NumField(); i++ {
		f := ht.Field(i)
		if t, ok := f.Tag.Lookup("ebpf"); ok && t == name {
			if m, ok := hv.Field(i).Interface().(*ebpf.Map); ok {
				return m
			}
		}
	}

	return nil
}

// Use reflection to craft a struct type which can be used to LoadAndAssign the given spec.
func typeFromSpec(spec *ebpf.CollectionSpec) specHolder {
	fields := make([]reflect.StructField, 0)

	progPtrType := reflect.TypeOf(&ebpf.Program{})
	mapPtrType := reflect.TypeOf(&ebpf.Map{})

	i := 0
	for name := range spec.Programs {
		fields = append(fields, reflect.StructField{
			Name: strings.Title(name),
			Type: progPtrType,
			Tag:  reflect.StructTag(fmt.Sprintf("ebpf:\"%s\"", name)),
		})
		i++
	}
	for name := range spec.Maps {
		switch name {
		case ".rodata", ".data", ".bss":
			// Don't include global maps in struct
			continue
		}
		fields = append(fields, reflect.StructField{
			Name: strings.Title(name),
			Type: mapPtrType,
			Tag:  reflect.StructTag(fmt.Sprintf("ebpf:\"%s\"", name)),
		})
		i++
	}

	structType := reflect.StructOf(fields)
	return reflect.New(structType).Interface()
}

func closeSpecHolder(sh specHolder) error {
	shStruct := reflect.ValueOf(sh).Elem()
	for i := 0; i < shStruct.NumField(); i++ {
		field := shStruct.Field(i)
		switch field := field.Interface().(type) {
		case *ebpf.Program:
			err := field.Close()
			if err != nil {
				return err
			}

		case *ebpf.Map:
			err := field.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func pinSpecHolder(sh specHolder, dir string) error {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("mkdir '%s': %w", dir, err)
	}

	shStruct := reflect.ValueOf(sh).Elem()
	shStructType := shStruct.Type()
	for i := 0; i < shStruct.NumField(); i++ {
		field := shStruct.Field(i)
		fieldType := shStructType.Field(i)
		switch obj := field.Interface().(type) {
		case *ebpf.Program:
			if flagVerifierLog {
				fmt.Println(fieldType.Tag.Get("ebpf"), " verifier log:")
				fmt.Println(obj.VerifierLog)
			}
			err := obj.Pin(filepath.Join(dir, fmt.Sprint("prog-", fieldType.Tag.Get("ebpf"))))
			if err != nil {
				return err
			}

		case *ebpf.Map:
			err := obj.Pin(filepath.Join(dir, fmt.Sprint("map-", fieldType.Tag.Get("ebpf"))))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeFeedback(feedback []byte) (*mimic.CapturedContext, error) {
	if len(feedback) < 4 {
		return nil, fmt.Errorf("feedback msg to small")
	}

	ne := mimic.GetNativeEndianness()

	// Trim feedback, by removing the length field and trimming feedback to the given length.
	// Since the perf reader might append some extra bytes.
	fbLen := ne.Uint32(feedback[:4])
	if len(feedback) < int(fbLen) {
		return nil, fmt.Errorf("feedback msg missing data expected: %d, got: %d", int(fbLen), len(feedback))
	}
	feedback = feedback[4:fbLen]

	helpers := make(map[string][]mimic.CapturedContextHelperCall)
	ctx := &mimic.CapturedContext{
		Sub: &mimic.GenericContext{},
	}

	var curHelper *mimic.CapturedContextHelperCall

	for len(feedback) > 0 {
		msgType := feedback[0]
		switch MsgType(msgType) {
		case ctxData:
			progType := ebpf.ProgramType(ne.Uint32(feedback[1:5]))
			var err error

			var subCtx mimic.Context
			subCtx, feedback, err = ctxDataDecode(progType, feedback[5:])
			if err != nil {
				return nil, fmt.Errorf("decode ctx data: %w", err)
			}
			ctx = &mimic.CapturedContext{
				Sub: subCtx,
			}

		case helperIDMsg:
			helperFn := asm.BuiltinFunc(ne.Uint32(feedback[1:5]))
			feedback = feedback[5:]

			// Submit current helper, if any
			if curHelper != nil {
				helperStr := strconv.Itoa(int(curHelper.HelperFn))
				helpers[helperStr] = append(helpers[helperStr], *curHelper)
			}

			curHelper = &mimic.CapturedContextHelperCall{
				HelperFn: helperFn,
			}

		case rInScalar:
			curHelper.Params = append(curHelper.Params, mimic.CapturedContextRegisterData{
				Reg:    asm.Register(feedback[1]),
				Scalar: ne.Uint64(feedback[2:10]),
			})
			feedback = feedback[10:]

		case rOutScalar:
			curHelper.Result = append(curHelper.Result, mimic.CapturedContextRegisterData{
				Reg:    asm.Register(feedback[1]),
				Scalar: ne.Uint64(feedback[2:10]),
			})
			feedback = feedback[10:]

		case rOutData:
			reg := feedback[1]
			size := ne.Uint16(feedback[2:4])
			data := feedback[4 : 4+size]
			curHelper.Result = append(curHelper.Result, mimic.CapturedContextRegisterData{
				Reg:  asm.Register(reg),
				Data: data,
			})
			feedback = feedback[4+size:]

		default:
			return nil, fmt.Errorf("unknown msg type: %d", msgType)
		}
	}

	if curHelper != nil {
		helperStr := strconv.Itoa(int(curHelper.HelperFn))
		helpers[helperStr] = append(helpers[helperStr], *curHelper)
	}

	ctx.HelperCalls = helpers

	return ctx, nil
}

const (
	// Offset within the first stack frame where the original context is stored
	ctxOff = -8
	// Offset within the first stack frame where the feedback buffer pointer is stored
	bufferPtr = -16
	// Offset within the first stack frame where the a pointer to the start of the feedback buffer is stored
	bufferStartPtr = -24
)

type MsgType byte

const (
	// Message is the data of the dereferenced ctx
	// For example a xdp_md struct and its underlaying data, or a pt_regs struct.
	ctxData MsgType = iota
	// Message is the ID of the helper function
	helperIDMsg
	// Message is a register as scalar value as function input
	// For example a int passed to a helper(flags)
	rInScalar
	// Message is data to which a register points as function input
	// For example a pointer passed to a helper, like a map key
	rInData
	// Message is a register as scalar value as function output
	// For example the return value(R0) of most functions.
	rOutScalar
	// Message is data to which a register points as function output
	// For example a pointer passed to a helper which is modified by the helper
	rOutData
)

func instrumentProgram(prog *ebpf.ProgramSpec) error {

	// Create a program checker and pass it a CTX at R1(for now)
	permChecker := analyse.NewChecker()
	initProgState := analyse.NewProgramState(prog.Instructions)
	initProgState.Frame().Registers[asm.R1] = analyse.RegisterState{
		Type:    analyse.RVUnknown,
		Precise: true,
	}

	// Check all permutations of the given initial program state, once done the permChecker should contain
	// a "union" state per instruction which we can use when deciding which registers and stack locations to use when
	// instrumenting the program
	err := permChecker.Check(&initProgState, analyse.None)
	if err != nil && err != analyse.ErrMaxInst {
		return fmt.Errorf("check: %w", err)
	}

	entryFuncStage := permChecker.UnionStatePerFunc[prog.Instructions[0].Symbol()]

	newInstructions := make(asm.Instructions, 0, len(prog.Instructions))

	// Create an new entrypoint, which will perform a BPF-to-BPF call to the real entrypoint.
	// We do this so we can use the first stack frame as memory which the main program will not touch.
	newInstructions = append(newInstructions, []asm.Instruction{
		// Store R1(ctx) in the first stack frame
		// TODO store other initial registers as well(R2-R5) for tracepoints and the like
		asm.StoreMem(asm.R10, ctxOff, asm.R1, asm.DWord),

		// Get ptr to map value 0, and store it at bufferPtr
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, bufferPtr),
		asm.StoreImm(asm.R2, 0, 0, asm.DWord),
		//
		asm.LoadMapPtr(asm.R1, 0).WithReference(bufferMap),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "instrument-main-exit"),
		asm.StoreMem(asm.R10, bufferStartPtr, asm.R0, asm.DWord),
		asm.Add.Imm(asm.R0, 4),
		asm.StoreMem(asm.R10, bufferPtr, asm.R0, asm.DWord),

		// TODO restore other initial registers as well(R2-R5) for tracepoints and the like
		// Restore CTX to R1
		asm.LoadMem(asm.R1, asm.R10, ctxOff, asm.DWord),
	}...)

	// Capture the passed context
	newInstructions = append(newInstructions, sendCtx(prog.Type)...)

	newInstructions = append(newInstructions, []asm.Instruction{
		// Restore CTX to R1
		asm.LoadMem(asm.R1, asm.R10, ctxOff, asm.DWord),
		// Pass the first frame pointer as second argument, call the main program.
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Call.Label("instrument-main-prog-wrapper"),

		// Save R0(return value of main prog)
		asm.Mov.Reg(asm.R6, asm.R0),

		// Returned to instrumentation wrapper
		// Restore CTX to R1
		asm.LoadMem(asm.R1, asm.R10, ctxOff, asm.DWord),
		// Load map ptr into R2
		asm.LoadMapPtr(asm.R2, 0).WithReference(feedbackMap),
		// Set flags to BPF_F_CURRENT_CPU
		asm.LoadImm(asm.R3, BPF_F_CURRENT_CPU, asm.DWord),
		// Load ptr to start of map value
		asm.LoadMem(asm.R4, asm.R10, bufferStartPtr, asm.DWord),
		// // Load end of buffer
		asm.LoadMem(asm.R5, asm.R10, bufferPtr, asm.DWord),
		// Size of msg to be sent is ptr to end - start.
		asm.Sub.Reg(asm.R5, asm.R4),
		// Store size in first 4 bytes
		asm.StoreMem(asm.R4, 0, asm.R5, asm.Word),
		// Make sure size is between 0 and 16384
		asm.JLE.Imm(asm.R5, bufferSize, "send-buffer"),
		asm.Mov.Imm(asm.R5, bufferSize),
		// Send buffer
		asm.FnPerfEventOutput.Call().WithSymbol("send-buffer"),

		// Restore R0 of main program
		asm.Mov.Reg(asm.R0, asm.R6),

		// Exit program
		asm.Return().WithSymbol("instrument-main-exit"),

		// This instruction prepends the main program, it stores the passed FP and stores it at the max value of the
		// stack, normal program will use memory from bottom to top, so this should work in all but the most extreme
		// cases.
		asm.StoreMem(
			asm.R10,
			-int16((len(entryFuncStage.Stack.Slots)+1)*8), // Get nearest unused spot on the stack frame
			asm.R2,
			asm.DWord,
		).WithSymbol("instrument-main-prog-wrapper"),
		// Init R9 so the verifier doesn't complain when we attempt to save it.
		asm.Mov.Imm(asm.R9, 0),
	}...)

	// Make a RawInstOffset -> instruction lookup which improves performance during jump labeling
	iter := prog.Instructions.Iterate()
	offToInst := map[asm.RawInstructionOffset]*asm.Instruction{}
	for iter.Next() {
		offToInst[iter.Offset] = iter.Ins
	}

	// Also record all existing labels, at this point all symbols are function entrypoints
	functionReferences := prog.Instructions.FunctionReferences()

	// A bpf-to-bpf function can be called from multiple funcs, but the callee can only access 1 set of offsets from the
	// prev call frame. So for each caller, get the first free offset on the stack, take the max of all callers.
	// All callers will use this offset when calling into the given function.
	maxFuncOffsets := map[string]int{}
	{
		funcName := ""
		for i, inst := range prog.Instructions {
			if functionReferences[inst.Symbol()] || i == 0 {
				funcName = inst.Symbol()
			}

			if inst.IsFunctionCall() {
				callerMax := len(permChecker.UnionStatePerFunc[funcName].Stack.Slots)
				curMax := maxFuncOffsets[inst.Reference()]
				if callerMax > curMax {
					maxFuncOffsets[inst.Reference()] = callerMax
				}
			}
		}
	}

	iter = prog.Instructions.Iterate()
	for iter.Next() {
		inst := iter.Ins

		// Ignore non-jump ops, or "special" jump instructions
		op := inst.OpCode.JumpOp()
		switch op {
		case asm.InvalidJumpOp, asm.Call, asm.Exit:
			continue
		}

		targetOff := iter.Offset + asm.RawInstructionOffset(inst.Offset+1)
		label := fmt.Sprintf("j-%d", targetOff)

		target := offToInst[targetOff]
		*target = target.WithSymbol(label)

		inst.Offset = -1
		*inst = inst.WithReference(label)
	}

	var (
		fpOff          int16
		primarySaveOff int16
		curFunc        string
	)

	for i, inst := range prog.Instructions {
		if functionReferences[inst.Symbol()] || i == 0 {
			unionState := permChecker.UnionStatePerFunc[inst.Symbol()]

			fpOff = -int16((len(unionState.Stack.Slots) + 1) * 8)
			primarySaveOff = -int16((len(unionState.Stack.Slots) + 2) * 8)

			curFunc = inst.Symbol()
		}

		// If the current function is a BPF-to-BPF function entrypoint.
		// i != 0 makes sure to skip the entrypoint
		if functionReferences[inst.Symbol()] && i != 0 {
			// Note: prior to calling a BPF-to-BPF function to original R1 is replaced by the previous stack frame and
			// the original R1 is put in that stack frame.

			newInstructions = append(newInstructions,
				// Load fp0 from previous stack frame into R9.
				// Note: using R9 has the size effect of populating it with a value so the verifier doesn't complain
				// if we try to save it later
				// Note: Add the symbol of the original instruction, since this is the new first instruction
				asm.LoadMem(asm.R9, asm.R1, int16(maxFuncOffsets[curFunc]+1)*-8, asm.DWord).WithSymbol(inst.Symbol()),
				// Store fp0 into fp
				asm.StoreMem(asm.R10, fpOff, asm.R9, asm.DWord),
				// Restore original R1
				asm.LoadMem(asm.R1, asm.R1, int16(maxFuncOffsets[curFunc]+2)*-8, asm.DWord),
			)

			// Strip the symbol from the original instruction
			inst = inst.WithSymbol("")
		}

		// Instrument helper calls
		if inst.IsBuiltinCall() {
			fn := asm.BuiltinFunc(inst.Constant)

			helperInstr := helperInstrumentation(fpOff, primarySaveOff)[fn]

			// Send the ID of the helper function
			newInstructions = append(newInstructions, sendHelperID(fn, fpOff, primarySaveOff)...)
			// Pre-execution instructions(saving registers in stack and/or sending register contents)
			newInstructions = append(newInstructions, helperInstr.pre...)
			// The helper call itself
			newInstructions = append(newInstructions, inst)
			// Send results of helper call.
			newInstructions = append(newInstructions, helperInstr.post...)
			continue
		}

		// Propegate fp0 to next call stack frame
		if inst.IsFunctionCall() {
			newInstructions = append(newInstructions,
				// Save R1 in current stack frame @ primary safe offset
				asm.StoreMem(asm.R10, int16(maxFuncOffsets[inst.Reference()]+2)*-8, asm.R1, asm.DWord).WithSymbol(inst.Symbol()),
				// Load fp into R1
				asm.Mov.Reg(asm.R1, asm.R10),
				// Call BPF-to-BPF function
				inst.WithSymbol(""),
			)

			continue
		}

		newInstructions = append(newInstructions, inst)
	}

	iter = newInstructions.Iterate()
	instToOffset := map[*asm.Instruction]asm.RawInstructionOffset{}
	for iter.Next() {
		instToOffset[iter.Ins] = iter.Offset
	}
	symOff, err := newInstructions.SymbolOffsets()
	if err != nil {
		return err
	}

	iter = newInstructions.Iterate()
	for iter.Next() {
		inst := iter.Ins

		// Ignore non-jump ops, or "special" jump instructions
		op := inst.OpCode.JumpOp()
		switch op {
		case asm.InvalidJumpOp, asm.Call, asm.Exit:
			continue
		}

		if inst.Reference() == "" {
			continue
		}

		inst.Offset = int16(instToOffset[&newInstructions[symOff[inst.Reference()]]]) - int16(iter.Offset) - 1
	}

	prog.Instructions = newInstructions

	return nil
}

// Copied from sys/unix
const BPF_F_CURRENT_CPU = 0xffffffff
