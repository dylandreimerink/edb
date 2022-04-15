package analyse

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/cilium/ebpf/asm"
)

const maxCallFrames = 8

func NewProgramState(prog []asm.Instruction) ProgramState {
	noopedProg := make([]asm.Instruction, 0, len(prog))
	for _, inst := range prog {
		noopedProg = append(noopedProg, inst)
		if inst.OpCode.IsDWordLoad() {
			// Add an empty instruction (noop)
			noopedProg = append(noopedProg, asm.Instruction{})
		}
	}

	return ProgramState{
		Prog: prog,
	}
}

type ProgramState struct {
	Frames   [maxCallFrames]FuncState
	CurFrame int
	Prog     []asm.Instruction
	InstOff  int
	FuncName string
}

func (ps *ProgramState) Frame() *FuncState {
	return &ps.Frames[ps.CurFrame]
}

func (ps *ProgramState) Inst() asm.Instruction {
	return ps.Prog[ps.InstOff]
}

func (ps *ProgramState) Copy() ProgramState {
	var nps ProgramState

	for i := 0; i < len(nps.Frames); i++ {
		nps.Frames[i] = ps.Frames[i].Copy()
	}

	nps.CurFrame = ps.CurFrame
	nps.Prog = ps.Prog
	nps.InstOff = ps.InstOff

	return nps
}

func (ps ProgramState) String() string {
	return ps.Frame().String()
}

type FuncState struct {
	Registers   [asm.R10 + 1]RegisterState
	Callsite    int
	FrameNumber int
	Stack       StackState
}

func (fs *FuncState) Copy() FuncState {
	var nfs FuncState

	copy(nfs.Registers[:], fs.Registers[:])
	nfs.Callsite = fs.Callsite
	nfs.FrameNumber = fs.FrameNumber
	nfs.Stack = fs.Stack.Copy()

	return nfs
}

func (fs FuncState) String() string {
	var sb strings.Builder

	for r := asm.R0; r < asm.R10; r++ {
		if fs.Registers[r].Type == RVNotInit {
			continue
		}

		sb.WriteString(r.String())
		sb.WriteString("=")
		sb.WriteString(fs.Registers[r].String())
		sb.WriteString(" ")
	}

	sb.WriteString(fmt.Sprintf("r10=fp%d ", fs.FrameNumber))

	sb.WriteString(fs.Stack.String(fs.FrameNumber))

	return sb.String()
}

type StackState struct {
	Slots []StackSlot
}

func (ss *StackState) Copy() StackState {
	nss := StackState{
		Slots: make([]StackSlot, len(ss.Slots)),
	}
	copy(nss.Slots, ss.Slots)
	return nss
}

func (ss *StackState) String(frameNumber int) string {
	var sb strings.Builder

	for i := len(ss.Slots) - 1; i >= 0; i-- {
		slot := ss.Slots[i]
		slotStr := slot.String()
		if slotStr != "" {
			sb.WriteString(fmt.Sprintf("fp%d%d=%s ", frameNumber, -8-(i*regSize), slotStr))
		}
	}

	return sb.String()
}

// -8 = len(ss.Slots)-1, -16 = len(ss.Slots)-2
func (ss *StackState) Slot(off int) *StackSlot {
	i := len(ss.Slots) + ((off + 1) / regSize) - 1
	if i >= len(ss.Slots) {
		return nil
	}

	// Grow stack
	if i < 0 {
		ss.Slots = append(make([]StackSlot, -i), ss.Slots...)
		i = 0
	}

	return &ss.Slots[i]
}

func (ss *StackState) WriteReg(off int, size asm.Size, reg RegisterState) {
	// If size is max and memory aligned, we will spill the register value to the stack
	if off%regSize == 0 && size == asm.DWord {
		slot := ss.Slot(off)
		if slot == nil {
			return
		}

		slot.Spilled = &reg
		for i := 0; i < regSize; i++ {
			slot.SlotTypes[i] = SlotTypeSpill
		}

		return
	}

	for i := off; i < off+size.Sizeof(); i++ {
		slot := ss.Slot(i)
		if slot == nil {
			continue
		}

		slot.SlotTypes[-(i % regSize)] = SlotTypeMisc
		slot.Spilled = nil
	}
}

func (ss *StackState) WriteMisc(off, len int) {
	for i := off; i < off+len; i++ {
		slot := ss.Slot(i)
		if slot == nil {
			continue
		}

		slot.SlotTypes[-(i % regSize)] = SlotTypeMisc
		slot.Spilled = nil
	}
}

// size of eBPF register in bytes
const regSize = 8

type StackSlotType byte

const (
	SlotTypeInvalid StackSlotType = iota
	SlotTypeSpill
	SlotTypeMisc
	SlotTypeZero
)

type StackSlot struct {
	SlotTypes [regSize]StackSlotType
	Spilled   *RegisterState
}

func (ss StackSlot) String() string {
	if ss.SlotTypes[regSize-1] == SlotTypeSpill && ss.Spilled != nil {
		return ss.Spilled.String()
	}

	var sb strings.Builder

	valid := false
	for i := 0; i < regSize; i++ {
		switch ss.SlotTypes[i] {
		case SlotTypeInvalid:
			sb.WriteRune('?')
		case SlotTypeSpill:
			sb.WriteRune('r')
			valid = true
		case SlotTypeMisc:
			sb.WriteRune('m')
			valid = true
		case SlotTypeZero:
			sb.WriteRune('0')
			valid = true
		}
	}

	if !valid {
		return ""
	}

	return sb.String()
}

type RegisterState struct {
	Type RegisterValueType

	// If true, we know the value exactly, otherwise the MinValue and MaxValue apply
	Precise bool

	// value if Scalar, offset if ptr
	Value    int64
	MinValue int64
	MaxValue int64

	// If ptr to stack, to which stack frame
	FrameNo int
}

func (rs *RegisterState) maxRange() bool {
	return !rs.Precise && rs.MinValue == -math.MaxInt64 && rs.MaxValue == math.MaxInt64
}

func (rs *RegisterState) AddIMM(i int64) {
	if rs.Precise {
		rs.Value += i
	} else {
		if rs.maxRange() {
			return
		}

		rs.MinValue += i
		rs.MaxValue += i
	}
}

func (rs *RegisterState) AddReg(r RegisterState) {
	if rs.Precise {
		if r.Precise {
			rs.Value += r.Value
		} else {
			rs.MinValue = rs.Value + r.MinValue
			rs.MaxValue = rs.Value + r.MaxValue
			rs.Precise = false
		}
	} else {
		if r.Precise {
			rs.MinValue = rs.MinValue + r.Value
			rs.MaxValue = rs.MaxValue + r.Value
		} else {
			if rs.maxRange() || r.maxRange() {
				rs.MinValue = -math.MaxInt64
				rs.MaxValue = math.MaxInt64
				return
			}

			rs.MinValue = rs.MinValue + r.MinValue
			rs.MaxValue = rs.MaxValue + r.MaxValue
		}
	}
}

func (rs *RegisterState) SubIMM(i int64) {
	if rs.Precise {
		rs.Value -= i
	} else {
		if rs.maxRange() {
			return
		}

		rs.MinValue -= i
		rs.MaxValue -= i
	}
}

func (rs *RegisterState) SubReg(r RegisterState) {
	if rs.Precise {
		if r.Precise {
			rs.Value -= r.Value
		} else {
			rs.MinValue = rs.Value - r.MinValue
			rs.MaxValue = rs.Value - r.MaxValue
			rs.Precise = false
		}
	} else {
		if r.Precise {
			rs.MinValue = rs.MinValue - r.Value
			rs.MaxValue = rs.MaxValue - r.Value
		} else {
			if rs.maxRange() || r.maxRange() {
				rs.MinValue = -math.MaxInt64
				rs.MaxValue = math.MaxInt64
				return
			}

			rs.MinValue = rs.MinValue - r.MinValue
			rs.MaxValue = rs.MaxValue - r.MaxValue
		}
	}
}

func (rs *RegisterState) MulIMM(i int64) {
	if rs.Precise {
		rs.Value = i * rs.Value
	} else {
		rs.MinValue = i * rs.MinValue
		rs.MaxValue = i * rs.MaxValue
	}
}

func (rs *RegisterState) MulReg(r RegisterState) {
	if rs.Precise {
		if r.Precise {
			rs.Value = rs.Value * r.Value
		} else {
			rs.MinValue = rs.Value * r.MinValue
			rs.MaxValue = rs.Value * r.MaxValue
			rs.Precise = false
		}
	} else {
		if r.Precise {
			rs.MaxValue = rs.MaxValue * r.Value
		} else {
			rs.MaxValue = rs.MaxValue * r.MaxValue
		}
	}
}

func (rs *RegisterState) DivIMM(i int64) {
	if i == 0 {
		return
	}

	if rs.Precise {
		rs.Value = rs.Value / i
	} else {
		rs.MinValue = rs.MinValue / i
		rs.MaxValue = rs.MaxValue / i
	}
}

func (rs *RegisterState) DivReg(r RegisterState) {
	if rs.Precise {
		if r.Precise {
			if r.Value == 0 {
				return
			}

			rs.Value = rs.Value / r.Value
		} else {
			if r.MinValue != 0 {
				rs.MinValue = rs.Value / r.MinValue
			}
			if r.MaxValue != 0 {
				rs.MaxValue = rs.Value / r.MaxValue
			}
			rs.Precise = false
		}
	} else {
		if r.Precise {
			if r.Value != 0 {
				rs.MaxValue = rs.MaxValue / r.Value
			}
		} else {
			if r.MaxValue != 0 {
				rs.MaxValue = rs.MaxValue / r.MaxValue
			}
		}
	}
}

func (rs *RegisterState) OrIMM(i int64) {
	if rs.Precise {
		rs.Value = i | rs.Value
	} else {
		rs.MinValue = i | rs.MinValue
		rs.MaxValue = i | rs.MaxValue
	}
}

func (rs *RegisterState) OrReg(r RegisterState) {
	if rs.Precise {
		if r.Precise {
			rs.Value = rs.Value | r.Value
		} else {
			rs.MinValue = rs.Value | r.MinValue
			rs.MaxValue = rs.Value | r.MaxValue
			rs.Precise = false
		}
	} else {
		if r.Precise {
			rs.MaxValue = rs.MaxValue | r.Value
		} else {
			rs.MaxValue = rs.MaxValue | r.MaxValue
		}
	}
}

func (rs *RegisterState) AndIMM(i int64) {
	if rs.Precise {
		rs.Value = i & rs.Value
	} else {
		rs.MaxValue = i & rs.MaxValue
	}
}

func (rs *RegisterState) AndReg(r RegisterState) {
	if rs.Precise {
		if r.Precise {
			rs.Value = rs.Value & r.Value
		} else {
			rs.MinValue = rs.Value & r.MinValue
			rs.MaxValue = rs.Value & r.MaxValue
			rs.Precise = false
		}
	} else {
		if r.Precise {
			rs.MaxValue = rs.MaxValue & r.Value
		} else {
			rs.MaxValue = rs.MaxValue & r.MaxValue
		}
	}
}

func (rs *RegisterState) LShIMM(i int64) {
	if rs.Precise {
		rs.Value = rs.Value << i
	} else {
		if rs.maxRange() {
			return
		}

		rs.MinValue = rs.MinValue << i
		rs.MaxValue = rs.MaxValue << i
	}
}

func (rs *RegisterState) LShReg(r RegisterState) {
	if rs.Precise {
		if r.Precise {
			rs.Value = rs.Value << r.Value
		} else {
			rs.MinValue = rs.Value << r.MinValue
			rs.MaxValue = rs.Value << r.MaxValue
			rs.Precise = false
		}
	} else {
		if r.Precise {
			rs.MaxValue = rs.MaxValue << r.Value
		} else {
			rs.MaxValue = rs.MaxValue << r.MaxValue
		}
	}
}

func (rs *RegisterState) RShIMM(i int64) {
	if rs.Precise {
		rs.Value = rs.Value >> i
	} else {
		if rs.maxRange() {
			return
		}

		rs.MinValue = rs.MinValue >> i
		rs.MaxValue = rs.MaxValue >> i
	}
}

func (rs *RegisterState) RShReg(r RegisterState) {
	if rs.Precise {
		if r.Precise {
			rs.Value = rs.Value >> r.Value
		} else {
			rs.MinValue = rs.Value >> r.MinValue
			rs.MaxValue = rs.Value >> r.MaxValue
			rs.Precise = false
		}
	} else {
		if r.Precise {
			rs.MaxValue = rs.MaxValue >> r.Value
		} else {
			rs.MaxValue = rs.MaxValue >> r.MaxValue
		}
	}
}

func (rs *RegisterState) Neg() {
	if rs.Precise {
		rs.Value = -rs.Value
	} else {
		tmp := rs.MinValue
		rs.MinValue = -rs.MaxValue
		rs.MaxValue = -tmp
	}
}

func (rs *RegisterState) ModIMM(i int64) {
	if i == 0 {
		return
	}

	if rs.Precise {
		rs.Value = rs.Value % i
	} else {
		rs.MinValue = rs.MinValue % i
		rs.MaxValue = rs.MaxValue % i
	}
}

func (rs *RegisterState) ModReg(r RegisterState) {
	if rs.Precise {
		if r.Precise {
			if r.Value == 0 {
				return
			}

			rs.Value = rs.Value % r.Value
		} else {
			if r.MinValue != 0 {
				rs.MinValue = rs.Value % r.MinValue
			}
			if r.MaxValue != 0 {
				rs.MaxValue = rs.Value % r.MaxValue
			}
			rs.Precise = false
		}
	} else {
		if r.Precise {
			if r.Value != 0 {
				rs.MaxValue = rs.MaxValue % r.Value
			}
		} else {
			if r.MaxValue != 0 {
				rs.MaxValue = rs.MaxValue % r.MaxValue
			}
		}
	}
}

func (rs *RegisterState) XorIMM(i int64) {
	if rs.Precise {
		rs.Value = i ^ rs.Value
	} else {
		rs.MaxValue = i ^ rs.MaxValue
	}
}

func (rs *RegisterState) XorReg(r RegisterState) {
	if rs.Precise {
		if r.Precise {
			rs.Value = rs.Value ^ r.Value
		} else {
			rs.MinValue = rs.Value ^ r.MinValue
			rs.MaxValue = rs.Value ^ r.MaxValue
			rs.Precise = false
		}
	} else {
		if r.Precise {
			rs.MaxValue = rs.MaxValue ^ r.Value
		} else {
			rs.MaxValue = rs.MaxValue ^ r.MaxValue
		}
	}
}

func (rs RegisterState) String() string {
	switch rs.Type {
	case RVNotInit:
		return "uninit"

	case RVScalar:
		if rs.Precise {
			return fmt.Sprintf("Inv%d", rs.Value)
		}

		if rs.MinValue == -math.MaxInt64 && rs.MaxValue == math.MaxInt64 {
			return "Inv"
		} else {
			if rs.MinValue != -math.MaxInt64 {
				if rs.MaxValue != math.MaxInt64 {
					return fmt.Sprintf("Inv(min_value=%d, max_value=%d)", rs.MinValue, rs.MaxValue)
				}

				return fmt.Sprintf("Inv(min_value=%d)", rs.MinValue)
			}

			return fmt.Sprintf("Inv(max_value=%d)", rs.MaxValue)
		}

	case RVPtrToStack:
		if rs.Precise {
			if rs.Value == 0 {
				return fmt.Sprintf("fp%d", rs.FrameNo)
			}

			return fmt.Sprintf("fp%d%d", rs.FrameNo, rs.Value)
		}

		return fmt.Sprintf("fp%d(%d,%d)", rs.FrameNo, rs.MaxValue, rs.MaxValue)
	default:
		return fmt.Sprintf("Unknown(%d)", rs.Type)
	}
}

type RegisterValueType int

func (rvt RegisterValueType) Init() bool {
	return rvt != RVNotInit
}

func (rvt RegisterValueType) IsScalar() bool {
	return rvt == RVScalar
}

func (rvt RegisterValueType) IsPtr() bool {
	return rvt == RVPtrToStack
}

const (
	// Register is not initialized
	RVNotInit RegisterValueType = iota
	// Register contains a scalar value
	RVScalar
	// RVPtrToCtx
	// RVConstMapPtr
	// RVPtrToMapValue
	// RVPtrToKeyValue
	RVPtrToStack
	// Register is in use, but by a value type we don't distinctly know
	RVUnknown
)

type CheckerLogLevel int

const (
	None CheckerLogLevel = iota
	Basic
	Verbose
)

// TODO this needs a better name
type Checker struct {
	Pending           chan *ProgramState
	UnionStatePerFunc map[string]FuncState
}

const maxPendingPermutations = 100000

func NewChecker() *Checker {
	return &Checker{
		Pending:           make(chan *ProgramState, maxPendingPermutations),
		UnionStatePerFunc: make(map[string]FuncState),
	}
}

var ErrMaxInst = errors.New("reached max amount of instructions to analyse")

func (c *Checker) Check(initialState *ProgramState, logLevel CheckerLogLevel) error {
	curState := initialState

	curState.Frame().Registers[asm.R10] = RegisterState{
		Type:    RVPtrToStack,
		Precise: true,
	}

	nextPermutation := func() bool {
		select {
		case curState = <-c.Pending:
			if logLevel > None {
				fmt.Println("---")
			}
			return false
		default:
			return true
		}
	}

	if logLevel > None {
		fmt.Println("Program state checker log:")
		defer fmt.Println("")
	}

	curState.FuncName = curState.Prog[curState.InstOff].Symbol()

	const instMax = 1000000
	for i := 0; i < instMax; i++ {
		// If out of bounds
		if curState.InstOff >= len(curState.Prog) {
			// TODO error instread ?
			if nextPermutation() {
				return nil
			}
			continue
		}

		// The current instruction
		inst := curState.Inst()
		f := curState.Frame()

		if logLevel >= Verbose {
			fmt.Printf("%d: %s\n", curState.InstOff, curState.String())
		}
		if logLevel >= Basic {
			fmt.Printf("%d: (%x) %v\n", curState.InstOff, uint8(inst.OpCode), inst)
		}

		// Make union per func
		funcUnion := c.UnionStatePerFunc[curState.FuncName]
		mergeFuncState(&funcUnion, *curState.Frame())
		c.UnionStatePerFunc[curState.FuncName] = funcUnion

		switch inst.OpCode.Class() {
		case asm.ALUClass, asm.ALU64Class:
			dst := &f.Registers[inst.Dst]
			src := f.Registers[inst.Src]

			switch asm.ALUOp(inst.OpCode & 0xF8) {
			case asm.Add | asm.ALUOp(asm.ImmSource):
				dst.AddIMM(inst.Constant)
			case asm.Add | asm.ALUOp(asm.RegSource):
				dst.AddReg(src)

			case asm.Sub | asm.ALUOp(asm.ImmSource):
				dst.SubIMM(inst.Constant)
			case asm.Sub | asm.ALUOp(asm.RegSource):
				dst.SubReg(src)

			case asm.Mul | asm.ALUOp(asm.ImmSource):
				dst.MulIMM(inst.Constant)
			case asm.Mul | asm.ALUOp(asm.RegSource):
				dst.MulReg(src)

			case asm.Div | asm.ALUOp(asm.ImmSource):
				dst.DivIMM(inst.Constant)
			case asm.Div | asm.ALUOp(asm.RegSource):
				dst.DivReg(src)

			case asm.Or | asm.ALUOp(asm.ImmSource):
				dst.OrIMM(inst.Constant)
			case asm.Or | asm.ALUOp(asm.RegSource):
				dst.OrReg(src)

			case asm.And | asm.ALUOp(asm.ImmSource):
				dst.AndIMM(inst.Constant)
			case asm.And | asm.ALUOp(asm.RegSource):
				dst.AndReg(src)

			case asm.LSh | asm.ALUOp(asm.ImmSource):
				dst.LShIMM(inst.Constant)
			case asm.LSh | asm.ALUOp(asm.RegSource):
				dst.LShReg(src)

			case asm.RSh | asm.ALUOp(asm.ImmSource):
				dst.RShIMM(inst.Constant)
			case asm.RSh | asm.ALUOp(asm.RegSource):
				dst.RShReg(src)

			case asm.Neg:
				dst.Neg()

			case asm.Mod | asm.ALUOp(asm.ImmSource):
				dst.ModIMM(inst.Constant)
			case asm.Mod | asm.ALUOp(asm.RegSource):
				dst.ModReg(src)

			case asm.Xor | asm.ALUOp(asm.ImmSource):
				dst.XorIMM(inst.Constant)
			case asm.Xor | asm.ALUOp(asm.RegSource):
				dst.XorReg(src)

			case asm.Mov | asm.ALUOp(asm.ImmSource):
				*dst = RegisterState{
					Type:    RVScalar,
					Precise: true,
					Value:   inst.Constant,
				}

			case asm.Mov | asm.ALUOp(asm.RegSource):
				*dst = src

			// TODO case asm.ArSh:
			case asm.Swap, asm.Swap | asm.ALUOp(asm.RegSource):
				// TODO implement swap for precise values
			default:
				return fmt.Errorf("unimplemented ALU inst: %v", inst)
			}

		case asm.JumpClass, asm.Jump32Class:
			branchState := curState.Copy()
			branchDst := &branchState.Frame().Registers[inst.Dst]
			nonBranchDst := &curState.Frame().Registers[inst.Dst]

			possible := true

			switch asm.JumpOp(inst.OpCode & 0xF8) {
			case asm.Ja:
				// unconditional jump
				possible = false
				curState.InstOff += int(inst.Offset)

			case asm.JEq | asm.JumpOp(asm.ImmSource):
				if branchDst.Precise && branchDst.Value != inst.Constant {
					possible = false
				} else {
					branchDst.Value = inst.Constant
					branchDst.Precise = true
				}

			// TODO case asm.JEq | asm.JumpOp(asm.RegSource):
			case asm.JGT | asm.JumpOp(asm.ImmSource):
				if branchDst.Precise && branchDst.Value <= inst.Constant {
					possible = false
				} else {
					if !branchDst.Precise {
						branchDst.MinValue = inst.Constant + 1
					}
				}

				if !nonBranchDst.Precise {
					nonBranchDst.MaxValue = inst.Constant
				}

			case asm.JGT | asm.JumpOp(asm.RegSource):
				src := curState.Frame().Registers[inst.Src]
				if branchDst.Precise && src.Precise && branchDst.Value <= src.Value {
					possible = false
				} else {
					if !branchDst.Precise && src.Precise {
						branchDst.MinValue = src.Value + 1
						nonBranchDst.MaxValue = src.Value
					}
				}

			case asm.JGE | asm.JumpOp(asm.ImmSource):

				if branchDst.Precise && branchDst.Value <= inst.Constant {
					possible = false
				} else {
					if !branchDst.Precise {
						branchDst.MinValue = inst.Constant
					}
				}

				if !nonBranchDst.Precise {
					nonBranchDst.MaxValue = inst.Constant - 1
				}

			case asm.JGE | asm.JumpOp(asm.RegSource):
				src := curState.Frame().Registers[inst.Src]
				if branchDst.Precise && src.Precise && branchDst.Value <= src.Value {
					possible = false
				} else {
					if !branchDst.Precise && src.Precise {
						branchDst.MinValue = src.Value
						nonBranchDst.MaxValue = src.Value - 1
					}
				}

			// TODO case asm.JSet:
			// TODO case asm.JNE:
			case asm.JNE | asm.JumpOp(asm.ImmSource):
				if branchDst.Precise && branchDst.Value == inst.Constant {
					possible = false
				} else {
					nonBranchDst.Value = inst.Constant
					nonBranchDst.Precise = true
				}

			// TODO case asm.JSGT:
			// TODO case asm.JSGE:

			case asm.Call:
				if inst.IsBuiltinCall() {
					var (
						buf asm.Register
						len asm.Register
					)
					switch asm.BuiltinFunc(inst.Constant) {
					case asm.FnProbeRead,
						asm.FnGetCurrentComm,
						asm.FnProbeReadStr,
						asm.FnProbeReadUser,
						asm.FnProbeReadKernel,
						asm.FnProbeReadUserStr,
						asm.FnProbeReadKernelStr,
						asm.FnCopyFromUser,
						asm.FnSnprintfBtf,
						asm.FnSnprintf:
						buf = asm.R1
						len = asm.R2

					case asm.FnSkbGetTunnelKey,
						asm.FnSkbGetTunnelOpt,
						asm.FnPerfProgReadValue,
						asm.FnGetStack,
						asm.FnReadBranchRecords,
						asm.FnGetTaskStack,
						asm.FnImaInodeHash,
						asm.FnSysBpf:
						buf = asm.R2
						len = asm.R3

					case asm.FnPerfEventReadValue,
						asm.FnSkbGetXfrmState,
						asm.FnSkLookupTcp,
						asm.FnSkLookupUdp,
						asm.FnSkcLookupTcp,
						asm.FnGetNsCurrentPidTgid:
						buf = asm.R3
						len = asm.R4

					case asm.FnGetsockopt,
						asm.FnSkbOutput,
						asm.FnXdpOutput:
						buf = asm.R4
						len = asm.R5
					}
					if buf != 0 && len != 0 {
						f.Stack.WriteMisc(int(f.Registers[buf].Value), int(f.Registers[len].Value))
					}

					// Clobber R1-R5
					for i := asm.R1; i <= asm.R5; i++ {
						f.Registers[i].Type = RVNotInit
					}
					// R0 = return value
					f.Registers[asm.R0] = RegisterState{
						Type:     RVScalar,
						Precise:  false,
						MinValue: -math.MaxInt64,
						MaxValue: math.MaxInt64,
					}

				} else {
					// BPF-to-BPF call

					if curState.CurFrame+1 >= len(curState.Frames) {
						if nextPermutation() {
							return nil
						}
						continue
					}

					newFrame := &curState.Frames[curState.CurFrame+1]
					// Copy R1-R5 to the new frame
					for i := asm.R1; i <= asm.R5; i++ {
						newFrame.Registers[i] = curState.Frame().Registers[i]
					}
					// De-init R6-R9 in case they were set somewhere in the past
					for i := asm.R6; i <= asm.R9; i++ {
						newFrame.Registers[i] = RegisterState{
							Type: RVNotInit,
						}
					}
					// Set R10, in case this is the first time using this frame
					newFrame.Registers[asm.R10] = RegisterState{
						Type: RVPtrToStack,
					}

					// Zero-init stack
					newFrame.Stack = StackState{}

					// Change frame
					curState.CurFrame++
					newFrame.FrameNumber = curState.CurFrame

					// Set callsite(used when returning)
					newFrame.Callsite = curState.InstOff

					// Change current instruction to func referenced by Call inst
					for i, checkInst := range curState.Prog {
						if checkInst.Symbol() == inst.Reference() {
							curState.InstOff = i - 1
							curState.FuncName = inst.Reference()
							break
						}
					}
				}

				// Call is not a branching instruction
				possible = false

			case asm.Exit:
				if curState.CurFrame > 0 {
					// Return

					newFrame := &curState.Frames[curState.CurFrame-1]
					// Clobber R1-R5
					for i := asm.R1; i <= asm.R5; i++ {
						newFrame.Registers[i] = RegisterState{
							Type: RVNotInit,
						}
					}

					// Keep R0 which is the return value
					newFrame.Registers[asm.R0] = curState.Frame().Registers[asm.R0]

					// Set R10, in case it somehow was modified(which is invalid)
					newFrame.Registers[asm.R10] = RegisterState{
						Type: RVPtrToStack,
					}

					// Set intoOff to callsite
					curState.InstOff = curState.Frame().Callsite
					// Switch frame
					curState.CurFrame--

				} else {
					// Exit

					if nextPermutation() {
						return nil
					}
					continue
				}

			// TODO case asm.JLT:
			// TODO case asm.JLE:
			// TODO case asm.JSLT:
			// TODO case asm.JSLE:

			default:
				return fmt.Errorf("unimplemented Jmp inst: %v", inst)
			}

			if possible {
				branchState.InstOff = branchState.InstOff + int(inst.Offset) + 1
				select {
				case c.Pending <- &branchState:
				default:
				}
			}

		case asm.LdXClass:
			switch inst.OpCode & 0xE0 {
			case asm.OpCode(asm.MemMode):
				src := f.Registers[inst.Src]
				if !src.Precise {
					// TODO implement bounded loops(var-off)

					f.Registers[inst.Dst] = RegisterState{
						Type:     RVScalar,
						Precise:  false,
						MinValue: -math.MaxInt64,
						MaxValue: math.MaxInt64,
					}
				}

				// Invert offset to get a positive number(assuming value + offset is negative)
				off := 0 - (src.Value + int64(inst.Offset))

				if src.Type == RVPtrToStack {
					slotIdx := int((off - 1) / regSize)

					slot := &f.Stack.Slots[slotIdx]
					slotOff := (1 + (off-1)%regSize) - int64(inst.OpCode.Size().Sizeof())
					if slotOff < 0 {
						slotOff = -slotOff
					}

					switch slot.SlotTypes[slotOff] {
					case SlotTypeInvalid, SlotTypeMisc:
						// TODO error on invalid?
						f.Registers[inst.Dst] = RegisterState{
							Type:     RVScalar,
							Precise:  false,
							MinValue: -math.MaxInt64,
							MaxValue: math.MaxInt64,
						}

					case SlotTypeSpill:
						f.Registers[inst.Dst] = *slot.Spilled

					case SlotTypeZero:
						// TODO account for size?
						f.Registers[inst.Dst] = RegisterState{
							Type:    RVScalar,
							Precise: true,
							Value:   0,
						}
					}
				} else {
					f.Registers[inst.Dst] = RegisterState{
						Type:     RVScalar,
						Precise:  false,
						MinValue: -math.MaxInt64,
						MaxValue: math.MaxInt64,
					}
				}

			default:
				return fmt.Errorf("unimplemented Ldx inst: %v", inst)
			}

		case asm.LdClass:
			dst := &f.Registers[inst.Dst]
			switch inst.OpCode {
			case asm.LoadImmOp(asm.DWord):
				// Load Dword
				if inst.OpCode.IsDWordLoad() {
					*dst = RegisterState{
						Type:    RVScalar,
						Precise: true,
						Value:   inst.Constant,
					}
				}

				// MapValue
				if inst.Src == asm.PseudoMapValue {
					*dst = RegisterState{
						Type:     RVScalar,
						Precise:  false,
						MinValue: -math.MaxInt64,
						MaxValue: math.MaxInt64,
					}
				}

			// TODO case asm.OpCode(asm.AbsMode):
			// 	// Load from sk_buff @ abs pos
			// TODO case asm.OpCode(asm.IndMode):
			// 	// Load from sk_buff @ rel pos
			default:
				return fmt.Errorf("unimplemented Ld inst: %v", inst)
			}

		case asm.StClass:
			switch inst.OpCode & 0xF0 {
			// TODO case asm.OpCode(asm.AbsMode):
			// 	// Store to sk_buff @ abs pos
			// TODO case asm.OpCode(asm.IndMode):
			// 	//  Store to  sk_buff @ rel pos
			default:
				return fmt.Errorf("unimplemented St inst: %v", inst)
			}

		case asm.StXClass:
			dst := &f.Registers[inst.Dst]
			src := f.Registers[inst.Src]

			switch inst.OpCode & 0xE0 {
			case asm.OpCode(asm.MemMode):
				// Store to stack

				f.Stack.WriteReg(int(dst.Value)+int(inst.Offset), inst.OpCode.Size(), src)

			// TODO case asm.OpCode(asm.XAddMode):
			// 	// Store to stack atomically
			default:
				return fmt.Errorf("unimplemented Stx inst: %v", inst)
			}

		default:
			return fmt.Errorf("unknown instruction class, inst %d, %v", curState.InstOff, inst)
		}

		// Next instruction
		curState.InstOff++
		if inst.OpCode.IsDWordLoad() {
			// If next instruction is Dword load, next inst is a no-op, skip it to
			curState.InstOff++
		}
	}

	return ErrMaxInst
}

func mergeFuncState(a *FuncState, b FuncState) {
	for i := asm.R0; i <= asm.R9; i++ {
		if b.Registers[i].Type != RVNotInit {
			a.Registers[i] = b.Registers[i]
		}
	}

	if len(a.Stack.Slots) < len(b.Stack.Slots) {
		diff := len(b.Stack.Slots) - len(a.Stack.Slots)
		a.Stack.Slots = append(a.Stack.Slots, make([]StackSlot, diff)...)
	}
	for i, slot := range b.Stack.Slots {
		empty := true
		for _, t := range slot.SlotTypes {
			if t != SlotTypeInvalid {
				empty = false
				break
			}
		}
		if empty {
			continue
		}

		a.Stack.Slots[i] = slot
		if slot.Spilled != nil {
			var spilled RegisterState
			spilled = *slot.Spilled
			a.Stack.Slots[i].Spilled = &spilled
		}
	}
}
