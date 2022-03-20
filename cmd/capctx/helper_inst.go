package capctx

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
)

type helperInstructions struct {
	// Executed before the call, R0 is set to fp0, params to the helper can now be captured
	pre []asm.Instruction
	// Executed after call, R0 is result
	post []asm.Instruction
}

var helperInstr map[asm.BuiltinFunc]helperInstructions

func helperInstrumentation(fpOff, primarySaveOff int16) map[asm.BuiltinFunc]helperInstructions {
	if len(helperInstr) > 0 {
		return helperInstr
	}

	helperInstr = make(map[asm.BuiltinFunc]helperInstructions)
	for fn, helper := range helpers {
		var inst helperInstructions

		// Send all input params
		inst.pre = sendRInScalars(len(helper.params), fpOff, primarySaveOff)

		// Send return value if not void
		if helper.retType != "void" {
			inst.post = sendROutScalar(asm.R0, fpOff)
		}

		helperInstr[fn] = inst
	}

	customInstr := map[asm.BuiltinFunc]helperInstructions{
		asm.FnProbeRead:       singleDataReturnInstr(asm.R1, asm.R2, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnGetCurrentComm:  singleDataReturnInstr(asm.R1, asm.R2, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnSkbGetTunnelKey: singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnSkbLoadBytes:    singleDataReturnInstr(asm.R3, asm.R4, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnSkbGetTunnelOpt: singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		// TODO asm.FnGetCurrentTask
		asm.FnProbeReadStr:         singleDataReturnInstr(asm.R1, asm.R2, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnPerfEventReadValue:   singleDataReturnInstr(asm.R3, asm.R4, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnPerfProgReadValue:    singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnGetStack:             singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnSkbLoadBytesRelative: singleDataReturnInstr(asm.R3, asm.R4, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnFibLookup:            singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnSkLookupTcp:          singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnSkLookupUdp:          singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		// TODO asm.FnSkRelease
		// TODO asm.FnSkFullsock
		// TODO asm.FnSkTcpSock
		// TODO asm.FnSkbEcnSetCe
		// TODO asm.FnGetListenerSock
		// TODO asm.FnSkcLookupTcp
		asm.FnSysctlGetName:         singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnSysctlGetCurrentValue: singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnSysctlGetNewValue:     singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnProbeReadUser:         singleDataReturnInstr(asm.R1, asm.R2, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnProbeReadKernel:       singleDataReturnInstr(asm.R1, asm.R2, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnProbeReadUserStr:      singleDataReturnInstr(asm.R1, asm.R2, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnProbeReadKernelStr:    singleDataReturnInstr(asm.R1, asm.R2, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnReadBranchRecords:     singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnGetNsCurrentPidTgid:   singleDataReturnInstr(asm.R3, asm.R4, defaultMaxSize, fpOff, primarySaveOff),
		// TODO asm.FnSkcToTcp6Sock
		// TODO asm.FnSkcToTcpSock
		// TODO asm.FnSkcToTcpTimewaitSock
		// TODO asm.FnSkcToTcpRequestSock
		// TODO asm.FnSkcToUdp6Sock
		asm.FnGetTaskStack: singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnLoadHdrOpt:   singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnDPath:        singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		asm.FnCopyFromUser: singleDataReturnInstr(asm.R1, asm.R2, defaultMaxSize, fpOff, primarySaveOff),
		// TODO asm.FnPerCpuPtr
		// TODO asm.FnThisCpuPtr
		// TODO asm.FnGetCurrentTaskBtf
		asm.FnImaInodeHash: singleDataReturnInstr(asm.R2, asm.R3, defaultMaxSize, fpOff, primarySaveOff),
		// TODO asm.FnSockFromFile
		asm.FnSnprintf: singleDataReturnInstr(asm.R1, asm.R2, defaultMaxSize, fpOff, primarySaveOff),
		// TODO asm.FnTaskPtRegs
		// bpf_get_branch_snapshot
		asm.BuiltinFunc(176): singleDataReturnInstr(asm.R1, asm.R2, defaultMaxSize, fpOff, primarySaveOff),
		// TODO bpf_get_func_arg
		// TODO bpf_get_func_ret
	}

	for k, v := range customInstr {
		inst := helperInstr[k]
		inst.pre = append(inst.pre, v.pre...)
		inst.post = append(inst.post, v.post...)
		helperInstr[k] = inst
	}

	return helperInstr
}

const defaultMaxSize = 128

func singleDataReturnInstr(ptr, size asm.Register, max uint16, fpOff, primarySaveOff int16) helperInstructions {
	return helperInstructions{
		pre: saveRegs(primarySaveOff, ptr, size),
		post: merge(
			restoreRegs(primarySaveOff, ptr, size),
			sendRoutData(ptr, size, max, fpOff),
		),
	}
}

func merge(slices ...[]asm.Instruction) []asm.Instruction {
	cnt := 0
	for _, slice := range slices {
		cnt += len(slice)
	}
	new := make([]asm.Instruction, 0, cnt)
	for _, slice := range slices {
		new = append(new, slice...)
	}
	return new
}

func sendHelperID(fn asm.BuiltinFunc, fpOff, primarySaveOff int16) []asm.Instruction {
	return []asm.Instruction{
		// Get fp0
		asm.LoadMem(asm.R0, asm.R10, fpOff, asm.DWord),
		// Save R9 in current stack frame
		asm.StoreMem(asm.R10, primarySaveOff, asm.R9, asm.DWord),
		// Load ptr to buffer at current offset
		asm.LoadMem(asm.R9, asm.R0, bufferPtr, asm.DWord),
		// Write message type to buffer
		asm.StoreImm(asm.R9, 0, int64(helperIDMsg), asm.Byte),
		// Write helper func nr (4 bytes)
		asm.StoreImm(asm.R9, 1, int64(fn), asm.Word),
		// Increment buf ptr by 5 bytes
		asm.Add.Imm(asm.R9, 5),
		// Write incremented buf ptr back
		asm.StoreMem(asm.R0, bufferPtr, asm.R9, asm.DWord),
		// Restore R9
		asm.LoadMem(asm.R9, asm.R10, primarySaveOff, asm.DWord),
	}
}

func sendRInScalars(num int, fpOff, primarySaveOff int16) []asm.Instruction {
	insts := make([][]asm.Instruction, 0)
	for i := asm.R1; i <= asm.Register(num); i++ {
		insts = append(insts, sendRInScalar(i, fpOff, primarySaveOff))
	}
	return merge(insts...)
}

func sendRInScalar(r asm.Register, fpOff, primarySaveOff int16) []asm.Instruction {
	// Use R0 since it will be clobbered by the helper function. use R9 since R1-R5 are inputs, but restore it
	// afterwards.
	return []asm.Instruction{
		// Get fp0
		asm.LoadMem(asm.R0, asm.R10, fpOff, asm.DWord),
		// Save R9 in current stack frame
		asm.StoreMem(asm.R10, primarySaveOff, asm.R9, asm.DWord),
		// Load ptr to buffer at current offset
		asm.LoadMem(asm.R9, asm.R0, bufferPtr, asm.DWord),
		// Write message type to buffer
		asm.StoreImm(asm.R9, 0, int64(rInScalar), asm.Byte),
		// Write register number to buffer
		asm.StoreImm(asm.R9, 1, int64(r), asm.Byte),
		// Write register contents
		asm.StoreMem(asm.R9, 2, r, asm.DWord),
		// Increment buf ptr by 10 bytes
		asm.Add.Imm(asm.R9, 10),
		// Write incremented buf ptr back
		asm.StoreMem(asm.R0, bufferPtr, asm.R9, asm.DWord),
		// Restore R9
		asm.LoadMem(asm.R9, asm.R10, primarySaveOff, asm.DWord),
	}
}

// save the contents of a register before a function call, which allows us to restore it afterwards
func saveRegs(primarySaveOff int16, regs ...asm.Register) []asm.Instruction {
	switch len(regs) {
	case 0:
		return nil
	case 1:
		return []asm.Instruction{
			asm.StoreMem(asm.R10, primarySaveOff, regs[0], asm.DWord),
		}
	case 2:
		return []asm.Instruction{
			asm.StoreMem(asm.R10, primarySaveOff, regs[0], asm.DWord),
			asm.StoreMem(asm.R10, primarySaveOff-8, regs[1], asm.DWord),
		}
	default:
		// We don't expect to need more than 2 regs ever. Needing to save more regs requires more reserved stack space.
		panic("can't save more than 2 regs")
	}
}

// restore the contents of a register saved by the saveRegs snippet
func restoreRegs(primarySaveOff int16, regs ...asm.Register) []asm.Instruction {
	switch len(regs) {
	case 0:
		return nil
	case 1:
		return []asm.Instruction{
			asm.LoadMem(regs[0], asm.R10, primarySaveOff, asm.DWord),
		}
	case 2:
		return []asm.Instruction{
			asm.LoadMem(regs[0], asm.R10, primarySaveOff, asm.DWord),
			asm.LoadMem(regs[1], asm.R10, primarySaveOff-8, asm.DWord),
		}
	default:
		// We don't expect to need more than 2 regs ever. Needing to save more regs requires more reserved stack space.
		panic("can't save more than 2 regs")
	}
}

var sendRoutDataCount = 0

func sendRoutData(ptr asm.Register, size asm.Register, maxSize uint16, fpOff int16) []asm.Instruction {
	// Pick a call clobbered register which is not `ptr` or `size`
	bufPtr := asm.R1
	for ; bufPtr <= asm.R5; bufPtr++ {
		if bufPtr != ptr && bufPtr != size {
			break
		}
	}

	// Pick a call clobbered register which is not `ptr`, `size` or `bufPtr`
	iReg := asm.R1
	for ; iReg <= asm.R5; iReg++ {
		if iReg != ptr && iReg != size && iReg != bufPtr {
			break
		}
	}

	// Pick a call clobbered register which is not `ptr`, `size`,  `bufPtr` or `iReg`
	tmpReg := asm.R1
	for ; tmpReg <= asm.R5; tmpReg++ {
		if tmpReg != ptr && tmpReg != size && tmpReg != bufPtr && tmpReg != iReg {
			break
		}
	}

	// Increment the global counter var when we are done
	defer func() { sendRoutDataCount++ }()
	cmpLabel := fmt.Sprintf("edb-send-rout-cmp-%d", sendRoutDataCount)
	nosizeLabel := fmt.Sprintf("edb-send-rout-nosize-%d", sendRoutDataCount)
	doneLabel := fmt.Sprintf("edb-send-rout-done-%d", sendRoutDataCount)

	return []asm.Instruction{
		// Get fp0
		asm.LoadMem(bufPtr, asm.R10, fpOff, asm.DWord),
		// Get buf ptr
		asm.LoadMem(bufPtr, bufPtr, bufferPtr, asm.DWord),
		// Set the message type
		asm.StoreImm(bufPtr, 0, int64(rOutData), asm.Byte),
		// Set the register number
		asm.StoreImm(bufPtr, 1, int64(ptr), asm.Byte),
		// reserve 4 bytes(msg type + reg num + size) for the size.
		asm.Add.Imm(bufPtr, 4),

		// Makes sure size never exceeds the given max size, which helps limit the amount of instructions the verifier
		// has so simulate.
		asm.JSLT.Imm(size, int32(maxSize), nosizeLabel),
		asm.Mov.Imm(size, int32(maxSize)),
		// int i = 0;
		asm.Mov.Imm(iReg, 0).WithSymbol(nosizeLabel),
		// while i < size
		asm.JGE.Reg(iReg, size, doneLabel).WithSymbol(cmpLabel),
		// bufPtr++ = ptr++
		asm.LoadMem(tmpReg, ptr, 0, asm.Byte),
		asm.StoreMem(bufPtr, 0, tmpReg, asm.Byte),
		asm.Add.Imm(ptr, 1),
		asm.Add.Imm(bufPtr, 1),
		// i++
		asm.Add.Imm(iReg, 1),
		// goto cmpLabel
		asm.Ja.Label(cmpLabel),

		// Get fp0
		asm.LoadMem(tmpReg, asm.R10, fpOff, asm.DWord).WithSymbol(doneLabel),
		// Get original buf ptr
		asm.LoadMem(ptr, tmpReg, bufferPtr, asm.DWord),
		// Write size
		asm.StoreMem(ptr, 2, iReg, asm.Half),
		// Store buf ptr
		asm.StoreMem(tmpReg, bufferPtr, bufPtr, asm.DWord),
	}
}

func sendROutScalar(r asm.Register, fpOff int16) []asm.Instruction {
	// Similar to the R-in scalar version, but use R1 and R2, they are available since the helper call
	// with have clobbered them
	return []asm.Instruction{
		// Get fp0
		asm.LoadMem(asm.R1, asm.R10, fpOff, asm.DWord),
		// Load ptr to buffer at current offset
		asm.LoadMem(asm.R2, asm.R1, bufferPtr, asm.DWord),
		// Write message type to buffer
		asm.StoreImm(asm.R2, 0, int64(rOutScalar), asm.Byte),
		// Write register number to buffer
		asm.StoreImm(asm.R2, 1, int64(r), asm.Byte),
		// Write register contents
		asm.StoreMem(asm.R2, 2, r, asm.DWord),
		// Increment buf ptr by 10 bytes
		asm.Add.Imm(asm.R2, 10),
		// Write incremented buf ptr back
		asm.StoreMem(asm.R1, bufferPtr, asm.R2, asm.DWord),
	}
}
