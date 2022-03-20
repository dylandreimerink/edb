package analyse

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"golang.org/x/exp/slices"
)

func ProgramBlocks(prog asm.Instructions) []*ProgBlock {
	prog = slices.Clone(prog)

	// Make a RawInstOffset -> instruction lookup which improves performance during jump labeling
	iter := prog.Iterate()
	offToInst := map[asm.RawInstructionOffset]*asm.Instruction{}
	for iter.Next() {
		offToInst[iter.Offset] = iter.Ins
	}

	iter = prog.Iterate()
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

	blocks := make([]*ProgBlock, 0)
	curBlock := &ProgBlock{}
	for _, inst := range prog {
		if inst.Symbol() != "" {
			if len(curBlock.Block) > 0 {
				newBlock := &ProgBlock{
					Index: curBlock.Index + 1,
				}
				curBlock.NoBranch = newBlock
				blocks = append(blocks, curBlock)
				curBlock = newBlock
			}
		}

		curBlock.Block = append(curBlock.Block, inst)

		// Continue on non-jump ops
		op := inst.OpCode.JumpOp()
		if op == asm.InvalidJumpOp {
			continue
		}

		newBlock := &ProgBlock{
			Index: curBlock.Index + 1,
		}

		if op != asm.Exit {
			// If the current op is exit, then the current block will not continue into the block after it.
			curBlock.NoBranch = newBlock
		}

		blocks = append(blocks, curBlock)
		curBlock = newBlock
	}

	symToBlock := make(map[string]*ProgBlock)
	for _, block := range blocks {
		sym := block.Block[0].Symbol()
		if sym != "" {
			symToBlock[sym] = block
		}
	}

	for _, block := range blocks {
		lastInst := block.Block[len(block.Block)-1]

		// Ignore non-jump ops and exit's
		op := lastInst.OpCode.JumpOp()
		switch op {
		case asm.InvalidJumpOp, asm.Exit:
			continue
		}

		block.Branch = symToBlock[lastInst.Reference()]
	}

	return blocks
}

type ProgBlock struct {
	Index int
	// The current block of code
	Block asm.Instructions

	// The next block of we don't branch
	NoBranch *ProgBlock
	// The next block if we do branch
	Branch *ProgBlock
}

func (pb *ProgBlock) String() string {
	noBranch := -1
	if pb.NoBranch != nil {
		noBranch = pb.NoBranch.Index
	}

	branch := -1
	if pb.Branch != nil {
		branch = pb.Branch.Index
	}

	return fmt.Sprintf(
		"Block %d:\n%sNo-Branch: %d\nBranch: %d\n",
		pb.Index,
		pb.Block,
		noBranch,
		branch,
	)
}
