package analyse

import (
	"fmt"
	"strconv"
	"strings"

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

func FlowPermutations(entryBlock *ProgBlock) []FlowPermutation {
	// A list of permutations which are still evolving
	activePermutations := []FlowPermutation{{Blocks: []*ProgBlock{entryBlock}}}
	// List of permutations which are "complete"
	donePermutations := make([]FlowPermutation, 0)

	const maxIter = 1000000
	i := 0

	// Keep iterating until there are no more permutations
	for {
		if i >= maxIter {
			// A safeguard against infinite loops
			break
		}
		i++

		updated := false

		for permIndex, perm := range activePermutations {
			lastBlock := perm.Last()

			if lastBlock.NoBranch == nil {
				// We hit a Exit/Return

				// If the return stack is empty, we hit program exit.
				if len(perm.Return) == 0 {
					// This permutation is "done"
					activePermutations = slices.Delete(activePermutations, permIndex, permIndex+1)
					donePermutations = append(donePermutations, perm)

					// Break, we modified activePermutations, doing so a second time will cause issues, so just re-run
					//  the outer loop
					updated = true
					break
				}

				// Return stack not empty, next block is return from func.
				returnBlock := perm.Return[len(perm.Return)-1]
				perm.Return = perm.Return[:len(perm.Return)-1]
				perm.Blocks = append(perm.Blocks, returnBlock)
				activePermutations[permIndex] = perm
				updated = true
				continue
			}

			// If this block can branch, create a new permutation of the brach
			if lastBlock.Branch != nil {

				lastInst := lastBlock.Block[len(lastBlock.Block)-1]
				if lastInst.OpCode.JumpOp() == asm.Call {
					// If the branch in because of a bpf-to-bpf call, add the NoBrach block to the return stack.
					perm.Return = append(perm.Return, lastBlock.NoBranch)
					perm.Blocks = append(perm.Blocks, lastBlock.Branch)
					activePermutations[permIndex] = perm
					updated = true
					continue
				}

				// The brach is due to a jump

				// We only make a permutation for the first loop iteration
				if SliceCount(perm.Blocks, lastBlock.Branch) < 2 {
					// Make a new permutation with the branch block
					newPerm := perm.Copy()
					newPerm.Blocks = append(newPerm.Blocks, lastBlock.Branch)
					activePermutations = append(activePermutations, newPerm)
					updated = true
				}
			}

			// If we are here, lastBlock.NoBranch != nil, so append a new block to the current permutation
			perm.Blocks = append(perm.Blocks, lastBlock.NoBranch)
			activePermutations[permIndex] = perm
			updated = true
		}

		if !updated {
			break
		}
	}

	return donePermutations
}

func SliceCount[E comparable](s []E, v E) int {
	var count int
	for _, e := range s {
		if e == v {
			count++
		}
	}
	return count
}

type FlowPermutation struct {
	Blocks []*ProgBlock
	Return []*ProgBlock
}

func (fp FlowPermutation) Copy() FlowPermutation {
	return FlowPermutation{
		Blocks: slices.Clone(fp.Blocks),
		Return: slices.Clone(fp.Return),
	}
}

func (fp FlowPermutation) Last() *ProgBlock {
	return fp.Blocks[len(fp.Blocks)-1]
}

func (fp FlowPermutation) String() string {
	var sb strings.Builder
	for i, block := range fp.Blocks {
		if i != 0 {
			sb.WriteString(" -> ")
		}
		sb.WriteString(strconv.Itoa(block.Index))
	}
	return sb.String()
}
