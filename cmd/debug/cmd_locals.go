package debug

import (
	"debug/dwarf"
	"fmt"

	"github.com/cilium/ebpf/btf"
	"github.com/dylandreimerink/mimic"
	"github.com/go-delve/delve/pkg/dwarf/op"
)

var cmdLocals = Command{
	Name:    "locals",
	Aliases: []string{"lv"},
	Summary: "Lists the local variables",
	Exec:    listLocalVarsExec,
}

func listLocalVarsExec(args []string) {
	if process == nil {
		printRed("No program loaded")
		return
	}

	det := progDwarf[process.Program.Name]

	programScopes := det.PCToScope[process.Program.Name]
	if process.Registers.PC >= len(programScopes) {
		fmt.Println("No locals in current scope")
		return
	}

	scope := programScopes[process.Registers.PC]

	fb := inferFrameBase(det, scope, process.Registers.R10)

	for _, child := range scope.Children {
		e := child.Entry
		name := det.Val(e, dwarf.AttrName)
		if name == nil {
			continue
		}

		switch e.Tag {
		case dwarf.TagVariable:
			fmt.Print(
				green("  (var) "),
				name,
				" ",
			)
		case dwarf.TagFormalParameter:
			fmt.Print(
				green("(param) "),
				name,
				" ",
			)
		default:
			continue
		}

		fmt.Print(blue(dwarfTypeName(child)), " = ")

		attrLoc := det.AttrField(e, dwarf.AttrLocation)
		if attrLoc == nil {
			fmt.Println(cyan("inlined"))
			continue
		}

		var instr []byte
		switch attrLoc.Class {
		case dwarf.ClassLocListPtr:
			lle, err := det.LocListReader.Find(int(attrLoc.Val.(int64)), 0, 0, uint64(process.Registers.PC*8), nil)
			if err != nil {
				fmt.Println(red(err.Error()))
				continue
			}
			if lle == nil {
				fmt.Println(gray("not available"))
				continue
			}

			instr = lle.Instr
		case dwarf.ClassExprLoc:
			instr = attrLoc.Val.([]byte)
		}

		// We don't have some registers, but still need to provide them
		const na = 12
		dwarfRegs := op.NewDwarfRegisters(0, dwarfRegisters(process.Registers), mimic.GetNativeEndianness(), 11, na, na, na)
		dwarfRegs.FrameBase = fb
		result, pieces, err := op.ExecuteStackProgram(*dwarfRegs, instr, 8, func(b []byte, u uint64) (int, error) {
			panic("not yet implemented")
		})
		if err != nil {
			fmt.Println(red(err.Error()))
			continue
		}

		typeSize := DWARFGetByteSize(det, child)
		data := make([]byte, typeSize)

		if len(pieces) > 0 && result == 0 {
			i := 0
			for _, p := range pieces {
				switch p.Kind {
				case op.ImmPiece:
					if p.Bytes != nil {
						copy(data[i:], p.Bytes)
						i += p.Size
						continue
					}

					// TODO Or should we use the ELF file endianness?
					ne := mimic.GetNativeEndianness()
					switch p.Size {
					case 1:
						data[i] = byte(p.Val)
					case 2:
						ne.PutUint16(data[i:], uint16(p.Val))
					case 4:
						ne.PutUint32(data[i:], uint32(p.Val))
					case 8:
						ne.PutUint64(data[i:], uint64(p.Val))
					}

					i += p.Size
				default:
					fmt.Println(red("unhandled op piece"))
				}
			}
		} else {
			memEntry, off, found := vm.MemoryController.GetEntry(uint32(result))
			if found {
				mem, ok := memEntry.Object.(mimic.VMMem)
				if ok {
					err = mem.Read(off, data)
					if err != nil {
						fmt.Println(red(err.Error()))
						continue
					}
				} else {
					mimic.GetNativeEndianness().PutUint64(data, uint64(result))
				}
			} else {
				mimic.GetNativeEndianness().PutUint64(data, uint64(result))
			}
		}

		fmt.Println(yellow(DWARFBytesToCValue(det, child, data, 0, true)))
	}
}

func dwarfRegisters(r mimic.Registers) []*op.DwarfRegister {
	var dregs []*op.DwarfRegister
	regs := []uint64{
		r.R0,
		r.R1,
		r.R2,
		r.R3,
		r.R4,
		r.R5,
		r.R6,
		r.R7,
		r.R8,
		r.R9,
		r.R10,
		uint64(r.PC),
	}
	ne := mimic.GetNativeEndianness()
	for _, rr := range regs {
		reg := &op.DwarfRegister{
			Uint64Val: rr,
			Bytes:     make([]byte, 8),
		}

		ne.PutUint64(reg.Bytes, rr)

		dregs = append(dregs, reg)
	}

	return dregs
}

func dwarfTypeName(node *EntryNode) string {
	det := progDwarf[process.Program.Name]

	e := node.Entry
	if attrType := det.AttrField(e, dwarf.AttrType); attrType != nil {
		entryType := det.EntitiesByOffset[attrType.Val.(dwarf.Offset)]

		attrName := entryType.Entry.AttrField(dwarf.AttrName)
		if attrName != nil {
			return attrName.Val.(string)
		}

		switch entryType.Entry.Tag {
		case dwarf.TagPointerType:
			return "*" + dwarfTypeName(entryType)
		case dwarf.TagArrayType:
			return "[]" + dwarfTypeName(entryType)
		case dwarf.TagConstType:
			return dwarfTypeName(entryType)
		default:
			panic(fmt.Sprintf("can't find name for %s", entryType.Entry.Tag))
		}
	}

	return ""
}

func DwarfToBTF(node *EntryNode) (btf.Type, error) {
	det := progDwarf[process.Program.Name]

	e := node.Entry
	if attrType := det.AttrField(e, dwarf.AttrType); attrType != nil {
		typeEntry := det.EntitiesByOffset[attrType.Val.(dwarf.Offset)]

		name := det.Val(typeEntry.Entry, dwarf.AttrName)
		if name == nil {
			return nil, nil
		}

		if typeEntry.Entry.Tag == dwarf.TagPointerType {
			return DwarfToBTF(typeEntry)
		}

		var err error
		ty, err := process.Program.BTF.AnyTypeByName(name.(string))
		if err != nil {
			return nil, err
		}

		return ty, nil
	}

	return nil, nil
}
