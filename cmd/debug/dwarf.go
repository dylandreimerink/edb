package debug

import (
	"bytes"
	"debug/dwarf"
	"fmt"
	"strings"

	"github.com/dylandreimerink/edb/elf"
	"github.com/dylandreimerink/edb/pkg/dwarf/rangelist"
	"github.com/dylandreimerink/mimic"
	"github.com/go-delve/delve/pkg/dwarf/loclist"
	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/dwarf/util"
)

// DET DWARF Entry table, holds the parsed DWARF entries, used for quick lookups
type DET struct {
	Tree EntryNode

	// SubPrograms by name
	SubPrograms map[string]*EntryNode
	//
	EntitiesByOffset map[dwarf.Offset]*EntryNode

	LocListReader *loclist.Dwarf2Reader

	// Map indexed by program name, slice indexed by PC
	PCToScope map[string][]*EntryNode

	Files []*dwarf.LineFile
}

type EntryNode struct {
	Parent   *EntryNode
	Entry    *dwarf.Entry
	Children []*EntryNode
}

func (e *EntryNode) load(r *dwarf.Reader, det *DET) error {
	for {
		entry, err := r.Next()
		if err != nil {
			return err
		}

		if entry == nil {
			return nil
		}

		if entry.Tag == 0 {
			return nil
		}

		child := &EntryNode{
			Parent: e,
			Entry:  entry,
		}
		e.Children = append(e.Children, child)

		det.EntitiesByOffset[entry.Offset] = child

		if entry.Tag == dwarf.TagSubprogram {
			name := entry.AttrField(dwarf.AttrName)
			if name != nil {
				det.SubPrograms[name.Val.(string)] = child
			}
		}

		if entry.Children {
			err = child.load(r, det)
			if err != nil {
				return err
			}
		}
	}
}

func (e *EntryNode) Print(indent int) {
	fmt.Print(strings.Repeat("-", indent))
	fmt.Print(e.Entry.Tag, "-", e.Entry.Children, "\n")
	for _, child := range e.Children {
		child.Print(indent + 1)
	}
}

func (e *EntryNode) WalkBreadthFirst(visitor func(e *EntryNode) error) error {
	err := visitor(e)
	if err != nil {
		return err
	}

	for _, child := range e.Children {
		err := child.WalkBreadthFirst(visitor)
		if err != nil {
			return err
		}
	}

	return nil
}

func newDET(elf *elf.File, progSection string) (*DET, error) {
	det := DET{
		SubPrograms:      make(map[string]*EntryNode),
		EntitiesByOffset: make(map[dwarf.Offset]*EntryNode),
		PCToScope:        make(map[string][]*EntryNode),
	}

	dd, err := elf.DWARF()
	if err != nil {
		return nil, fmt.Errorf("dwarf: %w", err)
	}

	r := dd.Reader()

	// Create the root node of the DWARF entry tree, this first node is always the DW_TAG_compilation unit
	det.Tree.Entry, err = r.Next()
	if err != nil {
		return nil, fmt.Errorf("next: %w", err)
	}

	lr, err := dd.LineReader(det.Tree.Entry)
	if err != nil {
		return nil, fmt.Errorf("lr: %w", err)
	}

	det.Files = lr.Files()

	err = det.Tree.load(r, &det)
	if err != nil {
		return nil, fmt.Errorf("load tree: %w", err)
	}

	err = det.buildPCToEntryNodeMap(elf)
	if err != nil {
		return nil, err
	}

	if elf.Section(".debug_loc") == nil {
		return nil, fmt.Errorf("ELF contains no .debug_loc section")
	}

	locData, err := elf.Section(".debug_loc").Data()
	if err != nil {
		return nil, fmt.Errorf("loc data: %w", err)
	}

	// An address size of 8 was experimentally found to be correct
	// TODO find a way to automatically chose between 4 and 8 in case this differs ELF to ELF or system to system.
	det.LocListReader = loclist.NewDwarf2Reader(locData, 8)

	return &det, nil
}

func (det *DET) buildPCToEntryNodeMap(elf *elf.File) error {
	if elf.Section(".debug_ranges") == nil {
		return fmt.Errorf("ELF contains no .debug_ranges section")
	}

	rangeData, err := elf.Section(".debug_ranges").Data()
	if err != nil {
		return fmt.Errorf("loc data: %w", err)
	}
	rangeReader := rangelist.NewRangeListReader(rangeData)

	// Walk over the whole DWARF tree, this ensures we always see a SubProgram before its inlined subroutines so we
	// can allocate memory for all PC values within the SubProgram.
	err = det.Tree.WalkBreadthFirst(func(en *EntryNode) error {
		e := en.Entry
		if e.Tag != dwarf.TagSubprogram {
			return nil
		}

		if e.Val(dwarf.AttrName) == nil {
			return nil
		}
		name := e.Val(dwarf.AttrName).(string)

		low := e.Val(dwarf.AttrLowpc)
		if low == nil {
			return nil
		}
		if low.(uint64) != 0 {
			return fmt.Errorf("sub-program '%s' doesn't start at PC 0", name)
		}

		high := e.Val(dwarf.AttrHighpc)
		if high == nil {
			return fmt.Errorf("sub-program '%s' doesn't have a high PC", name)
		}

		det.PCToScope[name] = make([]*EntryNode, (high.(int64) / 8))
		for i := range det.PCToScope[name] {
			det.PCToScope[name][i] = en
		}

		// Do a tree traversal of the sub tree, this is double work, but it ensures we always know which program
		// we are in within this sub-tree. Which is needed since PCToScope is indexed by program name.
		return en.WalkBreadthFirst(func(en *EntryNode) error {
			e := en.Entry
			if e.Tag != dwarf.TagInlinedSubroutine {
				return nil
			}

			// See DWARF 4, Section 2.17
			if e.Val(dwarf.AttrLowpc) != nil {
				low := e.Val(dwarf.AttrLowpc).(uint64) / 8
				if e.Val(dwarf.AttrHighpc) != nil {
					// Low - High
					high := e.Val(dwarf.AttrHighpc).(int64) / 8
					for i := low; i < low+uint64(high); i++ {
						det.PCToScope[name][i] = en
					}
				} else {
					// Single address
					det.PCToScope[name][low] = en
				}
			} else if e.Val(dwarf.AttrRanges) != nil {
				// Multiple ranges
				ranges, err := rangeReader.RangesAt(int(e.Val(dwarf.AttrRanges).(int64)))
				if err != nil {
					return err
				}

				for _, r := range ranges {
					for i := r.LowerPC / 8; i < r.UpperPC/8; i++ {
						det.PCToScope[name][i] = en
					}
				}
			} else {
				// No location info known
				return nil
			}

			return nil
		})
	})
	if err != nil {
		return err
	}

	return nil
}

// Val attempts to find a attribute value in `e`, if `e` doesn't have it, but does have an abstract origin, attempt
// to get it from the abstract origin.
func (det *DET) Val(e *dwarf.Entry, attr dwarf.Attr) any {
	val := e.Val(attr)
	if val != nil {
		return val
	}

	ao := e.Val(dwarf.AttrAbstractOrigin)
	if ao == nil {
		return nil
	}

	origin := det.EntitiesByOffset[ao.(dwarf.Offset)]
	if origin == nil {
		return nil
	}

	return origin.Entry.Val(attr)
}

// AttrField attempts to find a attribute field in `e`, if `e` doesn't have it, but does have an abstract origin, attempt
// to get it from the abstract origin.
func (det *DET) AttrField(e *dwarf.Entry, attr dwarf.Attr) *dwarf.Field {
	val := e.AttrField(attr)
	if val != nil {
		return val
	}

	ao := e.Val(dwarf.AttrAbstractOrigin)
	if ao == nil {
		return nil
	}

	origin := det.EntitiesByOffset[ao.(dwarf.Offset)]
	if origin == nil {
		return nil
	}

	return origin.Entry.AttrField(attr)
}

func DWARFGetByteSize(det *DET, en *EntryNode) int64 {
	e := en.Entry

	byteSize := det.Val(e, dwarf.AttrByteSize)
	typeOff := det.Val(e, dwarf.AttrType)

	switch e.Tag {
	case dwarf.TagArrayType:
		if typeOff == nil {
			return 0
		}
		typeEntryNode := det.EntitiesByOffset[typeOff.(dwarf.Offset)]

		byteSize = det.Val(typeEntryNode.Entry, dwarf.AttrByteSize)
		if byteSize == nil {
			return 0
		}

		size := byteSize.(int64)
		for _, c := range en.Children {
			if c.Entry.Tag != dwarf.TagSubrangeType {
				continue
			}

			count := c.Entry.Val(dwarf.AttrCount)
			if count != nil {
				size = size * count.(int64)
			}
		}

		return size
	}

	if byteSize != nil {
		return byteSize.(int64)
	}

	if typeOff == nil {
		return 0
	}

	typeEntryNode := det.EntitiesByOffset[typeOff.(dwarf.Offset)]
	return DWARFGetByteSize(det, typeEntryNode)
}

//
func DWARFBytesToCValue(det *DET, en *EntryNode, val []byte, depth int, formatted bool) string {
	var sb strings.Builder
	dwarfBytesToCValue(&sb, det, en, val, depth, formatted)
	return sb.String()
}

func dwarfBytesToCValue(sb *strings.Builder, det *DET, en *EntryNode, val []byte, depth int, formatted bool) []byte {
	if formatted {
		fmt.Fprint(sb, strings.Repeat(" ", depth))
	}

	e := en.Entry

	attrType := det.AttrField(e, dwarf.AttrType)
	if attrType == nil {
		sb.WriteString("%{Missing type info}")
		return val
	}

	typeEntryNode := det.EntitiesByOffset[attrType.Val.(dwarf.Offset)]

	switch typeEntryNode.Entry.Tag {
	case dwarf.TagArrayType:
		sb.WriteString("{")
		if formatted {
			sb.WriteString("\n")
		}

		// An array Tag contains one or more sub-ranges, each representing one dimention of an array.
		// See DWARF 4, section 5.11
		for _, c := range typeEntryNode.Children {
			if c.Entry.Tag == dwarf.TagSubrangeType {
				size := c.Entry.Val(dwarf.AttrCount).(int64)
				for i := int64(0); i < size; i++ {

					val = dwarfBytesToCValue(sb, det, typeEntryNode, val, depth+2, formatted)
					sb.WriteString(",")
					if formatted {
						sb.WriteString("\n")
					}
				}
			}

			// TODO add support for multi dimensional arrays
			break
		}

		if formatted {
			fmt.Fprint(sb, strings.Repeat(" ", depth))
		}
		sb.WriteString("}")

	case dwarf.TagStructType:
		name := typeEntryNode.Entry.Val(dwarf.AttrName)
		if name != nil {
			name = ""
			fmt.Fprintf(sb, "struct %s{", name.(string))
		}
		if formatted {
			sb.WriteString("\n")
		}

		for _, c := range typeEntryNode.Children {
			if c.Entry.Tag != dwarf.TagMember {
				continue
			}

			// A union within a struct doesn't have a name, in which case we can just leave it out
			memberNameAttr := c.Entry.Val(dwarf.AttrName)
			if memberNameAttr != nil {
				memberName := memberNameAttr.(string)
				if formatted {
					fmt.Fprint(sb, strings.Repeat(" ", depth+2))
				}
				fmt.Fprintf(sb, ".%s = ", memberName)

			}

			// TODO handle bitoffset

			dataMemberLocation := c.Entry.Val(dwarf.AttrDataMemberLoc).(int64)

			subTypeTag := det.EntitiesByOffset[c.Entry.Val(dwarf.AttrType).(dwarf.Offset)].Entry.Tag
			switch subTypeTag {
			case dwarf.TagArrayType, dwarf.TagUnionType:
				dwarfBytesToCValue(sb, det, c, val[dataMemberLocation:], depth+2, formatted)
			default:
				dwarfBytesToCValue(sb, det, c, val[dataMemberLocation:], 0, formatted)
			}

			sb.WriteString(",")
			if formatted {
				sb.WriteString("\n")
			}
		}

		structSize := typeEntryNode.Entry.Val(dwarf.AttrByteSize).(int64)
		val = val[structSize:]

		sb.WriteString("}")

	case dwarf.TagUnionType:
		sb.WriteString("union{")
		if formatted {
			sb.WriteString("\n")
		}

		for _, c := range typeEntryNode.Children {
			if c.Entry.Tag != dwarf.TagMember {
				continue
			}

			// A union within a struct doesn't have a name, in which case we can just leave it out
			memberNameAttr := c.Entry.Val(dwarf.AttrName)
			if memberNameAttr != nil {
				memberName := memberNameAttr.(string)
				if formatted {
					fmt.Fprint(sb, strings.Repeat(" ", depth+2))
				}
				fmt.Fprintf(sb, ".%s = ", memberName)
			}

			// Note: this is a union, don't set val, reuse the same val
			dwarfBytesToCValue(sb, det, c, val, 0, formatted)

			sb.WriteString(",")
			if formatted {
				sb.WriteString("\n")
			}
		}

		unionSize := typeEntryNode.Entry.Val(dwarf.AttrByteSize).(int64)
		val = val[unionSize:]

		if formatted {
			fmt.Fprint(sb, strings.Repeat(" ", depth))
		}
		sb.WriteString("}")

	case dwarf.TagPointerType:
		// TODO depth 0 ptr vs nested pointer handling.
		return dwarfBytesToCValue(sb, det, typeEntryNode, val, depth, formatted)

	case dwarf.TagTypedef:
		return dwarfBytesToCValue(sb, det, typeEntryNode, val, depth, formatted)

	// case dwarf.TagStringType:
	case dwarf.TagBaseType:
		byteSizeAttr := typeEntryNode.Entry.Val(dwarf.AttrByteSize)
		if byteSizeAttr == nil {
			sb.WriteString("%{Base type unknown byte size}")
			return val
		}
		byteSize := byteSizeAttr.(int64)
		data := val[:byteSize]
		val = val[byteSize:]

		// See DWARF 4, section 7.8
		enc := typeEntryNode.Entry.Val(dwarf.AttrEncoding).(int64)
		switch enc {
		case 0x05:
			// DW_ATE_signed
			ne := mimic.GetNativeEndianness()
			switch byteSize {
			case 1:
				fmt.Fprintf(sb, "%d", int(data[0]))
			case 2:
				fmt.Fprintf(sb, "%d", int16(ne.Uint16(data)))
			case 4:
				fmt.Fprintf(sb, "%d", int32(ne.Uint32(data)))
			case 8:
				fmt.Fprintf(sb, "%d", int32(ne.Uint64(data)))
			default:
				fmt.Fprintf(sb, "%%{unhandled byte size %d}", byteSize)
			}

		case 0x06:
			// DW_ATE_signed_char
			if byteSize != 1 {
				sb.WriteString("%{Signed char /w size>1}")
				return val
			}

			fmt.Fprintf(sb, "'%s'", string(rune(data[0])))

		case 0x07:
			// DW_ATE_unsigned
			ne := mimic.GetNativeEndianness()
			switch byteSize {
			case 1:
				fmt.Fprintf(sb, "%d", data[0])
			case 2:
				fmt.Fprintf(sb, "%d", ne.Uint16(data))
			case 4:
				fmt.Fprintf(sb, "%d", ne.Uint32(data))
			case 8:
				fmt.Fprintf(sb, "%d", ne.Uint64(data))
			default:
				fmt.Fprintf(sb, "%%{unhandled byte size %d}", byteSize)
			}

		case 0x08:
			// DW_ATE_unsigned_char
			if byteSize != 1 {
				sb.WriteString("%{unsigned char /w size>1}")
				return val
			}

			fmt.Fprintf(sb, "%d", data[0])
		default:
			fmt.Fprintf(sb, "%%{unknown base type encoding 0x%0x}", enc)
			return val
		}

	default:
		fmt.Printf("Unknown tag: %s\n", typeEntryNode.Entry.Tag)
	}

	return val
}

// currently(28-05-2022) Clang/LLVM generates invalid DWARF for eBPF code. The fb(framebase) is always given as just R10
// and then variable locations are often given as positive offsets from fb, which is invalid for eBPF since we always
// work with negative offsets from R10 to access the stack.
// This function attempts to infer the correct fb by seeing that the highest offset from it is, taking that value plus
// the size of the referenced variable and subtracting that value from the current R10. This should yield a "corrected"
// value that works.
func inferFrameBase(det *DET, scope *EntryNode, r10 uint64) int64 {
	// Walk up the tree until we find the subprogram we are currently in
	node := scope
	for node.Entry.Tag != dwarf.TagSubprogram {
		node = node.Parent
	}

	// No subprogram found in tree
	if node.Entry.Tag != dwarf.TagSubprogram {
		panic("no parent subprogram")
	}

	type nodeLoc struct {
		entry *EntryNode
		loc   []byte
	}
	// Walk the whole subtree and find all nodeLocations within
	var nodeLocations []nodeLoc
	_ = node.WalkBreadthFirst(func(en *EntryNode) error {
		e := en.Entry
		name := det.Val(e, dwarf.AttrName)
		if name == nil {
			return nil
		}

		switch e.Tag {
		case dwarf.TagVariable, dwarf.TagFormalParameter:
		default:
			return nil
		}

		attrLoc := det.AttrField(e, dwarf.AttrLocation)
		if attrLoc == nil {
			return nil
		}

		switch attrLoc.Class {
		case dwarf.ClassLocListPtr:
			det.LocListReader.Seek(int(attrLoc.Val.(int64)))
			var e loclist.Entry
			for det.LocListReader.Next(&e) {
				if e.Instr != nil {
					nodeLocations = append(nodeLocations, nodeLoc{
						entry: en,
						loc:   e.Instr,
					})
				}
			}
		case dwarf.ClassExprLoc:
			nodeLocations = append(nodeLocations, nodeLoc{
				entry: en,
				loc:   attrLoc.Val.([]byte),
			})
		}

		return nil
	})

	var (
		highFB      = int64(-1)
		highNodeLoc nodeLoc
	)
	for _, nodeLoc := range nodeLocations {
		in := bytes.NewBuffer(nodeLoc.loc)

		opcode, err := in.ReadByte()
		if err != nil {
			break
		}
		if op.Opcode(opcode) != op.DW_OP_fbreg {
			continue
		}

		n, _ := util.DecodeSLEB128(in)
		if n > highFB {
			highFB = n
			highNodeLoc = nodeLoc
		}
	}
	if highNodeLoc.entry == nil {
		// no locations that use framebases found
		return int64(r10)
	}

	size := DWARFGetByteSize(det, highNodeLoc.entry)
	// Round up to the nearest multiple of 8 (a 12 byte address will still take up 16 bytes on the stack since the stack
	// is 8 byte aligned)
	size += size % 8

	// The inferred framebase is the stack pointer, minus the highes FB offset minus the (rounded) size of that object
	return int64(r10) - highFB - size
}
