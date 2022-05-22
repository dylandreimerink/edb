package debug

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"github.com/cilium/ebpf/btf"
)

// Convert a BTF type to its C type definition
func BtfToCDef(t btf.Type, depth int) string {
	var sb strings.Builder
	btfToCDef(&sb, t, depth)
	return sb.String()
}

func btfToCDef(sb *strings.Builder, t btf.Type, depth int) {
	fmt.Fprint(sb, strings.Repeat(" ", depth))
	switch t := t.(type) {
	case *btf.Array:
		btfToCDef(sb, t.Type, 0)
		fmt.Fprintf(sb, "[%d]", t.Nelems)

	case *btf.Const:
		fmt.Fprint(sb, "const ")
		btfToCDef(sb, t.Type, 0)

	case *btf.Datasec:
		// Datasec isn't a C data type but a descriptor for a ELF section.

	case *btf.Enum:
		fmt.Fprint(sb, "enum ", t.Name, "{\n")
		for _, v := range t.Values {
			fmt.Fprint(sb, strings.Repeat(" ", depth+2))
			fmt.Fprint(sb, v.Name, " = ", v.Value, ",\n")
		}
		fmt.Fprint(sb, strings.Repeat(" ", depth), "}")

	case *btf.Float:
		fmt.Fprint(sb, t.Name)

	case *btf.Func:
		proto, ok := t.Type.(*btf.FuncProto)
		if !ok {
			break
		}

		btfToCDef(sb, proto.Return, 0)
		fmt.Fprint(sb, " ", t.Name, "(")
		for i, p := range proto.Params {
			btfToCDef(sb, p.Type, 0)
			fmt.Fprint(sb, " ", p.Name)

			if i != len(proto.Params)-1 {
				fmt.Fprintf(sb, ", ")
			}
		}
		fmt.Fprint(sb, ")")

	case *btf.FuncProto:
		// Can't print a func prototype on its own. print the btf.Func parent instread

	case *btf.Fwd:
		// TODO not 100% sure about this one
		fmt.Fprint(sb, t.Name)

	case *btf.Int:
		fmt.Fprint(sb, t.Name)

	case *btf.Pointer:
		fmt.Fprint(sb, "*")
		btfToCDef(sb, t.Target, 0)

	case *btf.Restrict:
		fmt.Fprint(sb, "restrict ")
		btfToCDef(sb, t.Type, 0)

	case *btf.Struct:
		fmt.Fprint(sb, "struct ", t.Name, "{\n")
		for _, m := range t.Members {
			btfToCDef(sb, m.Type, depth+2)
			if m.Name != "" {
				fmt.Fprint(sb, " ", m.Name)
			}
			fmt.Fprint(sb, ",\n")
			// TODO print bitfield
		}
		fmt.Fprint(sb, strings.Repeat(" ", depth), "}")

	case *btf.Typedef:
		// TODO typedef as root should be rendered seperately then included typerefs
		fmt.Fprint(sb, t.Name)

	case *btf.Union:
		fmt.Fprint(sb, "union ", t.Name, "{\n")
		for _, m := range t.Members {
			btfToCDef(sb, m.Type, depth+2)
			if m.Name != "" {
				fmt.Fprint(sb, " ", m.Name)
			}
			fmt.Fprint(sb, ",\n")
			// TODO print bitfield
		}
		fmt.Fprint(sb, strings.Repeat(" ", depth), "}")

	case *btf.Var:
		fmt.Fprintf(sb, "var %s ", t.Name)
		btfToCDef(sb, t.Type, 0)

	case *btf.Void:
		fmt.Fprint(sb, "void")

	case *btf.Volatile:
		fmt.Fprint(sb, "volatile ")
		btfToCDef(sb, t.Type, 0)

	}
}

//
func BtfBytesToCValue(t btf.Type, val []byte, depth int, formatted bool) string {
	var sb strings.Builder
	btfBytesToCValue(&sb, t, val, depth, formatted)
	return sb.String()
}

func btfBytesToCValue(sb *strings.Builder, t btf.Type, val []byte, depth int, formatted bool) []byte {
	fmt.Fprint(sb, strings.Repeat(" ", depth))
	switch t := t.(type) {
	case *btf.Array:
		fmt.Fprint(sb, "{")
		for i := 0; i < int(t.Nelems); i++ {
			val = btfBytesToCValue(sb, t.Type, val, depth, formatted)
			if i+1 < int(t.Nelems) {
				fmt.Fprint(sb, ", ")
			}
		}
		fmt.Fprint(sb, "}")

	case *btf.Const:
		return btfBytesToCValue(sb, t.Type, val, 0, formatted)

	case *btf.Datasec:
		// Datasec isn't a C data type but a descriptor for a ELF section.
		return val

	case *btf.Enum:
		// TODO are enums always 32 bit?
		enumVal := int32(binary.LittleEndian.Uint32(val[:4]))
		for _, v := range t.Values {
			if v.Value == enumVal {
				fmt.Fprint(sb, v.Name)
				break
			}
		}
		return val[4:]

	case *btf.Float:
		switch t.Size {
		case 4:
			bits := binary.LittleEndian.Uint32(val[:4])
			fmt.Fprint(sb, math.Float32frombits(bits))
			return val[4:]
		case 8:
			bits := binary.LittleEndian.Uint64(val[:8])
			fmt.Fprint(sb, math.Float64frombits(bits))
			return val[8:]
		}

	case *btf.Func:
		// Can't print a function as value
		return val

	case *btf.FuncProto:
		// Can't print a func prototype on its own. print the btf.Func parent instread
		return val

	case *btf.Fwd:
		// Can't print a forward decleration as value
		return val

	case *btf.Int:
		if t.Encoding&btf.Bool > 0 {
			var boolVal bool
			for _, b := range val[:t.Size] {
				if b > 0 {
					boolVal = true
				}
			}

			fmt.Fprint(sb, boolVal)

		} else if t.Encoding&btf.Char > 0 {
			fmt.Fprint(sb, rune(val[0]))

		} else {
			var i uint64
			switch t.Size {
			case 1:
				i = uint64(val[0])
			case 2:
				i = uint64(binary.LittleEndian.Uint16(val[:2]))
			case 4:
				i = uint64(binary.LittleEndian.Uint32(val[:4]))
			case 8:
				i = uint64(binary.LittleEndian.Uint64(val[:8]))
			}

			if t.Encoding&btf.Signed == 0 {
				fmt.Fprint(sb, i)
			} else {
				fmt.Fprint(sb, int64(i))
			}
		}

		return val[t.Size:]

	case *btf.Pointer:
		return btfBytesToCValue(sb, t.Target, val, 0, formatted)

	case *btf.Restrict:
		return btfBytesToCValue(sb, t.Type, val, 0, formatted)

	case *btf.Struct:
		fmt.Fprint(sb, "struct ", t.Name, "{")
		if formatted {
			fmt.Fprint(sb, "\n")
		}

		var newVal []byte
		for i, m := range t.Members {
			if m.Name != "" {
				fmt.Fprint(sb, ".", m.Name, " = ")
			}

			off := m.Offset.Bytes()

			if formatted {
				newVal = btfBytesToCValue(sb, m.Type, val[off:], depth+2, formatted)
				fmt.Fprint(sb, ",\n")
			} else {
				newVal = btfBytesToCValue(sb, m.Type, val[off:], 0, formatted)

				if i+1 < len(t.Members) {
					fmt.Fprint(sb, ", ")
				}
			}
		}

		if formatted {
			fmt.Fprint(sb, strings.Repeat(" ", depth))
		}
		fmt.Fprint(sb, "}")

		return newVal

	case *btf.Typedef:
		return btfBytesToCValue(sb, t.Type, val, 0, formatted)

	case *btf.Union:
		fmt.Fprint(sb, "union ", t.Name, "{")
		if formatted {
			fmt.Fprint(sb, "\n")
		}

		var newVal []byte
		for i, m := range t.Members {
			if m.Name != "" {
				fmt.Fprint(sb, ".", m.Name, " = ")
			}

			off := m.Offset.Bytes()

			if formatted {
				btfBytesToCValue(sb, m.Type, val[off:], depth+2, formatted)
				fmt.Fprint(sb, ",\n")
			} else {
				btfBytesToCValue(sb, m.Type, val[off:], 0, formatted)

				if i+1 < len(t.Members) {
					fmt.Fprint(sb, ", ")
				}
			}
		}

		if formatted {
			fmt.Fprint(sb, strings.Repeat(" ", depth))
		}
		fmt.Fprint(sb, "}")

		return newVal

	case *btf.Var:
		fmt.Fprint(sb, t.Name, " = ")
		return btfBytesToCValue(sb, t.Type, val, 0, formatted)

	case *btf.Void:
		fmt.Fprint(sb, "void")
		return val

	case *btf.Volatile:
		return btfBytesToCValue(sb, t.Type, val, 0, formatted)
	}

	return val
}
