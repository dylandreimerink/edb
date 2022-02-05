package debug

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/emulator"
)

var cmdMap = Command{
	Name:        "map",
	Aliases:     []string{"maps"},
	Summary:     "Map related operations",
	Description: "",
	Subcommands: []Command{
		{
			Name:    "list",
			Aliases: []string{"ls"},
			Summary: "Lists all loaded maps",
			Exec:    listMapsExec,
		},
		{
			Name:    "read-all",
			Summary: "Reads and displays all keys and values",
			Exec:    mapReadAllExec,
			Args: []CmdArg{{
				Name:     "map name|map index",
				Required: true,
			}},
		},
		{
			Name:    "get",
			Summary: "Get the value of a particular key in a map",
			Exec:    mapGetExec,
			Args: []CmdArg{
				{
					Name:     "map name|map index",
					Required: true,
				},
				{
					Name:     "key",
					Required: true,
				},
			},
		},
		{
			Name:    "set",
			Summary: "Set a value at a particular spot in a map",
			Exec:    mapSetExec,
			Args: []CmdArg{
				{
					Name:     "map name|map index",
					Required: true,
				},
				{
					Name:     "key",
					Required: true,
				},
				{
					Name:     "value",
					Required: true,
				},
			},
		},
		{
			Name:    "del",
			Summary: "Delete a value from a map with the given key",
			Exec:    mapDelExec,
			Args: []CmdArg{
				{
					Name:     "map name|map index",
					Required: true,
				},
				{
					Name:     "key",
					Required: true,
				},
			},
		},
		{
			Name:    "push",
			Aliases: []string{"enqueue"},
			Summary: "Push/enqueue a value into the map",
			Exec:    mapPushExec,
			Args: []CmdArg{
				{
					Name:     "map name|map index",
					Required: true,
				},
				{
					Name:     "value",
					Required: true,
				},
			},
		},
		{
			Name:    "pop",
			Aliases: []string{"dequeue"},
			Summary: "Pop/dequeue a value from the map, this shows and deletes the value",
			Exec:    mapPopExec,
			Args: []CmdArg{
				{
					Name:     "map name|map index",
					Required: true,
				},
			},
		},
	},
}

func listMapsExec(args []string) {
	indexPadSize := len(strconv.Itoa(len(vm.Maps)))
	for i, m := range vm.Maps {
		// Skip zero since it is an invalid program index
		if i == 0 {
			continue
		}

		fmt.Print(blue(fmt.Sprintf("%*d ", indexPadSize, i)))
		fmt.Printf("%s:\n", mapName[i])
		// TODO print Key and Value types from BTF
		def := m.GetDef()
		fmt.Printf("        Type: %s\n", def.Type)
		fmt.Printf("    Key size: %d bytes\n", def.KeySize)
		fmt.Printf("  Value size: %d bytes\n", def.ValueSize)
		fmt.Printf(" Max entries: %d\n", def.MaxEntries)
		fmt.Printf("       Flags: %s\n\n", def.Flags)
	}
}

func mapGetExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'map name|map index'\n")
		return
	}

	if len(args) < 2 {
		printRed("Missing required argument 'key'\n")
		return
	}

	nameOrID := args[0]
	m, err := nameOrIDToMap(nameOrID)
	if err != nil {
		printRed("%s\n", err)
		return
	}

	mt := m.GetType()
	ks := int(m.GetDef().KeySize)
	vs := int(m.GetDef().ValueSize)

	kv, err := valueFromString(args[1], ks)
	if err != nil {
		printRed("Error parsing key: %s\n", err)
		return
	}

	value, err := m.Lookup(kv)
	if err != nil {
		printRed("Error lookup map: %s\n", err)
		return
	}

	vPtr, ok := value.(emulator.PointerValue)
	if !ok {
		if _, ok := value.(*emulator.IMMValue); ok && value.Value() == 0 {
			printRed("Map doesn't contain a value for the given key\n")
			return
		}

		printRed("Error map value of type '%T' is not a emulator.PointerValue\n", value)
		return
	}
	vVal, err := vPtr.ReadRange(0, vs)
	if err != nil {
		printRed("Error read range key: %s\n", err)
		return
	}

	vStr := fmt.Sprintf("%0*X", vs, vVal)

	if bfmt, ok := mt.Value.(gobpfld.BTFValueFormater); ok {
		var vw strings.Builder
		_, err = bfmt.FormatValue(vVal, &vw, true)
		if err != nil {
			// TODO just fall back to showing bytes if we have formatting errors.
			printRed("Error while formatting value: %s\n", err)
			return
		}
		vStr = vw.String()
	}

	fmt.Printf("%s\n", yellow(vStr))
}

func mapReadAllExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'map name|map index'\n")
		return
	}

	nameOrID := args[0]
	m, err := nameOrIDToMap(nameOrID)
	if err != nil {
		printRed("%s\n", err)
		return
	}

	mt := m.GetType()
	ks := int(m.GetDef().KeySize)
	vs := int(m.GetDef().ValueSize)
	for _, k := range m.Keys() {
		v, err := m.Lookup(k)
		if err != nil {
			printRed("Error while looking up key '%s': %s\n", k, err)
			return
		}

		kPtr, ok := k.(emulator.PointerValue)
		if !ok {
			printRed("Error map key of type '%T' is not a emulator.PointerValue\n", k)
			return
		}
		kVal, err := kPtr.ReadRange(0, ks)
		if err != nil {
			printRed("Error read range key: %s\n", err)
			return
		}
		vPtr, ok := v.(emulator.PointerValue)
		if !ok {
			printRed("Error map value of type '%T' is not a emulator.PointerValue\n", v)
			return
		}
		vVal, err := vPtr.ReadRange(0, vs)
		if err != nil {
			printRed("Error read range key: %s\n", err)
			return
		}

		kStr := fmt.Sprintf("%0*X", vs, kVal)
		vStr := fmt.Sprintf("%0*X", ks, vVal)

		if bfmt, ok := mt.Key.(gobpfld.BTFValueFormater); ok {
			var kw strings.Builder
			_, err = bfmt.FormatValue(kVal, &kw, false)
			if err != nil {
				// TODO just fall back to showing bytes if we have formatting errors.
				printRed("Error while formatting key: %s\n", err)
				return
			}
			kStr = kw.String()
		}

		if bfmt, ok := mt.Value.(gobpfld.BTFValueFormater); ok {
			var vw strings.Builder
			_, err = bfmt.FormatValue(vVal, &vw, false)
			if err != nil {
				// TODO just fall back to showing bytes if we have formatting errors.
				printRed("Error while formatting value: %s\n", err)
				return
			}
			vStr = vw.String()
		}

		fmt.Printf("%s = %s\n",
			blue(kStr),
			yellow(vStr),
		)
	}
}

func mapSetExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'map name|map index'\n")
		return
	}

	if len(args) < 2 {
		printRed("Missing required argument 'key'\n")
		return
	}

	if len(args) < 3 {
		printRed("Missing required argument 'value'\n")
		return
	}

	nameOrID := args[0]
	m, err := nameOrIDToMap(nameOrID)
	if err != nil {
		printRed("%s\n", err)
		return
	}

	keySize := m.GetDef().KeySize
	valueSize := m.GetDef().ValueSize

	kv, err := valueFromString(args[1], int(keySize))
	if err != nil {
		printRed("Error parsing key: %s\n", err)
		return
	}

	vv, err := valueFromString(args[2], int(valueSize))
	if err != nil {
		printRed("Error parsing key: %s\n", err)
		return
	}

	_, err = m.Update(kv, vv, bpfsys.BPFMapElemAny)
	if err != nil {
		printRed("Error updating map: %s\n", err)
		return
	}

	fmt.Println("Map value written")
}

func mapDelExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'map name|map index'\n")
		return
	}

	if len(args) < 2 {
		printRed("Missing required argument 'key'\n")
		return
	}

	nameOrID := args[0]
	m, err := nameOrIDToMap(nameOrID)
	if err != nil {
		printRed("%s\n", err)
		return
	}

	keySize := m.GetDef().KeySize

	kv, err := valueFromString(args[1], int(keySize))
	if err != nil {
		printRed("Error parsing key: %s\n", err)
		return
	}

	err = m.Delete(kv, bpfsys.BPFMapElemAny)
	if err != nil {
		printRed("Error deleting value from map: %s\n", err)
		return
	}

	fmt.Println("Map value deleted")
}

func mapPushExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'map name|map index'\n")
		return
	}

	if len(args) < 2 {
		printRed("Missing required argument 'value'\n")
		return
	}

	nameOrID := args[0]
	m, err := nameOrIDToMap(nameOrID)
	if err != nil {
		printRed("%s\n", err)
		return
	}

	valueSize := m.GetDef().ValueSize

	vv, err := valueFromString(args[1], int(valueSize))
	if err != nil {
		printRed("Error parsing key: %s\n", err)
		return
	}

	err = m.Push(vv, int64(m.GetDef().ValueSize))
	if err != nil {
		printRed("Error updating map: %s\n", err)
		return
	}

	fmt.Println("Map value written")
}

func mapPopExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'map name|map index'\n")
		return
	}

	nameOrID := args[0]
	m, err := nameOrIDToMap(nameOrID)
	if err != nil {
		printRed("%s\n", err)
		return
	}

	mt := m.GetType()
	vs := int(m.GetDef().ValueSize)

	value, err := m.Pop()
	if err != nil {
		printRed("Error pop map: %s\n", err)
		return
	}

	vPtr, ok := value.(emulator.PointerValue)
	if !ok {
		if _, ok := value.(*emulator.IMMValue); ok && value.Value() == 0 {
			printRed("Map doesn't contain a value for the given key\n")
			return
		}

		printRed("Error map value of type '%T' is not a emulator.PointerValue\n", value)
		return
	}
	vVal, err := vPtr.ReadRange(0, vs)
	if err != nil {
		printRed("Error read range key: %s\n", err)
		return
	}

	vStr := fmt.Sprintf("%0*X", vs, vVal)

	if bfmt, ok := mt.Value.(gobpfld.BTFValueFormater); ok {
		var vw strings.Builder
		_, err = bfmt.FormatValue(vVal, &vw, true)
		if err != nil {
			// TODO just fall back to showing bytes if we have formatting errors.
			printRed("Error while formatting value: %s\n", err)
			return
		}
		vStr = vw.String()
	}

	fmt.Printf("%s\n", yellow(vStr))
}

func nameOrIDToMap(nameOrID string) (emulator.Map, error) {
	id, err := strconv.Atoi(nameOrID)
	if err != nil {
		id = -1
		for i := range vm.Maps {
			if i == 0 {
				continue
			}

			if mapName[i] == nameOrID {
				id = i
				break
			}
		}
		if id == -1 {
			return nil, fmt.Errorf("No map with name '%s' exists, use 'maps list' to see valid options", nameOrID)
		}
	}
	if id < 1 || len(vm.Maps) <= id {
		return nil, fmt.Errorf("No map with id '%d' exists, use 'maps list' to see valid options", id)
	}

	return vm.Maps[id], nil
}

func valueFromString(str string, size int) (emulator.RegisterValue, error) {
	if strings.HasPrefix(str, "0x") {
		b, err := hex.DecodeString(strings.TrimPrefix(str, "0x"))
		if err != nil {
			return nil, fmt.Errorf("hex decode: %w", err)
		}

		if len(b) > size {
			return nil, fmt.Errorf("hex to long, got '%d' bytes, expected '%d'", len(b), size)
		}

		// Zero pad to the correct size
		rb := make([]byte, size)
		copy(rb[size-len(b):], b)

		return &emulator.MemoryPtr{
			Memory: &emulator.ByteMemory{
				MemName: "key",
				Backing: rb,
			},
			Offset: 0,
		}, nil
	}

	num, err := strconv.Atoi(str)
	if err != nil {
		return nil, fmt.Errorf("atoi: %w", err)
	}

	b := make([]byte, size)
	switch size {
	case 1:
		b[0] = byte(num)

	case 2:
		binary.LittleEndian.PutUint16(b, uint16(num))

	case 4:
		binary.LittleEndian.PutUint32(b, uint32(num))

	case 8:
		binary.LittleEndian.PutUint64(b, uint64(num))

	default:
		return nil, fmt.Errorf("can't convert int to %d bytes", size)
	}

	return &emulator.MemoryPtr{
		Memory: &emulator.ByteMemory{
			Backing: b,
		},
	}, nil
}
