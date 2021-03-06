package debug

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/dylandreimerink/mimic"
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
				Name:     "map name",
				Required: true,
			}},
		},
		{
			Name:    "get",
			Summary: "Get the value of a particular key in a map",
			Exec:    mapGetExec,
			Args: []CmdArg{
				{
					Name:     "map name",
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
					Name:     "map name",
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
					Name:     "map name",
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
					Name:     "map name",
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
					Name:     "map name",
					Required: true,
				},
			},
		},
	},
}

func listMapsExec(args []string) {
	for name, m := range vmEmulator.Maps {
		fmt.Printf("%s:\n", green(name))

		spec := m.GetSpec()
		fmt.Printf("        Type: %s\n", spec.Type)
		fmt.Print("         Key: ")

		if m.GetSpec().Key != nil && m.GetSpec().Key.TypeName() != "" {
			cType := blue(strings.TrimSpace(BtfToCDef(m.GetSpec().Key, 14)))
			fmt.Printf("%s (%d bytes)\n", cType, spec.KeySize)
		} else {
			fmt.Printf("%d bytes\n", spec.KeySize)
		}

		fmt.Print("       Value: ")
		if m.GetSpec().Value != nil && m.GetSpec().Value.TypeName() != "" {
			cType := yellow(strings.TrimSpace(BtfToCDef(m.GetSpec().Value, 14)))
			fmt.Printf("%s (%d bytes)\n", cType, spec.ValueSize)
		} else {
			fmt.Printf("%d bytes\n", spec.ValueSize)
		}

		fmt.Printf(" Max entries: %d\n", spec.MaxEntries)
		fmt.Printf("       Flags: %d\n\n", spec.Flags)
		// TODO decode flags into human readable strings
	}
}

func mapGetExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'map name'\n")
		return
	}

	if len(args) < 2 {
		printRed("Missing required argument 'key'\n")
		return
	}

	name := args[0]
	m, err := nameToMap(name)
	if err != nil {
		printRed("%s\n", err)
		return
	}

	spec := m.GetSpec()
	ks := int(spec.KeySize)
	vs := int(spec.ValueSize)

	kv, err := valueFromString(args[1], ks)
	if err != nil {
		printRed("Error parsing key: %s\n", err)
		return
	}

	valPtr, err := m.Lookup(kv, 0)
	if err != nil {
		printRed("Error lookup map: %s\n", err)
		return
	}

	if valPtr == 0 {
		fmt.Println("No value found")
		return
	}

	entry, off, found := process.VM.MemoryController.GetEntry(valPtr)
	if !found {
		printRed("Not memory entry for value pointer 0x%08X\n", valPtr)
		return
	}

	// TODO format the key bytes using BTF type if available

	// By default, just print the value as an offset into the memory object, which always works
	vStr := yellow(fmt.Sprintf("(%T)(%p) + %d", entry.Object, entry.Object, off))

	// If the object is virtual memory, we can read the raw value bytes
	if vmMem, ok := entry.Object.(mimic.VMMem); ok {
		// We can read the actual value
		vVal := make([]byte, spec.ValueSize)
		if err = vmMem.Read(off, vVal); err == nil {
			// We have the bytes of the value, so display those
			vStr = yellow(fmt.Sprintf("%0*X", vs, vVal))

			switch m.GetSpec().Type {
			case ebpf.ArrayOfMaps, ebpf.HashOfMaps, ebpf.ProgramArray:
				// For map in map types, we know that the values should be pointers to maps, so attempt to find
				// and display them.
				addr := mimic.GetNativeEndianness().Uint32(vVal)
				entry, _, found := process.VM.MemoryController.GetEntry(addr)
				if found {
					vStr = fmt.Sprintf("%s -> <%s>", vStr, green(entry.Name))
				}

			default:
				// TODO format the bytes using BTF type
			}
		}
	}

	fmt.Printf("%s\n", vStr)
}

func mapReadAllExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'map name'\n")
		return
	}

	name := args[0]
	m, err := nameToMap(name)
	if err != nil {
		printRed("%s\n", err)
		return
	}

	spec := m.GetSpec()
	ks := int(spec.KeySize)
	vs := int(spec.ValueSize)
	// TODO show values for all CPU indices
	keys := m.Keys(0)
	for i := 0; i < len(keys)/ks; i++ {
		k := keys[i*ks : (i+1)*ks]
		vPtr, err := m.Lookup(k, 0)
		if err != nil {
			printRed("Error while looking up key '%v': %s\n", k, err)
			return
		}

		memEntry, off, found := vm.MemoryController.GetEntry(vPtr)
		if !found {
			printRed("Mem ctl doesn't have entry for value pointer 0x%08X\n", vPtr)
			return
		}

		var kStr string
		if spec.Key == nil {
			kStr = fmt.Sprintf("%0*X", ks, k)
		} else {
			kStr = BtfBytesToCValue(spec.Key, k, 0, false)
		}

		// TODO format the key bytes using BTF type if available

		// By default, just print the value as an offset into the memory object, which always works
		vStr := yellow(fmt.Sprintf("(%T)(%p) + %d", memEntry.Object, memEntry.Object, off))

		// If the object is virtual memory, we can read the raw value bytes
		if vmMem, ok := memEntry.Object.(mimic.VMMem); ok {
			// We can read the actual value
			vVal := make([]byte, spec.ValueSize)
			if err = vmMem.Read(off, vVal); err == nil {
				// We have the bytes of the value, so display those
				vStr = yellow(fmt.Sprintf("%0*X", vs, vVal))

				switch m.GetSpec().Type {
				case ebpf.ArrayOfMaps, ebpf.HashOfMaps, ebpf.ProgramArray:
					// For map in map types, we know that the values should be pointers to maps, so attempt to find
					// and display them.
					addr := mimic.GetNativeEndianness().Uint32(vVal)
					entry, _, found := process.VM.MemoryController.GetEntry(addr)
					if found {
						vStr = fmt.Sprintf("%s -> <%s>", vStr, green(entry.Name))
					}
				default:
					if spec.Value != nil {
						vStr = yellow(BtfBytesToCValue(spec.Value, vVal, 0, false))
					}
				}
			}
		}

		fmt.Printf("%s = %s\n",
			blue(kStr),
			vStr,
		)
	}
}

func mapSetExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'map name'\n")
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

	name := args[0]
	m, err := nameToMap(name)
	if err != nil {
		printRed("%s\n", err)
		return
	}
	mu, ok := m.(mimic.LinuxMapUpdater)
	if !ok {
		printRed("Can't update map of this type\n")
		return
	}

	keySize := m.GetSpec().KeySize
	valueSize := m.GetSpec().ValueSize

	kv, err := valueFromString(args[1], int(keySize))
	if err != nil {
		printRed("Error parsing key: %s\n", err)
		return
	}

	var vv []byte
	switch m.GetSpec().Type {
	case ebpf.ArrayOfMaps, ebpf.HashOfMaps:
		// For these map types, the name of a map should be input as value.
		// We will then actually set the addr of that map.
		valueMap, found := vmEmulator.Maps[args[2]]
		if !found {
			printRed("Error can't find map with name '%s'\n", args[2])
			return
		}

		entry, found := vm.MemoryController.GetEntryByObject(valueMap)
		if !found {
			printRed("Error can't memory entry for map '%s'\n", args[2])
			return
		}

		vv = make([]byte, 4)
		mimic.GetNativeEndianness().PutUint32(vv, entry.Addr)

	case ebpf.ProgramArray:
		for _, prog := range vm.GetPrograms() {
			if prog.Name != args[2] {
				continue
			}

			entry, found := vm.MemoryController.GetEntryByObject(prog)
			if !found {
				printRed("Error can't memory entry for program '%s'\n", args[2])
				return
			}

			vv = make([]byte, 4)
			mimic.GetNativeEndianness().PutUint32(vv, entry.Addr)
			break
		}

	default:
		vv, err = valueFromString(args[2], int(valueSize))
		if err != nil {
			printRed("Error parsing value: %s\n", err)
			return
		}
	}

	err = mu.Update(kv, vv, 0, 0)
	if err != nil {
		printRed("Error updating map: %s\n", err)
		return
	}

	fmt.Println("Map value written")
}

func mapDelExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'map name'\n")
		return
	}

	if len(args) < 2 {
		printRed("Missing required argument 'key'\n")
		return
	}

	name := args[0]
	m, err := nameToMap(name)
	if err != nil {
		printRed("%s\n", err)
		return
	}
	md, ok := m.(mimic.LinuxMapDeleter)
	if !ok {
		printRed("Can't delete values from this map type\n")
		return
	}

	keySize := m.GetSpec().KeySize

	kv, err := valueFromString(args[1], int(keySize))
	if err != nil {
		printRed("Error parsing key: %s\n", err)
		return
	}

	err = md.Delete(kv)
	if err != nil {
		printRed("Error deleting value from map: %s\n", err)
		return
	}

	fmt.Println("Map value deleted")
}

func mapPushExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'map name'\n")
		return
	}

	if len(args) < 2 {
		printRed("Missing required argument 'value'\n")
		return
	}

	name := args[0]
	m, err := nameToMap(name)
	if err != nil {
		printRed("%s\n", err)
		return
	}
	pusher, ok := m.(mimic.LinuxMapPusher)
	if !ok {
		printRed("Map type '%s' doesn't support the push operation\n", m.GetSpec().Type)
		return
	}

	valueSize := m.GetSpec().ValueSize

	vv, err := valueFromString(args[1], int(valueSize))
	if err != nil {
		printRed("Error parsing key: %s\n", err)
		return
	}

	err = pusher.Push(vv, 0)
	if err != nil {
		printRed("Error updating map: %s\n", err)
		return
	}

	fmt.Println("Map value written")
}

func mapPopExec(args []string) {
	if len(args) < 1 {
		printRed("Missing required argument 'map name'\n")
		return
	}

	name := args[0]
	m, err := nameToMap(name)
	if err != nil {
		printRed("%s\n", err)
		return
	}

	var valVal []byte
	vs := 0
	if pea, ok := m.(*mimic.LinuxPerfEventArrayMap); ok {
		valVal, err = pea.Pop(0)
		if err != nil {
			printRed("Error pop map: %s\n", err)
			return
		}
		vs = len(valVal)

	} else {
		valVal = make([]byte, m.GetSpec().ValueSize)
		popper, ok := m.(mimic.LinuxMapPopper)
		if !ok {
			printRed("Map type '%s' doesn't support the pop operation\n", m.GetSpec().Type)
			return
		}
		vs = int(m.GetSpec().ValueSize)

		valAddr, err := popper.Pop(0)
		if err != nil {
			printRed("Error pop map: %s\n", err)
			return
		}
		if valAddr == 0 {
			fmt.Println("map is empty")
			return
		}

		valueEntry, off, found := vm.MemoryController.GetEntry(valAddr)
		if !found {
			printRed("Value addr doesn't exist in mem ctl")
			return
		}
		vmmem, ok := valueEntry.Object.(mimic.VMMem)
		if !ok {
			printRed("Value addr points to non-vmmem")
			return
		}

		err = vmmem.Read(off, valVal)
		if err != nil {
			printRed("VM-Mem read: %s", err)
			return
		}
	}

	vStr := fmt.Sprintf("%0*X", vs, valVal)

	fmt.Printf("%s\n", yellow(vStr))
}

func nameToMap(name string) (mimic.LinuxMap, error) {
	m, found := vmEmulator.Maps[name]
	if !found {
		return nil, fmt.Errorf("No map with name '%s' exists, use 'maps list' to see valid options", name)
	}

	return m, nil
}

func valueFromString(str string, size int) ([]byte, error) {
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

		return rb, nil
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

	return b, nil
}
