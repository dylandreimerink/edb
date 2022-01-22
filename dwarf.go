package main

import (
	"debug/dwarf"
	"fmt"
	"strings"

	"github.com/dylandreimerink/edb/elf"
)

// DET DWARF Entry table, holds the parsed DWARF entries, used for quick lookups
type DET struct {
	Tree EntryNode

	// Entry per file, per line
	EntriesPerLoc map[string]map[int64][]*EntryNode

	// SubPrograms by name
	SubPrograms map[string]*EntryNode
	//
	EntitiesByOffset map[dwarf.Offset]*EntryNode
}

type EntryNode struct {
	Parent   *EntryNode
	Entry    *dwarf.Entry
	Children []*EntryNode
}

func (e *EntryNode) load(r *dwarf.Reader, det *DET, files []*dwarf.LineFile) error {
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

		declFile := entry.AttrField(dwarf.AttrDeclFile)
		declLine := entry.AttrField(dwarf.AttrDeclLine)
		if declFile != nil && declLine != nil {
			file := files[declFile.Val.(int64)]
			fileMap := det.EntriesPerLoc[file.Name]
			if fileMap == nil {
				fileMap = make(map[int64][]*EntryNode)
			}

			list := fileMap[declLine.Val.(int64)]
			list = append(list, child)
			fileMap[declLine.Val.(int64)] = list

			det.EntriesPerLoc[file.Name] = fileMap
		}

		det.EntitiesByOffset[entry.Offset] = child

		if entry.Tag == dwarf.TagSubprogram {
			name := entry.AttrField(dwarf.AttrName)
			if name != nil {
				det.SubPrograms[name.Val.(string)] = child
			}
		}

		if entry.Children {
			err = child.load(r, det, files)
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

func newDET(elf *elf.File, progSection string) (*DET, error) {
	det := DET{
		EntriesPerLoc:    make(map[string]map[int64][]*EntryNode),
		SubPrograms:      make(map[string]*EntryNode),
		EntitiesByOffset: make(map[dwarf.Offset]*EntryNode),
	}

	dd, err := elf.DWARF()
	if err != nil {
		return nil, fmt.Errorf("dwarf: %w", err)
	}

	r := dd.Reader()
	det.Tree.Entry, err = r.Next()
	if err != nil {
		return nil, fmt.Errorf("next: %w", err)
	}

	lr, err := dd.LineReader(det.Tree.Entry)
	if err != nil {
		return nil, fmt.Errorf("lr: %w", err)
	}

	err = det.Tree.load(r, &det, lr.Files())
	if err != nil {
		return nil, fmt.Errorf("load tree: %w", err)
	}

	return &det, nil
}
