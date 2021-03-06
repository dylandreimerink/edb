package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/cilium/ebpf/asm"
)

const defUrl = "https://raw.githubusercontent.com/libbpf/libbpf/9c44c8a8e01cf86bc801c3b72324358d5ea99e50/src/bpf_helper_defs.h"

func main() {
	tmpDir := os.TempDir()
	cacheDir := path.Join(tmpDir, "edb-cache")
	cacheFile := path.Join(tmpDir, "edb-cache", "bpf_helper_defs.h")

	f, err := os.Open(cacheFile)
	if err != nil {
		err = os.MkdirAll(cacheDir, 0775)
		if err != nil {
			panic(err)
		}

		f, err = os.Create(cacheFile)
		if err != nil {
			panic(err)
		}

		resp, err := http.Get(defUrl)
		if err != nil {
			panic(err)
		}

		_, err = io.Copy(f, resp.Body)
		if err != nil {
			panic(err)
		}

		_, err = f.Seek(0, 0)
		if err != nil {
			panic(err)
		}
	}
	defer f.Close()

	contents, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}

	parsedFuncs := make([]parsedFunc, 0)

	for _, match := range fnRegexp.FindAllSubmatch(contents, -1) {
		parsedFunc := parsedFunc{
			RetType: strToCtype(strings.TrimSpace(string(match[1]))),
		}

		num, err := strconv.Atoi(string(match[3]))
		if err != nil {
			panic(err)
		}
		parsedFunc.FnNum = asm.BuiltinFunc(num)

		for _, param := range strings.Split(string(match[2]), ", ") {
			name := paramRegexp.FindString(param)
			typ := strings.TrimSuffix(param, name)

			// Edge case, used to indicate there are no Params
			if typ == "" && name == "void" {
				continue
			}

			parsedFunc.Params = append(parsedFunc.Params, parsedParam{
				Typ:  strToCtype(strings.TrimSpace(typ)),
				Name: name,
			})
		}

		parsedFuncs = append(parsedFuncs, parsedFunc)
	}

	tpl, err := template.New("tpl").Parse(goTpl)
	if err != nil {
		panic(err)
	}

	err = tpl.Execute(os.Stdout, parsedFuncs)
	if err != nil {
		panic(err)
	}
}

var (
	fnRegexp    = regexp.MustCompile(`static (.+)\(\*[a-zA-Z0-9_]+\)\(([^;\n]*)\) = \(void \*\) ([0-9]+);\n`)
	cTypeRegexp = regexp.MustCompile(`(const)? ?(struct)? ?([a-zA-Z_0-9\.]+)? ?(\*)?`)
	paramRegexp = regexp.MustCompile(`([a-zA-Z0-9_]+)$`)
)

type parsedFunc struct {
	RetType parsedCType
	Params  []parsedParam
	FnNum   asm.BuiltinFunc
}

type parsedParam struct {
	Typ  parsedCType
	Name string
}

type parsedCType struct {
	Name   string
	Ptr    bool
	Const  bool
	Struct bool
}

func (c parsedCType) String() string {
	var sb strings.Builder
	sb.WriteString("CType{")

	props := []string{fmt.Sprintf("Name: \"%s\"", c.Name)}
	if c.Const {
		props = append(props, "Const: true")
	}
	if c.Struct {
		props = append(props, "Struct: true")
	}
	if c.Ptr {
		props = append(props, "Ptr: true")
	}

	sb.WriteString(strings.Join(props, ", "))
	sb.WriteString("}")

	return sb.String()
}

func strToCtype(str string) parsedCType {
	match := cTypeRegexp.FindStringSubmatch(str)
	return parsedCType{
		Const:  match[1] != "",
		Struct: match[2] != "",
		Name:   match[3],
		Ptr:    match[4] != "",
	}
}

var goTpl = `package helperdata

import (
	"github.com/cilium/ebpf/asm"
	"strings"
)

// Code generated by 'go run cmd/gen/helperdata.go | gofmt > pkg/helperdata/helperdata.go' DO NOT EDIT

// HelperFunc describes the signature of a helper function
type HelperFunc struct {
	RetType CType
	Params  []HelperParam
}

// HelperParam describes a parameter of a helper function
type HelperParam struct {
	Type  CType
	Name string
}

// CType describes a type in the C language
type CType struct {
	Name string
	Ptr bool
	Const bool
	Struct bool
}

func (c CType) String() string {
	var parts []string
	if c.Const {
		parts = append(parts, "const")
	}

	if c.Struct {
		parts = append(parts, "struct")
	}

	parts = append(parts, c.Name)

	if c.Ptr {
		parts = append(parts, "*")
	}

	return strings.Join(parts, " ")
}

// Signatures is a map of eBPF helper function signatures keyed by asm.BuiltinFunc
var Signatures = map[asm.BuiltinFunc]HelperFunc{ {{ range . }}
asm.{{.FnNum}}: {
	RetType: {{.RetType}},
	Params: []HelperParam{
		{{ range .Params }}{Type: {{.Typ}}, Name: "{{.Name}}"},
		{{end}}
    },
},{{end}}
}
`
