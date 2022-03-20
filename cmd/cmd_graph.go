package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/dylandreimerink/edb/analyse"
	"github.com/emicklei/dot"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
)

func graphCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graph {ELF} {program name}",
		Short: "Generate a control-flow graph for an eBPF program",
		Long: "This command reads the provided ELF file and creates a control-flow graph for the given program. " +
			"The program is broken up into 'blocks' of code by BPF-to-BPF function calls and branching instructions. " +
			"Red arrows indicate the non-branching path, green arrows indicate the branching path, yellow arrows " +
			"indicate bpf-to-bpf function calls(which will return and then follow the non-branching path).\n\n" +
			"If no flags are specified the command will attempt to render the graph as SVG and open it in the browser.",
		RunE: runGraph,
		Args: cobra.ExactArgs(2),
	}

	f := cmd.Flags()

	f.StringVarP(&graphOutput, "output", "o", "", "output to given file path or - for stdout, instread of opening "+
		"in browser")
	f.StringVarP(&graphOutputFormat, "format", "f", "svg", "The output format: dot, svg, pdf or png")

	return cmd
}

var (
	graphOutput       string
	graphOutputFormat string
)

func runGraph(cmd *cobra.Command, args []string) error {
	// Load collection from ELF
	spec, err := ebpf.LoadCollectionSpec(args[0])
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}

	prog := spec.Programs[args[1]]
	if prog == nil {
		return fmt.Errorf(
			"no program with name '%s', pick from: %s",
			args[1],
			strings.Join(maps.Keys(spec.Programs), ", "),
		)
	}

	graph := ProgramToGraph(prog)

	switch graphOutputFormat {
	case "dot":
		if graphOutput == "-" {
			fmt.Println(graph.String())
			return nil
		}

		var f *os.File
		if graphOutput == "" {
			f, err = os.CreateTemp(os.TempDir(), "edb-graph-*.dot.txt")
			if err != nil {
				return fmt.Errorf("create tmp: %w", err)
			}
		} else {
			f, err = os.Create(graphOutput)
			if err != nil {
				return fmt.Errorf("create file: %w", err)
			}
		}

		_, err = io.Copy(f, strings.NewReader(graph.String()))
		if err != nil {
			return fmt.Errorf("copy: %w", err)
		}

		if graphOutput == "" {
			browser.OpenFile(f.Name())
		}

	case "png", "svg", "pdf":
		dotF, err := os.CreateTemp(os.TempDir(), "edb-graph-*.dot")
		if err != nil {
			return fmt.Errorf("create tmp: %w", err)
		}

		_, err = io.Copy(dotF, strings.NewReader(graph.String()))
		if err != nil {
			return fmt.Errorf("copy: %w", err)
		}

		var (
			cmd  *exec.Cmd
			imgF *os.File
		)
		switch graphOutput {
		case "-":
			cmd = exec.Command("dot", fmt.Sprintf("-T%s", graphOutputFormat), dotF.Name())
			cmd.Stdout = os.Stdout
		case "":
			imgF, err = os.CreateTemp(os.TempDir(), fmt.Sprintf("edb-graph-*.%s", graphOutputFormat))
			if err != nil {
				return fmt.Errorf("create tmp: %w", err)
			}

			cmd = exec.Command(
				"dot",
				fmt.Sprintf("-T%s", graphOutputFormat),
				fmt.Sprintf("-o%s", imgF.Name()),
				dotF.Name(),
			)
		default:
			cmd = exec.Command(
				"dot",
				fmt.Sprintf("-T%s", graphOutputFormat),
				fmt.Sprintf("-o%s", graphOutput),
				dotF.Name(),
			)
		}

		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("dot: %w", err)
		}

		if graphOutput == "" {
			browser.OpenFile(imgF.Name())
		}
	}

	return nil
}

func ProgramToGraph(prog *ebpf.ProgramSpec) *dot.Graph {
	functions := prog.Instructions.FunctionReferences()

	blocks := analyse.ProgramBlocks(prog.Instructions)

	graph := dot.NewGraph(dot.Directed)
	graph.Attr("splines", "ortho")
	graph.Attr("nodesep", "0.5")
	graph.Attr("ranksep", "0.3")

	funcSubGraph := graph.Subgraph(prog.Instructions[0].Symbol(), dot.ClusterOption{})
	funcSubGraph.Attr("color", "blue")

	var instCnt int

	blockNodes := make(map[*analyse.ProgBlock]dot.Node)
	for _, block := range blocks {
		if functions[block.Block.Name()] {
			funcSubGraph = graph.Subgraph(block.Block.Name(), dot.ClusterOption{})
			funcSubGraph.Attr("color", "blue")
		}

		var label strings.Builder
		label.WriteString("\"")
		for _, inst := range block.Block {
			// Remove references from jump ops since they are not needed when we have edges
			if inst.OpCode.JumpOp() != asm.InvalidJumpOp {
				inst = inst.WithReference("")
			}

			label.WriteString(fmt.Sprintf("%d %v\\l", instCnt, inst))
			instCnt++
		}
		label.WriteString("\"")

		blockNode := funcSubGraph.Node(fmt.Sprintf("Block %d", block.Index))

		blockNode.Attr("label", dot.Literal(label.String()))
		blockNode.Attr("shape", "box")

		blockNodes[block] = blockNode
	}

	for _, block := range blocks {
		if block.Branch != nil {
			edge := graph.Edge(blockNodes[block], blockNodes[block.Branch]).
				Attr("color", "darkgreen")

			if block.Block[len(block.Block)-1].OpCode.JumpOp() == asm.Call {
				edge.Attr("color", "orange")
			}
		}

		if block.NoBranch != nil {
			graph.Edge(blockNodes[block], blockNodes[block.NoBranch]).
				Attr("color", "red")
		}
	}

	return graph
}
