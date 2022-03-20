package capctx

import (
	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/dylandreimerink/mimic"
)

// TODO should we make this configurable, start with 100 and allow the user to increase if they expect to need more
// packet data?
const maxXDPPacketSize = 100

func sendCtx(progType ebpf.ProgramType) []asm.Instruction {
	switch progType {
	case ebpf.SocketFilter, ebpf.SchedACT, ebpf.SchedCLS, ebpf.CGroupSKB, ebpf.LWTIn, ebpf.LWTOut, ebpf.LWTXmit,
		ebpf.SkSKB, ebpf.LWTSeg6Local, ebpf.FlowDissector:
		// __sk_buff

	case ebpf.Kprobe, ebpf.PerfEvent, ebpf.RawTracepoint:
		// pt_regs

	case ebpf.TracePoint:
		// different per tracepoint
		// https://stackoverflow.com/questions/64944729/read-ebpf-tracepoint-argument

	case ebpf.XDP:
		// xdp_md
		return []asm.Instruction{
			// Load buf pointer
			// __u32 *buf = ...;
			asm.LoadMem(asm.R0, asm.R10, bufferPtr, asm.DWord),

			// Set msg type
			asm.StoreImm(asm.R0, 0, int64(ctxData), asm.Byte),
			asm.StoreImm(asm.R0, 1, int64(progType), asm.Word),
			// Advance buf ptr
			asm.Add.Imm(asm.R0, 5),
			// Store location of size in R2
			asm.Mov.Reg(asm.R2, asm.R0),
			// Advance buf ptr, 2 bytes for `size`
			asm.Add.Imm(asm.R0, 2),

			// Copy xdp_md struct
			// buf[3] = xdp_md->ingress_ifindex
			asm.LoadMem(asm.R6, asm.R1, 12, asm.Word),
			asm.StoreMem(asm.R0, 12, asm.R6, asm.Word),
			// buf[4] = xdp_md->rx_queue_index
			asm.LoadMem(asm.R6, asm.R1, 16, asm.Word),
			asm.StoreMem(asm.R0, 16, asm.R6, asm.Word),
			// buf[1] = xdp_md->data_end
			// void *end = (void *)(long)xdp_md->data_end
			asm.LoadMem(asm.R7, asm.R1, 4, asm.Word),
			asm.StoreMem(asm.R0, 4, asm.R7, asm.Word),
			// buf[2] = xdp_md->data_meta
			asm.LoadMem(asm.R6, asm.R1, 8, asm.Word),
			asm.StoreMem(asm.R0, 8, asm.R6, asm.Word),
			// buf[0] = xdp_md->data
			// void *cur = (void *)(long)xdp_md->data
			asm.LoadMem(asm.R6, asm.R1, 0, asm.Word),
			asm.StoreMem(asm.R0, 0, asm.R6, asm.Word),

			// __u8 buf = (__u8 *) buf + 20
			asm.Add.Imm(asm.R0, 20),

			// i = 0
			asm.Mov.Imm(asm.R1, 0),

			// Copy packet memory
			// if cur+1 >= end: goto xdp_md_cp_done
			asm.Mov.Reg(asm.R9, asm.R6).WithSymbol("xdp_md_cp_cmp"),
			asm.Add.Imm(asm.R9, 1),
			asm.JGT.Reg(asm.R9, asm.R7, "xdp_md_cp_done"),
			// if i > maxXDPPacketSize: goto xdp_md_cp_done
			asm.JGT.Imm(asm.R1, maxXDPPacketSize, "xdp_md_cp_done"),

			// *buf = (__u8) *cur
			asm.LoadMem(asm.R8, asm.R6, 0, asm.Byte),
			asm.StoreMem(asm.R0, 0, asm.R8, asm.Byte),
			// buf++
			asm.Add.Imm(asm.R0, 1),
			// cur++
			asm.Add.Imm(asm.R6, 1),
			// i++
			asm.Add.Imm(asm.R1, 1),
			asm.Ja.Label("xdp_md_cp_cmp"),

			// Set i as `size` of ctx_data msg.
			asm.StoreMem(asm.R2, 0, asm.R1, asm.Half).WithSymbol("xdp_md_cp_done"),

			// Store buf ptr
			asm.StoreMem(asm.R10, bufferPtr, asm.R0, asm.DWord),
		}

	case ebpf.CGroupSock:
		// bpf_sock

	case ebpf.SockOps:
		// bpf_sock_ops

	case ebpf.CGroupDevice:
		// bpf_cgroup_dev_ctx

	case ebpf.SkMsg:
		// sk_msg_md

	case ebpf.CGroupSockAddr:
		// bpf_sock_addr

	case ebpf.LircMode2:
		// unsigned int *sample

	case ebpf.SkReuseport:
		// sk_reuseport_md

	case ebpf.CGroupSysctl:
		// bpf_sysctl

	case ebpf.CGroupSockopt:
		// bpf_sockopt

	case ebpf.StructOps:
		// different per attach point

	case ebpf.Tracing:
		// different per attach point

	case ebpf.Extension:
		// different per attach point

	case ebpf.LSM:
		// different per attach point

	case ebpf.SkLookup:
		// bpf_sk_lookup

	case ebpf.Syscall:
		// struct args*
	}

	return nil
}

func ctxDataDecode(progType ebpf.ProgramType, data []byte) (mimic.Context, []byte, error) {
	ne := mimic.GetNativeEndianness()

	switch progType {
	case ebpf.SocketFilter, ebpf.SchedACT, ebpf.SchedCLS, ebpf.CGroupSKB, ebpf.LWTIn, ebpf.LWTOut, ebpf.LWTXmit,
		ebpf.SkSKB, ebpf.LWTSeg6Local, ebpf.FlowDissector:
		// __sk_buff

	case ebpf.Kprobe, ebpf.PerfEvent, ebpf.RawTracepoint:
		// pt_regs

	case ebpf.TracePoint:
		// different per tracepoint
		// https://stackoverflow.com/questions/64944729/read-ebpf-tracepoint-argument

	case ebpf.XDP:
		// xdp_md
		size := ne.Uint16(data[0:2])
		xdp_md := data[2:22]
		pkt := data[22 : 22+size]
		data = data[22+size:]

		ctx := mimic.GenericContext{
			Emulator: make(map[string]interface{}),
			Memory: []mimic.GenericContextMemory{
				{
					Name: "pkt",
					Block: &mimic.GenericContextMemoryBlock{
						Value:     pkt,
						ByteOrder: binary.BigEndian,
					},
				},
				{
					Name: "data",
					Pointer: &mimic.GenericContextPointer{
						Memory: "pkt",
						Offset: 0,
						Size:   32,
					},
				},
				{
					Name: "data_end",
					Pointer: &mimic.GenericContextPointer{
						Memory: "pkt",
						Offset: int(size),
						Size:   32,
					},
				},
				{
					Name: "data_meta",
					Pointer: &mimic.GenericContextPointer{
						Memory: "pkt",
						Offset: 0,
						Size:   32,
					},
				},
				{
					Name: "ingress_ifindex",
					Int: &mimic.GenericContextInt{
						Value: int64(ne.Uint32(xdp_md[12:16])),
						Size:  32,
					},
				},
				{
					Name: "rx_queue_index",
					Int: &mimic.GenericContextInt{
						Value: int64(ne.Uint32(xdp_md[16:20])),
						Size:  32,
					},
				},
				{
					Name: "egress_ifindex",
					Int: &mimic.GenericContextInt{
						Value: 0,
						Size:  32,
					},
				},
				{
					Name: "xdp_md",
					Struct: &mimic.GenericContextStruct{
						Fields: []mimic.GenericContextStructField{
							{
								Name:   "data",
								Memory: "data",
							},
							{
								Name:   "data_end",
								Memory: "data_end",
							},
							{
								Name:   "data_meta",
								Memory: "data_meta",
							},
							{
								Name:   "ingress_ifindex",
								Memory: "ingress_ifindex",
							},
							{
								Name:   "rx_queue_index",
								Memory: "rx_queue_index",
							},
							{
								Name:   "egress_ifindex",
								Memory: "egress_ifindex",
							},
						},
					},
				},
			},
		}

		ctx.Registers.R1 = "xdp_md"

		return &ctx, data, nil

	case ebpf.CGroupSock:
		// bpf_sock

	case ebpf.SockOps:
		// bpf_sock_ops

	case ebpf.CGroupDevice:
		// bpf_cgroup_dev_ctx

	case ebpf.SkMsg:
		// sk_msg_md

	case ebpf.CGroupSockAddr:
		// bpf_sock_addr

	case ebpf.LircMode2:
		// unsigned int *sample

	case ebpf.SkReuseport:
		// sk_reuseport_md

	case ebpf.CGroupSysctl:
		// bpf_sysctl

	case ebpf.CGroupSockopt:
		// bpf_sockopt

	case ebpf.StructOps:
		// different per attach point

	case ebpf.Tracing:
		// different per attach point

	case ebpf.Extension:
		// different per attach point

	case ebpf.LSM:
		// different per attach point

	case ebpf.SkLookup:
		// bpf_sk_lookup

	case ebpf.Syscall:
		// struct args*
	}

	return nil, data, nil
}
