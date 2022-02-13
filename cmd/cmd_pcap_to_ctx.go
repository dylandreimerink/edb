package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/dylandreimerink/mimic"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
)

var pcapToCtxCommand = &cobra.Command{
	Use:   "pcap-to-ctx {.pcap input} {.json ctx output}",
	Short: "Convert a PCAP(packet capture) file into a context file which can be passed to a XDP eBPF program",
	RunE:  runPCAPToCtx,
	Args:  cobra.ExactArgs(2),
}

func runPCAPToCtx(cmd *cobra.Command, args []string) error {
	pcap, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("open pcap file: %w", err)
	}
	defer pcap.Close()

	r, err := pcapgo.NewReader(pcap)
	if err != nil {
		return fmt.Errorf("new ng reader: %w", err)
	}

	lt := r.LinkType()

	var ctxs []mimic.Context

	for i := 0; true; i++ {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}

			return fmt.Errorf("read packet: %w", err)
		}

		// XDP expects to always get ethernet packets. PCAPs don't nesseserely start at the ethernet level.
		// If we are missing data, mock it as best we can, and notify the user that part of the data is fake.
		// If we can't convert the data to valid XDP contexts, just don't and inform the user.

		// Use the CaptureInfo interface index by default
		InterfaceIndex := ci.InterfaceIndex

		pkt := gopacket.NewPacket(data, lt, gopacket.Default)
		buf := gopacket.NewSerializeBuffer()

		switch lt {
		case layers.LinkTypeLinuxSLL, layers.LinkTypeLinuxSLL2:
			// If the PCAP contains linux cooked packets, replace the SLL header with a fake ethernet header
			pktLayers := pkt.Layers()

			switch lt {
			case layers.LinkTypeLinuxSLL:
				sll, ok := pktLayers[0].(*layers.LinuxSLL)
				if !ok {
					continue
				}

				pktLayers[0] = &layers.Ethernet{
					SrcMAC:       sll.Addr,
					DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
					EthernetType: sll.EthernetType,
					BaseLayer: layers.BaseLayer{
						Payload: sll.Payload,
					},
				}

			case layers.LinkTypeLinuxSLL2:
				sll2, ok := pktLayers[0].(*layers.LinuxSLL2)
				if !ok {
					continue
				}

				pktLayers[0] = &layers.Ethernet{
					SrcMAC:       sll2.Addr,
					DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
					EthernetType: sll2.ProtocolType,
					BaseLayer: layers.BaseLayer{
						Payload: sll2.Payload,
					},
				}

				// SLL2 has interface index info per packet
				InterfaceIndex = int(sll2.InterfaceIndex)
			}

			serializeable := make([]gopacket.SerializableLayer, 0, len(pktLayers))
			for _, l := range pktLayers {
				sl, ok := l.(gopacket.SerializableLayer)
				if !ok {
					continue
				}
				serializeable = append(serializeable, sl)
			}

			err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, serializeable...)
			if err != nil {
				fmt.Println(err)
				continue
			}

			data = buf.Bytes()

		case layers.LinkTypeEthernet:
			// Already an ethernet packet, nothing to do here
		}

		ctx := &mimic.GenericContext{
			Name: ci.Timestamp.String(),
			Registers: mimic.GenericContextRegisters{
				R1: "xdp_md",
			},
			Memory: []mimic.GenericContextMemory{
				{
					Name: "pkt",
					Block: &mimic.GenericContextMemoryBlock{
						Value: data,
						// TODO determine endianness of pcap
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
						Offset: len(data),
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
						Value: int64(InterfaceIndex),
						Size:  32,
					},
				},
				{
					Name: "rx_queue_index",
					Int: &mimic.GenericContextInt{
						// PCAP files don't contain rx_queue_index info
						Size: 32,
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

		ctxs = append(ctxs, ctx)
	}

	ctxFile, err := os.Create(args[1])
	if err != nil {
		return fmt.Errorf("create context file: %w", err)
	}
	defer ctxFile.Close()

	jsonEncoder := json.NewEncoder(ctxFile)
	jsonEncoder.SetIndent("", "  ")
	err = jsonEncoder.Encode(ctxs)
	if err != nil {
		return fmt.Errorf("json encode context: %w", err)
	}

	return nil
}
