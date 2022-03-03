module github.com/dylandreimerink/edb

go 1.16

replace github.com/cilium/ebpf => ../ebpf

// replace github.com/cilium/ebpf => github.com/dylandreimerink/ebpf v0.8.1-0.20220224192713-bd4672e3772a

replace github.com/google/gopacket => github.com/dylandreimerink/gopacket v1.1.20-0.20220126223506-0d3623bffc1f

require (
	github.com/c-bata/go-prompt v0.2.6
	github.com/cilium/ebpf v0.8.0
	github.com/davecgh/go-spew v1.1.1
	github.com/dylandreimerink/mimic v0.0.6
	github.com/go-delve/delve v1.8.0
	github.com/google/gopacket v1.1.19
	github.com/lithammer/fuzzysearch v1.1.3
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d
	github.com/spf13/cobra v1.3.0
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/sys v0.0.0-20211205182925-97ca703d548d
)
