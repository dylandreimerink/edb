module github.com/dylandreimerink/edb

go 1.16

replace github.com/cilium/ebpf => github.com/dylandreimerink/ebpf v0.8.1-0.20220213140259-64386bac261c

replace github.com/google/gopacket => github.com/dylandreimerink/gopacket v1.1.20-0.20220126223506-0d3623bffc1f

require (
	github.com/c-bata/go-prompt v0.2.6
	github.com/cilium/ebpf v0.8.0
	github.com/dylandreimerink/mimic v0.0.1
	github.com/go-delve/delve v1.8.0
	github.com/google/gopacket v0.0.0-00010101000000-000000000000
	github.com/lithammer/fuzzysearch v1.1.3
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d
	github.com/spf13/cobra v1.3.0
)
