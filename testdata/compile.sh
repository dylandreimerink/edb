#!/bin/bash
clang -target bpf -Wall -O2 -g -c xdp_stats1.c -I/usr/include -o xdp_stats1
clang -target bpf -Wall -O2 -g -c bpf-to-bpf.c -I/usr/include -o bpf-to-bpf