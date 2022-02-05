#!/bin/bash
clang -target bpf -Wall -O2 -g -c xdp_stats1.c -I/usr/include -o xdp_stats1
clang -target bpf -Wall -O2 -g -c bpf-to-bpf.c -I/usr/include -o bpf-to-bpf
clang -target bpf -Wall -O2 -g -c trace1.c -I/usr/include -o trace1
clang -target bpf -Wall -O2 -g -c tailcall.c -I/usr/include -o tailcall
clang -target bpf -Wall -O2 -g -c map-in-map.c -I/usr/include -o map-in-map
clang -target bpf -Wall -O2 -g -c stack.c -I/usr/include -o stack
clang -target bpf -Wall -O2 -g -c queue.c -I/usr/include -o queue
