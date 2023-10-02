#!/usr/bin/python
#
# An example program which opens an IR and prints all paths between
# two blocks.
#
# To run this example, do the following.
#
# 1. Install the gtirb package from Pypi.
#
# 2. Run ddisasm to disassemble a binary to GTIRB.
#
#    $ echo 'main(){puts("hello world");}'|gcc -x c - -o /tmp/hello
#    $ ddisasm /tmp/hello --ir /tmp/hello.gtirb
#
# 3. Execute the following command to run the program on the
#    serialized GTIRB data.
#
#    $ ./doc/examples/cfg-paths.py /tmp/hello.gtirb
import sys

import gtirb
import networkx as nx

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} /path/to/file.gtirb")
    quit(1)

ir = gtirb.ir.IR.load_protobuf(sys.argv[1])

for edge in ir.cfg:
    if not isinstance(edge.target, gtirb.block.ProxyBlock):
        print(str(edge.source.address) + ' ' + str(edge.target.address))
