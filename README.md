# SAFER: A platform for safe and efficient binary instrumentation

SAFER is a platform for instrumenting/altering program binaries without
accessing the source code. This provides a platform for several applications
such as security hardening of binaries (control flow integrity, randomization,
debloating, etc), profram analysis, malware analysis, etc. SAFER operates on
stripped binaries and does not require symbolic or debugging information. It can
also handle various complexities such as position dependent and independent
code. SAFER also makes sure that support of exception handling and error
reporting in binaries remain unaffected by instrumentation.

SAFER incorporates our in-house disassembler called DASSA that can produce
3x accurate disassembly than other state-of-the-art disassemblers.

DASSA: https://dl.acm.org/doi/pdf/10.1145/3623278.3624766
SAFER: https://www.usenix.org/conference/usenixsecurity23/presentation/priyadarshan

### Dependencies

SAFER has been designed to operate on x86-64 bit Linux ELF binaries. Although,
the general principles behind SAFER's design are architecture independent, the
current design requires additional implementation effort to support other
architectures such as ARM and other platforms such as Windows.

SAFER's disassembly (DASSA) relies on capstone and libopcodes (binutils-dev) for
converting machine code (byte streams) to assembly instructions. capstone is
open source and a version of it is provided along with SAFER. Binutils-dev can
be installed on Linux systems using apt (apt install binutils-dev).  

SAFER also relies on a customized version of Linux system loader (ld.so) to load
and run instrumented programs. The current ld.so for SAFER has been implemented
by customizing the glibc version 2.31 (compatible with ubuntu 20.04). The
customizations can be easily extended to other higher versions of glibc.

### Installation

1. Installing customized loader:

```bash
cd SAFER/SAFER-Loader
mkdir glibc-build
cd glibc-build
../glibc-2.31/configure --prefix=/usr
make
cd elf
sudo cp ld.so /usr/lib/x86_64-linux-gnu/ld-safer.so
cd /lib64
sudo ln -sf /usr/lib/x86_64-linux-gnu/ld-safer.so ld-linux-xsafer.so.2
```

2. Installing SAFER and its dependencies:

```bash
cd SAFER
./install.sh
```

### API and usage

1. To disassemble:

```bash
cd SAFER/run
make clean
make
./run.sh /bin/ls disasmonly
```

Output assembly: SAFER/run/tmp/ls_defcode.s

2. To disassemble and dump control flow graph


```bash
./run.sh /bin/ls disasmonly dumpcfg
```
* Function entry: SAFER/run/tmp/cfg/functions.lst
* Basic blocks: SAFER/run/tmp/cfg/definite_basicblocks.lst
* Jump tables: SAFER/run/tmp/cfg/jmptables.lst

3. Instrumentation:

*STEP 1:* Find all modules in the target program
```bash
cd SAFER/testsuite
./find_libs.sh /bin/ls
```
*STEP 2:* Apply instrumentaion.

You can either apply pre-defined instrumentations or write custom
instrumentation code. Pre-defined instrumentations consist of known program
hardening schemes such as CFI, Shadow stack, etc. The detailed list of
pre-defined instrumentations are present in *SAFER/API*. Below example is for
applying CFI and shadow stack.

```bash
cd ${HOME}
./instrument_prog.sh ls ptr_trans=CFI_SHSTK
```

Custom instrumentation code can be written in C or Assembly. Refer to
*SAFER/API* for details about writing instrumentation code.

To apply custom instrumentation:

```bash
cd ${HOME}
./instrument_prog.sh ls
```

To run and test the instrumented program:

```bash
cd ${HOME}/instrumented_libs
./ls
```
