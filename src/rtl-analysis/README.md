# LibAnalysis

LibAnalysis is a sound, scalable, cross-platform static binary analysis framework that enables automated tools. It is designed to be independent from other modules, e.g., disassembler or binary instrumentation tools. It can also be customized for specific static analyses.

## How to build
LibAnalysis is built upon [Lift](https://github.com/nhuhuan/lift), [GNU assembler](https://ftp.gnu.org/gnu/binutils/) and [objdump](https://ftp.gnu.org/gnu/binutils/).

```bash
$ git clone https://github.com/nhuhuan/libanalysis.git
$ export LD_LIBRARY_PATH=/usr/lib/ocaml:<current_path>
$ cd libanalysis
$ make libanalysis
```

## How to use
```bash
$ make test
$ ./test fileList.txt
```