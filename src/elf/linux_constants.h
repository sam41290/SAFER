#pragma once
#include "elf64.h"
#include <string>
using namespace std;

#define binary_class ElfClass



typedef enum class elf_data
{
  PHEADER = 0,
  ELF_HEADER,
  RELOCATED_POINTERS,
  SYMBOL,
  SECTIONS,
  SECTION_HEADER,
  CODE_POINTERS
} bin_data;

typedef enum class elf_section_types
{
  RW = 0,
  RX,
  RONLY,
  RELRO,
  SYM,
  RELA,
  RorX,
  ALL,
  NONLOAD
} section_types;


typedef enum class elf_pheader_types
{
  LOAD = 1,
  DYNAMIC,
  INTERP,
  NOTE,
  SHLIB,
  PHDR,
  TLS,
  ALL
} pheader_types;

typedef enum class elf_pheader_flags
{
  XONLY = 1,
  WONLY,
  WX,
  RONLY,
  RX,
  RW,
  RWX,
  DONTCARE
} pheader_flags;

struct elf_section
{
  string name;
  int hdr_indx = -1;
  Elf64_Shdr *sh;
  uint64_t header_offset;
};
