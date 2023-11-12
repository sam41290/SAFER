#pragma once
#include <string>
#include <vector>
using namespace std;

/*
 * These struct definitions are available to the instrumentation tool.
 * The instrumentation tool shall use these structures whenever it requests for
 * any executable format related data (such as section details or program
 * headers).
 */

enum class exe_format
{
  ELF,
  PE
};

enum class exe_type {
  PIE,
  NOPIE
};

enum class rel {
  CONSTPTR_PIC,
  PCREL,
  CFTARGET,
  CONSTPTR_NOPIC
};

struct section
{
  string name = "";
  section_types sec_type;
  bool load = true;
  bool is_metadata = false;
  bool printed = false;
  bool is_att = false;
  uint64_t offset = 0;
  uint64_t size = 0;
  uint64_t vma = 0;
  uint64_t align;
  string start_sym = "";
  string end_sym = "";
  bool additional = false;
  string asm_file = "";
  string header_asm = "";
  section (string nm,uint64_t offt, uint64_t sz, uint64_t addr, uint64_t
      aln) {
    name = nm;
    offset = offt;
    size = sz;
    vma = addr;
    align = aln;
  }
};

struct pheader
{
  uint64_t offset = 0;
  uint64_t address = 0;
  uint64_t file_sz = 0;
  uint64_t mem_sz = 0;
  string start_sym = "";
  string mem_end_sym = "";
  string file_end_sym = "";
  pheader_flags p_flag = pheader_flags::DONTCARE;
  pheader() {};
  pheader(uint64_t offt, uint64_t addr, uint64_t fsz, uint64_t msz) {
    offset = offt;
    address = addr;
    file_sz = fsz;
    mem_sz = msz;
  }
};

enum class ObJType {
  CODE,
  DATA,
  UNKNOWN
};

struct Object
{
  string name;
  uint64_t addr;
  uint64_t size;
  ObJType type;
};
