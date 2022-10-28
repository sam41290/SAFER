#ifndef BINARY_H
#define BINARY_H

#include "Cfg.h"
#include "instrument.h"
#include "disasm.h"

using namespace std;

//This class is the entry point of the whole instrumentation program.

/* Represents the target executable to be instrumented.
 * Contains related data members such as code sections, data sections, entry
 * point, CFG, etc.
 */
namespace SBI {
class Binary:public Instrument
{
  string exePath_;
  ExeManager *manager_;
  DisasmEngn *disassembler_;
  vector <section> rxSections_;
  vector <section> roSections_;
  vector <section> rwSections_;
  set <uint64_t> exitCallPlt_;
  set <uint64_t> mayExitPlt_;
  set <uint64_t> allPltSlots_;
  uint64_t codeSegmentStart_ = INT_MAX;
  uint64_t codeSegmentEnd_ = 0;
  uint64_t entryPoint_ = 0;
  uint64_t libcStartMain_ = 0;
  map <uint64_t, Pointer *> pointerMap_;
  map <uint64_t, Function *> funcMap_;
  map <uint64_t, Instruction *> insCache_;
  vector <Reloc> pcrelReloc_;
  vector <Reloc> xtraConstReloc_;
  vector <Reloc> picConstReloc_;
  Cfg *codeCFG_;
  map<uint64_t, vector<uint8_t> > trampData_;
  vector <uint64_t> hookPoints_;
  vector <pair<uint64_t, uint64_t>> hookTgts_;
  //Cfg unknownCFG_;

public:
  DisasmEngn *disassembler() { return disassembler_;}
  Binary(string Binary_path);
  ~Binary();
  void disassemble();
  void rewrite();
  map <uint64_t, Pointer *>&get_pointers();
  string get_Binary_path();
  vector <section> get_ro_data_section();
  void populate_ptr_sym_table();
  //void assignLabeltoFn(string label, string func_name);
  void get_section_asm(string sec_name, string sec_file);
  string printPsblData();
  Cfg *codeCfg() { return codeCFG_; }
private:
  void init();
  void hookPoints();
  uint64_t nextHookPoint(uint64_t addr);
  uint64_t findSecondHookSpace(uint64_t addrs);
  void calcTrampData();
  void populate_functions();
  void populate_pointers();
  void populate_relocation_pointers();
  void map_functions_to_section();
  void populate_ptr_eh_frame();
  void populate_ptr_reloc_ptr();
  void print_function_boundaries();
  void set_codeCFG_params();
  //void set_unknown_cfg_params();
  string print_assembly();
  void print_data_segment(string file_name);
  void print_old_code_and_data(string file_name);
  void rewrite_jmp_tbls(string file_name);
  //void print_gaps(string file_name);
  void print_executable_section(uint64_t section_start, uint64_t section_end,
				 string sec_file);
  void print_ro_section(uint64_t start_offset, uint64_t section_start,
			 uint64_t byte_count, string sec_file);
  void genInstAsm();
  void install_segfault_handler();
  void check_segfault_handler();
  void reduce_eh_metadata();
  void mark_leaf_functions();
  void instrument();
  void printSections();
  void stitchSections(section_types t,string file_name, bool align);
};
}
#endif
