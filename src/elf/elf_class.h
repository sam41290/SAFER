/*-----------------------------------------------------------*
Author: Soumyakant Priyadarshan
		PhD student, Stony Brook University


*------------------------------------------------------------*/



#ifndef _ELF_PARSER_H
#define _ELF_PARSER_H

#include <iostream>
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include<stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iterator>
#include <vector>
#include <regex>
#include <map>
#include "exe_manager.h"
using namespace std;

/* Deals with linux ELF executables.
 * Parses the ELF headers (program headers and section headers) and other
 * metadata (symbol tables, relocation tables) and passes them to the
 * instrumentation tool.
 *
 * Also responsible for regeneration of ELF metadata after re-assembly.
 */


//TODO: Replace allSections_ with a vector and remove shTable_

class ElfClass:public ExeManager
{
  map <string, off_t> allSyms_;
  map <string, off_t> newSymOfft_; 
  map <string, off_t> newSymAddrs_; 
  map <string, elf_section> allSections_;
  map <string, uint64_t> allJmpSlots_; 
  map <rel, vector<Reloc>>allRelocs_;
  Elf64_Ehdr *elfHeader_; 
  int32_t fd;
  vector <Elf64_Shdr *> shTable_; //Kept to facilitate rewriting. Donot remove
  vector <Elf64_Phdr *> phTable_; 
  const vector <string> exitSyms
    =
    { "abort", "_exit", "exit", "xexit","__stack_chk_fail", "__assert_fail",
    "__fortify_fail", "__chk_fail","err","errx","verr","verrx",
    "g_assertion_message_expr", "longjmp", "__longjmp", "__longjmp_chk", "_Unwind_Resume",
    "_ZSt17__throw_bad_allocv","_ZSt20__throw_length_errorPKc", "__f90_stop", "fancy_abort",
    "ExitProcess","_ZSt20__throw_out_of_rangePKc", "__cxa_rethrow", "__cxa_throw",
    "_ZSt21__throw_runtime_errorPKc", "_ZSt9terminatev", "_gfortran_os_error", "_ZSt24__throw_out_of_range_fmtPKcz",
    "_gfortran_runtime_error", "_gfortran_stop_numeric", "_gfortran_runtime_error_at",
    "_gfortran_stop_string", "_gfortran_abort", "_gfortran_exit_i8",
    "_gfortran_exit_i4", "for_stop_core", "__sys_exit", "_Exit", "ExitThread", "FatalExit", 
    "RaiseException", "RtlRaiseException", "TerminateProcess", "__cxa_throw_bad_array_new_length",
    "_ZSt19__throw_logic_errorPKc","_Z8V8_FatalPKciS0_z","_ZSt16__throw_bad_castv"};
  const vector <string> mayExitSyms_ = {"__fprintf_chk","__printf_chk","error","__vfprintf_chk"};
  const unordered_set <string> metaSections_
    = {".interp",".note.gnu.property",".note.gnu.build-id",
      ".note.ABI-tag",".gnu.hash",".dynstr",".gnu.version",
      ".gnu.version_r",".rela.dyn",".rela.plt",".eh_frame_hdr",
      ".eh_frame",".gcc_except_table"};
  const unordered_set <string> ehSections_ = {".eh_frame_hdr", ".eh_frame",".gcc_except_table"};
  uint64_t oldDataSeg_;
  char *attTbl_ = NULL;
  uint64_t attOffset_;
  uint64_t attSize_;
  uint64_t hashEntryCnt_;
public:

  ElfClass (string name);
  void parse (const char *file_name);
  ElfClass ();
  ~ElfClass ();
  bool is64Bit ();

  uint64_t entryPoint ();
  vector<pheader> prgrmHeader (pheader_types p_type, pheader_flags p_flag);
  section secHeader (string sec_name);
  vector <section> sections (section_types p_type);
  
  vector <elf_section> elfSections (elf_section_types sec_type);
  elf_section elfSectionHdr (string sec_name);
  vector <Elf64_Phdr *>elfPhdr (elf_pheader_types type, elf_pheader_flags flag);
  Elf64_Ehdr elfHeader ();
  vector <Reloc> relocatedPtrs (rel type);
  off_t symbolVal (string func_name);
  vector <Reloc> codePtrs ();
  void rewrite (string asm_file);
  set <uint64_t> exitPlts ();
  set <uint64_t> mayExitPlts();
  uint64_t jmpSlot (string name);
  vector <uint64_t> allSyms ();
  vector <pheader> ptLoadHeaderes ();
  vector <uint64_t> dataSyms ();
  set<uint64_t> allJmpSlots ();
  uint64_t fileOfft(uint64_t ptr);
  uint64_t memAddrs(uint64_t offt);
  uint64_t segAlign();
  exe_type type();
  void printNonLoadSecs(string asm_file);
  void printExeHdr(string fname);
  void printNewSectionHdrs(string fname);
  void printPHdrs(string fname);

  uint64_t exeHdrSz() { return sizeof(Elf64_Ehdr); }
  int newPHdrSz() { return sizeof(Elf64_Phdr) * (phTable_.size() + 3); }
  vector <Elf64_Phdr *> phTable() { return phTable_; }
  void updateWithoutObjCopy(string bname,string obj_file);
  vector <Object> codeObjects();
  vector <Object> dataObjects();
  vector <Object> noTypeObjects();
  bool isMetaData(uint64_t addrs);
  bool isEhSection(uint64_t addrs);
  uint64_t generateHashTbl(string &bin_asm, section &att_sec);
  string hashTblAsm();
private:
  void insertHashTbl (string bname);
  void readElfHeader64 ();
  char *readSection64 (Elf64_Shdr * sh);
  void readSectionHdrTbl64 ();
  void readSymbols64 ();
  void readPHdrTbl64 ();
  void readSymTbl64 (int32_t symbol_table);
  void readRelocs();
  void populateNewSymOffts (string obj_file);
  int pHdrIndx (unsigned int type, int flag);

  vector <elf_section> rwSections ();
  vector <elf_section> symSections ();
  vector <elf_section> relaSections ();
  vector <elf_section> rxSections ();
  vector <elf_section> relroSections ();
  vector <elf_section> ronlySections ();
  vector <elf_section> rorxSections ();

  vector <Reloc> pltGotTramps ();
  vector <Reloc> initArray ();
  vector <Reloc> finiArray ();
  vector <uint64_t> dynSyms ();


  void updAllPHdrs (string bname);
  void updAllPHdrsV2(string bname);
  string xtrctSection (string bname, string section_name);
  void populateNewSymAddrs ();
  void updAllSecHdrs (string bname);
  void insertDataSeg (string bname);
  void updSymTbl (string bname);
  void updRelaSections (string bname);
  void updTramps (string bname);
  void updDynSection (string bname);
  void changeEntryPnt (string bname);
  void readJmpSlots ();
  uint64_t newSymVal (uint64_t old_offset);
  void ptrArray(vector <Reloc> &lst, string secname);
  bool usedAtRunTime(uint64_t addrs);
  void updAllSecHdrsV2(string bname);
  string secIdxToNm(int idx) {
    string shstr = "";
    for(auto & sec : allSections_) {
      if(sec.second.hdr_indx == idx) {
        shstr = sec.second.name;
        break;
      }
    }
    return shstr;
  }

  uint64_t codeSegOffset() {
    auto it = allSections_.find(".mycodesegment");
    if(it == allSections_.end())
      return 0;
    return shTable_[allSections_[".mycodesegment"].hdr_indx]->sh_offset;
  }
};

#define SECTIONS(type, sec_list) \
  for(auto & sec: allSections_) {\
    if(sec.second.sh->sh_type == type) \
      sec_list.push_back(sec.second); \
  }

#define ADDRELOC(ign_neg_add,type,add,offt,symtbl,relinfo) { \
    uint32_t indx = (uint32_t) (relinfo >> 32); \
    uint64_t symval = symtbl[indx].st_value; \
    if(symval > 0) { \
      Reloc r; \
      r.storage = offt; \
      if(ign_neg_add && add <= 0) \
        r.ptr = symval; \
      else \
        r.ptr = symval + add; \
      allRelocs_[type].push_back(r); \
    }\
  }

#define SAME_ACCESS_PERM(p,s) \
  (((p == pheader_flags::RONLY && s == section_types::RONLY) || \
  (p == pheader_flags::RX && s == section_types::RX) || \
  (p == pheader_flags::RW && s == section_types::RW)) ? true : false)

#define SEC_TYPE_TO_PFLAG(s) \
  ((s == section_types::RONLY) ? pheader_flags::RONLY \
  :(s == section_types::RW) ? pheader_flags::RW \
  :(s == section_types::RX) ? pheader_flags::RX \
  : pheader_flags::DONTCARE)

#define PFLAG_TO_SECTYPE(p) \
  ((p == pheader_flags::RONLY) ? section_types::RONLY \
  :(p == pheader_flags::RW) ? section_types::RW \
  :(p == pheader_flags::RX) ? section_types::RX \
  : section_types::RX)

#define SEGEND(p,s) {\
  if((if_exists(s.name,allSections_) && allSections_[s.name].sh->sh_type != SHT_NOBITS) \
      || s.additional == true) \
    p.file_end_sym = s.end_sym; \
  p.mem_end_sym = s.end_sym;}

#define SECTOSEG(p,s) {\
  p.offset = s.offset; \
  p.address = s.vma; \
  p.start_sym = s.start_sym; \
  SEGEND(p,s) \
  p.p_flag = SEC_TYPE_TO_PFLAG(s.sec_type);}

#define PFLAG(p) \
  ((p == pheader_flags::RONLY) ? PF_R : \
  (p == pheader_flags::RX) ? PF_R + PF_X : \
  (p == pheader_flags::RW) ? PF_R + PF_W : \
  (p == pheader_flags::XONLY) ? PF_X : PF_R)

#define REVERSE_PFLAG(p) \
  ((p == PF_R) ? pheader_flags::RONLY \
  :(p == PF_R + PF_X) ? pheader_flags::RX \
  :(p == PF_R + PF_W) ? pheader_flags::RW \
  :(p == PF_X) ? pheader_flags::XONLY \
  : pheader_flags::DONTCARE)

#define NOOBJCOPY 1

#endif



