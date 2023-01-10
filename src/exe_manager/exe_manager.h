#pragma once
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
#include "encode.h"
#include "config.h"
#ifndef _WIN32
#include "linux_constants.h"
#else
//include windows constants file
#endif
#include "manager_constants.h"

/* This class deals with the executable format (ELF or Windows PE)
 *
 * This class is created to serve as an abstraction between the instrumentation
 * tool and the target executable format.
 * This class shall be inheritted by the class representing the executable
 * format. For example, class elf_class inherits this class and implements all
 * the pure virtual functions.
 * Class for Windows PE format, when implemented will also inherit this class.
 *
 * A pointer to class ExeManager is present in binary class and is type casted
 * at runtime (to class elf_class).
 *
 */

using namespace std;

struct Reloc {
  uint64_t storage;
  uint64_t ptr;
};

class ExeManager : public virtual ENCCLASS
{
  string origBname_;
  string bname_;
  string instBname_;
  exe_format fmt_;
  exe_type type_;

  //set of all code pointers that shall be encoded in the instrumented binary.
  unordered_set < uint64_t > encode_;
  vector <section> newSections_;
  vector <pheader> newPHdrs_;
  void *attTbl_;
  uint64_t attTblSz_; 
public:
  ExeManager() {}
  ExeManager (string p_filename, exe_format fmt);

  static bool is_ELF64 ();
  string binaryName () { return bname_; }
  void ptrsToEncode (uint64_t ptr) { encode_.insert (ptr); }
  bool encoded(uint64_t addrs) {
    if(ENCODE == 1 && encode_.find(addrs) != encode_.end())
      return true;
    return false;
  }
  uint64_t encode (uint64_t ptr, uint64_t orig_ptr);
  string origBname() { return origBname_; }
  void bname(string nm) { bname_ = nm; }
  void instBname(string nm) { instBname_ = nm; }
  string instBname() { return instBname_; }

  pair <uint64_t, uint64_t> progMemRange();

  vector <section> newSections() { return newSections_; }
  void newSection(section sec) { newSections_.push_back(sec); }
  vector <pheader> newPheaders() { return newPHdrs_; }
  void newPheader(pheader p) { newPHdrs_.push_back(p); }
  virtual uint64_t entryPoint () = 0;
  virtual vector<pheader> prgrmHeader (pheader_types p_type, pheader_flags p_flag) = 0;
  virtual section secHeader (string sec_name) = 0;
  virtual vector < section > sections (section_types p_type) = 0;
  virtual off_t symbolVal (string sym) = 0;
  virtual vector <Reloc> relocatedPtrs (rel type) = 0;
  virtual vector <Reloc> codePtrs () = 0;
  virtual void rewrite (string asm_file) = 0;
  virtual set < uint64_t > exitPlts () = 0;
  virtual uint64_t jmpSlot (string name) = 0;
  virtual set < uint64_t > mayExitPlts () = 0;
  virtual vector < uint64_t > allSyms () = 0;
  virtual vector < uint64_t > dataSyms () = 0;
  virtual vector < pheader > ptLoadHeaderes () = 0;
  virtual set<uint64_t> allJmpSlots () = 0;
  virtual uint64_t fileOfft(uint64_t ptr) = 0;
  virtual uint64_t memAddrs(uint64_t offt) = 0;
  virtual exe_type type() = 0;
  virtual uint64_t newSymVal (uint64_t old_offset) = 0;
  virtual uint64_t segAlign () = 0;
  virtual void printExeHdr(string fname) = 0;
  virtual void printPHdrs(string fname) = 0;
  virtual void printNonLoadSecs(string fname) = 0;
  virtual void printNewSectionHdrs(string fname) = 0;
  
  virtual int newPHdrSz() = 0;
  virtual uint64_t exeHdrSz() = 0;
  virtual vector <Object> codeObjects() = 0;
  virtual vector <Object> dataObjects() = 0;
  virtual vector <Object> noTypeObjects() = 0;
  virtual bool isMetaData(uint64_t addrs) = 0;
  virtual bool isEhSection(uint64_t addrs) = 0;
  virtual uint64_t generateHashTbl(string &bin_asm, section &att_sec) = 0;
  void placeHooks(map <uint64_t, vector <uint8_t>> &hooks);
  vector <string> additionSecs();
  //virtual void extraRelocs() = 0;
};
