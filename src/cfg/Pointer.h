/**
 * @file Pointer.h
 * @brief 
 * @author Soumyakant Priyadarshan <spriyadarsha@cs.stonybrook.edu>
 * @version 1
 * @date 2021-05-24
 */
#ifndef POINTER_H
#define POINTER_H

#include <stdint.h>
#include <vector>
#include <stdarg.h>
#include "libutils.h"

using namespace std;

namespace SBI {
enum class SymbolType
{
  CONSTANT,
  OPERAND,
  RLTV,
  JMP_TBL_TGT,
  LINEAR_SCAN
};

enum class SymbolizeIf {
  SYMLOCMATCH,
  ALIGNEDCONST,
  IMMOPERAND,
  IMMOP_LOC_MATCH,
  CONST,
  JMP_TBL_TGT,
  RLTV,
  LINEAR_SCAN
};

/**
 * @brief A single Pointer value can be part of multiple symbol candidates.
 */

class Symbol {
  uint64_t location_; //For RLTV and OPERAND, this will be instruction address
  SymbolType type_;
  bool symbolize_ = false;
  int size_ = 0;
public:

  Symbol(uint64_t loc, SymbolType t) {
    location_ = loc;
    type_ = t;
  }

  bool symbolize() { return symbolize_; }
  uint64_t location() { return location_; }
  SymbolType type() { return type_; }
  bool symbolizable(SymbolizeIf cnd, uint64_t loc) {
    switch (cnd) {
      case SymbolizeIf::LINEAR_SCAN :
        if(type_ == SymbolType::LINEAR_SCAN)
          return true;
        break;
      case SymbolizeIf::JMP_TBL_TGT :
        if(type_ == SymbolType::JMP_TBL_TGT)
          return true;
        break;
      case SymbolizeIf::SYMLOCMATCH :
        if(loc == location_)
          return true;
        break;
      case SymbolizeIf::ALIGNEDCONST :
        if(type_ == SymbolType::CONSTANT && (location_ % 8 == 0))
          return true;
        break;
      case SymbolizeIf::IMMOPERAND :
        if(type_ == SymbolType::OPERAND)
          return true;
        break;
      case SymbolizeIf::CONST :
        if(type_ == SymbolType::CONSTANT) {
          //LOG("Constant at: "<<hex<<location_);
          return true;
        }
      case SymbolizeIf::RLTV :
        if(type_ == SymbolType::RLTV)
          return true;
        break;
      case SymbolizeIf::IMMOP_LOC_MATCH:
        if(type_ == SymbolType::OPERAND && (loc == location_))
          return true;
        break;
      default:
        return false;
    }
    return false;
  }
  void symbolize(SymbolizeIf cnd, uint64_t loc) {
    if(symbolizable(cnd,loc)) {
      LOG("Symbolizing : "<<hex<<location_);
      symbolize_ = true;
    }
  }
  bool symbolized(SymbolizeIf cnd, uint64_t loc) {
    if(symbolizable(cnd,loc)) {
      return symbolize_;
    }
    return false;
  }
  void symbolize(bool yes) { symbolize_ = yes; }
  void dump(ofstream & ofile) {
    ofile<<"symcandidate "<<dec<<location_;
    ofile<<" "<<dec<<(int)type_;
    ofile<<" "<<dec<<(int)symbolize_<<endl;
  }
  int size() { return size_; }
  void size(int s) { size_ = s; }
};

enum class PointerType
{
  // tells whether a Pointer is code Pointer, data Pointer or unknown.
  CP = 0,
  DP,
  UNKNOWN,
  DEF_PTR
};

enum class PointerSource
{
  //Tells from where the Pointer is obtained.
  //DONOT change the sequence. 
  //The sources are arranged in the increasing order of their likelyhood of
  //being pointer.
  NONE,
  CALL_TGT_2,
  CALL_TGT_1,
  VALIDITY_WINDOW,
  PHANTOM,
  RANDOMADDRS,
  GAP_PTR,
  GAP_HINT,
  EH,
  DEBUGINFO,
  SYMTABLE,
  STOREDCONST,
  JUMPTABLE,
  POSSIBLE_RA,
  EXTRA_RELOC_PCREL,
  EXTRA_RELOC_CONST,
  CONSTOP,
  CONSTMEM,
  RIP_RLTV,
  PIC_RELOC,
  EHFIRST,
  KNOWN_CODE_PTR
};

/*
 * class Pointer represents a definite Pointer.
 */

class Pointer
{
  PointerType type_;
  uint64_t address_;
  PointerSource source_;
  PointerSource rootSrc_ = PointerSource::NONE;
  bool encodable_ = true;
  uint64_t loadPoint_ = 0;
  vector <Symbol> symCandidates_;
  //bool jmpTblBase_ = false;
  //bool jmpTblLoc_ = false;
  //vector <pair<uint64_t,SymbolType>> symbolize_;
public:
  Pointer(uint64_t ptr, PointerType ptr_type, PointerSource p_source) {
    address_ = ptr;
    type_ = ptr_type;
    source_ = p_source;
  }
  //bool jmpTblLoc() { return jmpTblLoc_; }
  //void jmpTblLoc(bool val) { jmpTblLoc_ = val; }
  //bool jmpTblBase() { return jmpTblBase_; }
  //void jmpTblBase(bool val) { jmpTblBase_ = val; }
  void rootSrc(PointerSource src) { rootSrc_ = src; }
  PointerSource rootSrc() { return rootSrc_; }
  uint64_t address() { return address_; }
  PointerType type() { return type_; }
  PointerSource source() { return source_; }
  void loadPoint(uint64_t pt) { loadPoint_ = pt; }
  uint64_t loadPoint() { return loadPoint_; }
  void type(PointerType type) { type_ = type; }
  void address(uint64_t address) { address_ = address; }
  void source(PointerSource src) { source_ = src; }
  void encodable(bool enc) { encodable_ = enc; }
  bool encodable() { return encodable_; }
  bool symExists(uint64_t loc) {
    for(auto & sym : symCandidates_) {
      if(sym.location() == loc)
        return true;
    }
    return false;
  }
  void symCandidate(Symbol s) {
    //LOG("Adding symbol candidate: "<<hex<<address_<<" storage: "<<hex<<s.location());
    symCandidates_.push_back(s); 
  }
  vector <Symbol> symCandidate() { return symCandidates_; }
  bool symbolized(SymbolizeIf cnd, ...) {
    va_list args;
    va_start(args,cnd);
    uint64_t loc = 0;
    if(cnd == SymbolizeIf::SYMLOCMATCH ||
       cnd == SymbolizeIf::IMMOP_LOC_MATCH)
      loc = va_arg(args,uint64_t);
    for(auto & sym : symCandidates_) {
      if(sym.symbolized(cnd,loc))
        return true;
    }
    va_end(args);
    return false;
  }
  void symbolize(SymbolizeIf cnd, ...) {
    va_list args;
    va_start(args,cnd);
    uint64_t loc = 0;
    if(cnd == SymbolizeIf::SYMLOCMATCH ||
       cnd == SymbolizeIf::IMMOP_LOC_MATCH)
      loc = va_arg(args,uint64_t);
    for(auto & sym : symCandidates_) {
      if(sym.location() == 0 || sym.location() == 100)
        continue;
      sym.symbolize(cnd,loc);
    }
    va_end(args);
  }
  bool symbolizable(SymbolizeIf cnd, ...) {
    va_list args;
    va_start(args,cnd);
    uint64_t loc = 0;
    if(cnd == SymbolizeIf::SYMLOCMATCH ||
       cnd == SymbolizeIf::IMMOP_LOC_MATCH)
      loc = va_arg(args,uint64_t);
    for(auto & sym : symCandidates_) {
      if(sym.location() == 0 || sym.location() == 100)
        continue;
      if(sym.symbolizable(cnd,loc))
        return true;
    }
    va_end(args);
    return false;
  }
  vector<uint64_t> storages(SymbolType t) {
    vector <uint64_t> loc_list;
    for(auto & sym : symCandidates_) {
      if(sym.location() == 100 || sym.location() == 0)
        continue;
      if(sym.type() == t) {
        //LOG("location: "<<hex<<sym.location());
        loc_list.push_back(sym.location());
      }
    }
    return loc_list;
  }
  void size(int s, uint64_t loc) {
    for(auto & sym : symCandidates_) {
      if(sym.location() == loc)
        sym.size(s);
    }
  }
  vector<uint64_t> storages(int s) {
    vector <uint64_t> loc_list;
    for(auto & sym : symCandidates_) {
      if(sym.location() == 100 || sym.location() == 0)
        continue;
      if(sym.size() == s) {
        //LOG("location: "<<hex<<sym.location());
        loc_list.push_back(sym.location());
      }
    }
    return loc_list;
  }
  void dump(ofstream &ofile) {
    ofile<<"pointer "<<dec<<address_;
    ofile<<" "<<dec<<(int)source_;
    ofile<<" "<<dec<<(int)rootSrc_;
    ofile<<" "<<dec<<(int)type_<<endl;
    for(auto & sym : symCandidates_)
      sym.dump(ofile);
  }
};
}
#endif
