
#ifndef DATAFLOW_H
#define DATAFLOW_H


#include <stdio.h>
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "Binary.h"
#include "Dfs.h"
#include "lifter.h"
#include "domain.h"
#include "analysishandler.h"

using namespace std;
using namespace SBI;

enum class RegValType {
  UNDEFINED,
  UNKNOWN,
  CONSTANT,
  FRAME_PTR,
  REG_RDI,
  REG_RSI,
  REG_RBP,
  REG_RBX,
  REG_RDX,
  REG_RAX,
  REG_RCX,
  REG_RSP,
  REG_R8,
  REG_R9,
  REG_R10,
  REG_R11,
  REG_R12,
  REG_R13,
  REG_R14,
  REG_R15,
  POINTER,
  VARINT
};

struct RegVal {
  //GPR base = GPR::NONE;
  RegValType val = RegValType::UNDEFINED;
  vector<int64_t> addend ;
};


struct TempState {
  unordered_map<int,RegVal> stackState;
  vector <RegVal> regState;
};

struct Instr {
    uint64_t addr;
    uint32_t size;
    uint32_t id;          // opcode id (e.g., X86_INS_CALL)
    // Decode of operands (regs, mem, imm). If using Capstone, keep cs_insn + cs_x86.
    // ...
};

struct VCallSite {
    uint64_t call_addr;      // address of the indirect call/thunk call
    uint64_t vptr_load_addr; // address of the vptr load (if found)
    int      vptr_offset;    // [this + vptr_offset]  (0 for primary)
    int      slot_bytes;     // mem.disp at [vptr + slot_bytes]
    int      slot_index;     // slot_bytes / 8
    unsigned this_reg;       // expected ABI reg at call (RDI SysV / RCX Win64)
    unsigned vptr_reg;       // reg used as base for [vptr + slot]
    unsigned recv_reg;       // the register carrying 'this' when vptr was loaded
};


struct ParsedOperand {
    enum class Kind { Register, Memory, Invalid } kind = Kind::Invalid;

    // For Kind::Register
    std::string reg;          // e.g. "rax"

    // For Kind::Memory
    std::optional<std::string> base;   // e.g. "rax", "rip"
    std::optional<std::string> index;  // e.g. "rbx"
    int scale = 1;                      // 1,2,4,8 (default 1 if omitted)
    std::optional<int64_t> disp;        // numeric displacement if present and numeric
    std::optional<std::string> symbol;  // symbolic displacement (e.g. "foo", "foo@GOTPCREL")
    bool rip_relative = false;          // true if base == rip
    bool has_indirection = false;       // true if operand had leading '*'
};

//class CFPattern {
//  RegVal base;
//  int stride = 0;
//  RegVal ind;
//public:
//  void base(RegVal b) { base = b; }
//  RegVal base() { return b; }
//  void stride(int s) { stride = s; }
//  int stride() { return stride; }
//  void ind(RegVal i) { ind = i; }
//  RegVal ind() { return ind; }
//};

struct PtrTable {
    enum class Kind { DataTab, CodeTab, Invalid } kind = Kind::Invalid;
    uint64_t location = 0;
    int stride = 0;
};

struct IndCFInfo {
    vector<PtrTable> table;
    enum class Kind { Register, Memory, Invalid } kind = Kind::Invalid;
    RegVal rval;
};

struct CallSite {
    uint64_t location;
    BasicBlock *fall = NULL;
    TempState state;
    unordered_set <uint64_t> target;
    string pltTarget = "";
    bool isIndirect = false;
    bool jtable = false;
    bool resolved = true;
    bool expectsRetVal_ = false;
    IndCFInfo *ind = NULL;
};

struct FuncInfo {
    vector <CallSite *> callSiteInfo_;	    
    unordered_set <uint64_t> memWrites_;
    unordered_set <uint64_t> loadsAddress_;
    unordered_set <uint64_t> readsAddress_;
    unordered_set <uint64_t> escapedAddress_;
    unordered_set <uint64_t> psblVtable_;
    unordered_map<string, string> argsUse_;
    bool ret_ = true;
};


class DataFlow {
  BasicBlock *entry_;
  Cfg *cfg_;
  vector <BasicBlock *> bbList_;
  AnalysisHandler *baseLHHandler_ = NULL;
  SBAFunction * baseLHFunc_ = NULL;
  unordered_map <uint64_t, int> executionCtr_;
  bool bad_ = false;
  FuncInfo *info_ = NULL;
  unordered_map<int,unordered_map<string, string>> usedArgsStats_;
  //bool usedArgsStatsDone_ = false;

public:
  DataFlow(BasicBlock *entry, Cfg *cfg) {
    entry_ = entry;
    cfg_ = cfg;
  }

  bool deeperDetails_ = true;

  vector <RegVal> getRegValAtBackward(GPR reg,uint64_t ins_addresses);
  vector <uint64_t> getRegValAt(string reg, uint64_t ins_address);
  vector<uint64_t> getInstructionLocations(string mne);
  vector <BasicBlock *> getAllBBs();

  uint64_t entryAddress() { return entry_->start(); }
  vector<uint64_t> getCallSites(uint64_t callee_addrs);
  FuncInfo *getFuncInfo();

  void baseLHHandler(AnalysisHandler * h);// {
  //  baseLHHandler_ = h;
  //  baseLHFunc_ = analyze_function(h, entry_->start());
  //}
  unordered_map<string, string> usedArgs(int call_depth);
  bool bad() { return bad_; }
  void bad(bool b) { bad_ = b; }
  Cfg *cfg() { return cfg_; }

  unordered_map <string, string> usedArgsDfs(BasicBlock *bb, unordered_set <uint64_t> &checked, int call_depth);
  void clear() {
    if(baseLHHandler_ != NULL) {
      delete baseLHHandler_;
      baseLHHandler_ = NULL;
      baseLHFunc_ = NULL;
    }
  }
  void collectInfo();
  void collectBasicInfo();
  void getBaseLHHandler();
  FuncInfo *info() { return info_; }
private:
  vector<RegVal> getRegValRecurse(GPR reg, BasicBlock *bb, uint64_t ins_addrs);
  TempState propagateConst(vector <Instruction *> &ins_list, TempState &state);
  RegVal updateState(RegVal &tgt, TempState &state, Operation &op,
		                        Instruction *ins, bool loop_update);
  

  BaseLH *getBaseLHValAt(string reg, uint64_t ins_address);
  unordered_map<uint64_t, unordered_map<string, BaseLH *>> getBaseLHValAt(unordered_map<uint64_t, vector <string>> &track_map);
  bool isFunctionEntry(uint64_t entry);
  void getCallArgsState(CallSite *cs);
  void getCallArgState(vector<CallSite *> &cs_list);
  void updateCallSiteRegState(CallSite *cs, string &reg, BaseLH *val);
  IndCFInfo *indirectCFExpr(uint64_t addrs);
  void usedArgsInBB(BasicBlock *bb, unordered_map<string, string> &reg_status_map);
  bool returnType();
  string raxUseInBB(BasicBlock *bb, unordered_set<uint64_t> & checked);
  void callSiteRetType(FuncInfo *info);
  unordered_set<string> memAccessInBB(BasicBlock *bb, unordered_set<string> &source_regs);
  void assignType(unordered_map <string, string> &reg_map);
  string escapesInThisIns(Instruction *ins, string & reg, unordered_set <uint64_t> known_usage_points); 
  string escapesInThisBB(BasicBlock *bb, string reg, unordered_set <uint64_t> known_usage_points);
  bool escapeAnalysisDFS(BasicBlock *bb, string reg, unordered_set <uint64_t> &checked, unordered_set<uint64_t> known_usage_points);
  bool escapes(string reg, uint64_t start_loc, unordered_set<uint64_t> known_usage_points);
  void addEscapedAddrs(FuncInfo *info, Instruction *ins, uint64_t addrs);
  void collectCallsiteInfo(FuncInfo *info);
  void collectATInfo(FuncInfo *info);
  unordered_set <uint64_t> knownCodePtrUsagePoints(FuncInfo *info, uint64_t used_addrs);
  void vtableAccess(FuncInfo *info);
};

class LiftedProg {
  static Cfg *cfg_;
  unordered_set <int> entryList_;
  static unordered_map <uint64_t, DataFlow *> liftedFuncs_;
  vector<tuple<IMM,RTL*,vector<uint8_t>>> progRtl_;
  static unordered_map<uint64_t,tuple<RTL*,vector<uint8_t>>> progRtlMap_;
public:
  static bool deeperDetails_;
  LiftedProg(Cfg *cfg, unordered_set <int> entry_list);
  static DataFlow * getLiftedFn(uint64_t addr) {
    if(liftedFuncs_.find(addr) != liftedFuncs_.end() && 
       liftedFuncs_[addr]->bad() == false) { 
      auto df = liftedFuncs_[addr];
      df->deeperDetails_ = deeperDetails_;
      return df;
    }
    cout<<"[getLiftedFn] Function not part of the program: "<<hex<<addr<<endl;
    return NULL;
  }

  static vector<string> regsReadByIns(uint64_t ins_addr);
  static vector<string> regsWrittenByIns(uint64_t ins_addr);
  static unordered_set <string> regsUsedInDeref(uint64_t ins_addr);
  static RTL *getRtl(uint64_t ins_addr);
  static string memWriteExpr(uint64_t ins_addr);
  static string sourceReg(uint64_t ins_addr);
  static string taintedSourceReg(uint64_t addr);
  static AnalysisHandler *liftFn(uint64_t addrs);
};

#endif
