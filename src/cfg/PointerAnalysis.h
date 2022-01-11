#ifndef POINTERANALYSIS_H
#define POINTERANALYSIS_H

#include "JumpTable.h"
#include "BasicBlock.h"
#include "config.h"
#include "Instruction.h"
#include "Pointer.h"
#include "Function.h"
#include "libutils.h"
#include "libanalysis.h"
#include "CFValidity.h"
#include "Dfs.h"
#include "SaInput.h"
#include "CfgElems.h"
#include "JmpTblAnalysis.h"

/*
 * Reponsible for identifying jump tables.
 * Generates assembly files for paths in a CFG that may have jump table
 * computation.
 * A path that starts with an "LEA" instruction and ends with an indirect jump
 * is considered as a potential candidate for jump table calculation.
 * Assembly files for such paths within every function is generated and provided
 * as an input to static analysis.
 * Static analysis code (Huan's code) - present in ../../jmp_table_analysis. 
 */

#define OVERLAP(bb,fns) \
  auto fn = is_within(bb->start(),fns);\
  if(fn->second->checkOverlap(bb)) { \
    LOG("overlapping bb: "<<hex<<bb->start()); \
    return false;\
  }

namespace SBI {

struct BBSeq {
  vector <BasicBlock *> bbList_;
  vector <vector<BasicBlock *>> psblRtrnBBs_;
};

class PointerAnalysis : public virtual SaInput, public virtual CFValidity,
  public virtual CfgElems, public JmpTblAnalysis
{
  vector <Reloc> allConstRelocs_;
public:
  PointerAnalysis (uint64_t memstrt, uint64_t memend);
  void cfgConsistencyAnalysis();
  //void spAnalysis();
  void symbolize();
  void allConstRelocs(vector <Reloc> & r) { allConstRelocs_ = r; }
  virtual bool addToCfg(uint64_t addrs, PointerSource src) = 0;
  virtual void addToDisasmRoots (uint64_t address) = 0;
  virtual void rootSrc(PointerSource root) = 0;
private:
  void symbolizeIfValidAccess(Pointer *ptr);
  

  double CFTransferDensity(vector <BasicBlock *> &bbList);
  bool callsDefCode(vector <BasicBlock *> &bbList);
  //bool validateCFtransfers(BasicBlock *bb);
  void classifyPsblFn(Function *fn);
  void jmpTblConsistency();
  //bool invalidIns(vector<BasicBlock *> &bbList);
  bool CFDensityChk(vector <BasicBlock *> &bbList);
  //bool overlapCheck(vector <BasicBlock *> &bbList);
  bool validInit(uint64_t entry, vector <BasicBlock *> fin_bb_lis);
  bool regPreserved(uint64_t entry,
    vector <BasicBlock *> fin_bb_list,const vector <string> &reg_list);
  //void callTgtsAsDefCode(vector <BasicBlock *> &bbList);
  bool aligned(Pointer *ptr);
  bool immOperand(Pointer *ptr);
  bool relocatedConst(Pointer *ptr);
  bool relocatedImm(Pointer *ptr);
  uint64_t insWithOperand(uint64_t constop,uint64_t storage);
  bool isSymbolizable(uint64_t addrs);

  void symbolizeRelocatedImm(Pointer *ptr);
  void symbolizeImmOp(Pointer *ptr);
  void symbolizeRelocatedConst(Pointer *ptr);
  void symbolizeAlignedConst(Pointer *ptr);
  void symbolizeRltvPtr(Pointer *ptr);
  bool rltvPtr(Pointer *ptr);
  bool notString(Pointer *ptr);
  void symbolizeNonString(Pointer *ptr);
  void symbolizeIfSymbolArray(Pointer *ptr);
  void callTgtsAsDefCode(vector <BasicBlock *> &bb_list);
  void symbolizeConst(Pointer *ptr);
  CFStatus callsValidFns(BasicBlock *bb);
  CFStatus reachableFromValidRoot(BasicBlock *bb);
  void cfConsistency(map <uint64_t, Function *> &funMap);
  void spatialIntegrity();
  void resolveConflict(uint64_t p1, uint64_t p2);
  vector <pair<uint64_t,uint64_t>> conflicts(Function *fn1, Function *fn2);
  void resolvePossiblyExits(BasicBlock *bb);
  void classifyCode();
  void resolveAllPossibleExits();
  //vector<vector<BasicBlock *>> bbSeq(BasicBlock *bb);
};
}
#endif
