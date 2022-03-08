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


#define RESOLVE(t,b1,b2) \
  ((t == ResolutionType::SPATIAL) ? spatialResolver(b1,b2) :\
  symbolizabilityResolver(b1,b2))

namespace SBI {

enum class ResolutionType {
  SPATIAL,
  SYMBOLIZABILITY,
  NONE
};


class PointerAnalysis : public virtual SaInput, public virtual CFValidity,
  public virtual CfgElems, public JmpTblAnalysis
{
  vector <Reloc> allConstRelocs_;
  unordered_set <uint64_t> conflictingBBs_;
  vector <Property> propList_;
  unordered_set <uint64_t> possibleRAs_;
public:
  PointerAnalysis (uint64_t memstrt, uint64_t memend);
  void cfgConsistencyAnalysis();
  void symbolize();
  void allConstRelocs(vector <Reloc> & r) { allConstRelocs_ = r; }
  virtual bool addToCfg(uint64_t addrs, PointerSource src) = 0;
  virtual void addToDisasmRoots (uint64_t address) = 0;
  virtual void rootSrc(PointerSource root) = 0;
private:
  void resolveConflict(ResolutionType t);
  vector <pair<uint64_t,uint64_t>> getConflicts(uint64_t fn_Start,Function *fn);
  void spatialResolver(BasicBlock *b1, BasicBlock *b2);
  bool hasSymbolizableRoot(BasicBlock *b);
  void symbolizeIfValidAccess(Pointer *ptr);
  void symbolizabilityResolver(BasicBlock *b1, BasicBlock *b2);

  double CFTransferDensity(vector <BasicBlock *> &bbList);
  bool callsDefCode(vector <BasicBlock *> &bbList);
  void classifyPsblFn(Function *fn);
  void jmpTblConsistency();
  bool CFDensityChk(vector <BasicBlock *> &bbList);
  bool validInit(uint64_t entry, vector <BasicBlock *> &fin_bb_lis);
  bool regPreserved(uint64_t entry,
    vector <BasicBlock *> &fin_bb_list,const vector <string> &reg_list);
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
  bool jmpTblTgt(Pointer *ptr);
  bool notString(Pointer *ptr);
  void symbolizeNonString(Pointer *ptr);
  void symbolizeIfSymbolArray(Pointer *ptr);
  void callTgtsAsDefCode(vector <BasicBlock *> &bb_list);
  void symbolizeConst(Pointer *ptr);
  void cfConsistency(map <uint64_t, Function *> &funMap);
  void resolveConflict(uint64_t p1, uint64_t p2);
  bool resolvePossiblyExits(BasicBlock *entry_bb, BasicBlock *bb);
  void classifyCode();
  //void resolveAllPossibleExits();
  void resolveAndClassify(ResolutionType t);
  void filterJmpTblTgts(Function *fn);
  bool conflictingSeqs(vector <BasicBlock *> &seq1,
                       vector <BasicBlock *> &seq2);
  void checkIndTgts(unordered_map<int64_t, vector<int64_t>> & ind_tgts,
                    vector <BasicBlock *> & fin_bb_list);
  void classifyEntry(uint64_t entry);
  bool codeByProperty(BasicBlock *bb);
  bool dataByProperty(BasicBlock *bb);
  void propertyCheck(BasicBlock *entry_bb, vector<BasicBlock *> &bb_list);
  void resolveAllNoRetCalls();
  void resolveNoRetCall(BasicBlock *entry);
  void classifyPossibleRAs();
  void validateIndTgts(vector <BasicBlock *> &entry_lst, BasicBlock *entry_bb, BasicBlock *ind_bb);
};
}
#endif
