#ifndef POINTERANALYSIS_H
#define POINTERANALYSIS_H

#include "JumpTable.h"
#include "BasicBlock.h"
#include "config.h"
#include "Instruction.h"
#include "Pointer.h"
#include "Function.h"
#include "libutils.h"
//#include "libanalysis.h"
#include "../src/SBD/includes/libanalysis.h"
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

#define PRIORITIZED_REJECT true

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

enum class CandidateType {
  DEF_FN_ENTRY,
  PSBL_FN_ENTRY,
  PSBL_PTRS,
  ADDITIONAL_PSBL_PTRS,
  JMP_TBL_TGTS
};

struct AnalysisCandidate {
  uint64_t address_;
  long double score_;
  AnalysisCandidate(uint64_t addr, long double sc) {
    address_ = addr;
    score_ = sc;
  }
};

struct CompareCandidate {
  bool operator()(AnalysisCandidate &c1, AnalysisCandidate &c2) {
    if(c1.score_ == c2.score_)
      return c2.address_ < c1.address_;
    return c1.score_ < c2.score_;
  }
};


class PointerAnalysis : public virtual SaInput, public virtual CFValidity,
  public virtual CfgElems, public JmpTblAnalysis
{
  vector <Reloc> allConstRelocs_;
  vector <Property> propList_;
  unordered_set <uint64_t> postQAnalysis_;
  unordered_set <uint64_t> possiblePtrs_;
  unordered_set <uint64_t> additionalPtrs_;
  unordered_set <uint64_t> Conflicts_;
  unordered_set <uint64_t> passed_;
  unordered_set <uint64_t> checked_;
  unordered_set <uint64_t> validInsAndCF_;
  unordered_set <uint64_t> FNCorrectionDone_;
  unordered_map <uint64_t, unordered_set<uint64_t>> IndTgtValidationMap_;
  priority_queue<AnalysisCandidate, vector<AnalysisCandidate>, CompareCandidate> analysisQ_;
  const vector<string> ABIReg = {"sp","bx","bp","r12","r13","r14","r15"};
public:
  PointerAnalysis (uint64_t memstrt, uint64_t memend, string exepath);
  void cfgConsistencyAnalysis();
  void symbolize();
  void allConstRelocs(vector <Reloc> & r) { allConstRelocs_ = r; }
  int tgtCount(vector <BasicBlock *> &bb_list);
  bool conflictingSeqs(vector <BasicBlock *> &seq1,
                       vector <BasicBlock *> &seq2);
  void checkIndTgts(unordered_map<int64_t, vector<int64_t>> & ind_tgts,
                    vector <BasicBlock *> & fin_bb_list,
                    const unordered_set <uint64_t> &present);
  virtual bool addToCfg(uint64_t addrs, PointerSource src) = 0;
  virtual void addToDisasmRoots (uint64_t address) = 0;
  virtual void rootSrc(PointerSource root) = 0;
  static bool codeByProperty(BasicBlock *bb);
  static bool dataByProperty(BasicBlock *bb);
private:
  void symbolizeIfValidAccess(Pointer *ptr);
  bool sameFunctionBody(uint64_t addr1, uint64_t addr2);
  double CFTransferDensity(vector <BasicBlock *> &bbList);
  bool callsDefCode(vector <BasicBlock *> &bbList);
  void classifyPsblFn(Function *fn);
  void jmpTblConsistency();
  bool CFDensityChk(vector <BasicBlock *> &bbList);
  unordered_map <uint64_t,int> validInit(vector <BasicBlock *> &entry_lst,
                                         vector <BasicBlock *> &fin_bb_list,
                                         const unordered_set <uint64_t> &valid_ind_path);
  //int validInit(uint64_t entry, vector <BasicBlock *> &fin_bb_lis);
  unordered_map <uint64_t,int> regPreserved(vector <BasicBlock *> &entry_lst,
                                            vector <BasicBlock *> &fin_bb_list,
                                            const vector <string> &reg_list,
                                            const unordered_set <uint64_t> &valid_ind_path);
  //int regPreserved(uint64_t entry,
  //  vector <BasicBlock *> &fin_bb_list,const vector <string> &reg_list);
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
  void classifyCode();
  void classify();
  void filterJmpTblTgts(Function *fn);
  void classifyEntry(uint64_t entry);
  unordered_map <uint64_t, int> propertyCheck(vector <BasicBlock *> &entry_bb, 
                                              vector<BasicBlock *> &bb_list,
                                              const unordered_set <uint64_t> &valid_ind_path = unordered_set <uint64_t>());
  void resolveAllNoRetCalls();
  void resolveNoRetCall(BasicBlock *entry);
  void classifyPossiblePtrs();
  void validateIndTgts(unordered_set <BasicBlock *> &pre_lst,
                                 BasicBlock *ind_tgt, BasicBlock *entry);
  void validateIndTgtsFrmEntry(BasicBlock *entry);
  void analyzeEntry(BasicBlock *entry, bool force = false);
  void analyzeEntries(vector <BasicBlock *> &entry, bool force = false);
  bool hasPossibleCode(vector <BasicBlock *> &bb_list);
  bool indTgtConsistency(BasicBlock *entry);
  bool contextPassed(BasicBlock *entry, BasicBlock *bb);
  bool hasUnresolvedIndTgts(BasicBlock *entry);
  unordered_map <uint64_t,int> validInitAndRegPreserve(vector <BasicBlock *> &entry_lst,
                                                       vector <BasicBlock *> &fin_bb_list,
                                                       const vector <string> &reg_list,
                                                       const unordered_set <uint64_t> &valid_ind_path);
  //int validInitAndRegPreserve(uint64_t entry,
  //  vector <BasicBlock *> &fin_bb_list,
  //  const vector <string> &reg_list);
  void removeEHConflicts();
  void removeConflicts();
  //void disassembleGaps();
  void propagateDefCodeProperty();
  void createAnalysisQ(CandidateType t);
  void analyzeCandidates();
  bool entryPointCorrection(BasicBlock *ptr_bb);
  bool callTargetIntegrity(BasicBlock *entry, unordered_set <uint64_t> &checked);
  bool avoidValidBehaviourCheck(BasicBlock *bb);
  void FNCorrection();
  void FNEntryCorrection(BasicBlock *ptr_bb);
  BasicBlock *checkSignature(BasicBlock *bb);
  void markConflicting(vector <BasicBlock *> &bb_list);
  bool conflictsPriorityCode(BasicBlock *bb);
  bool conflictsPriorityCode(uint64_t addrs);
  int cfCheck(vector <BasicBlock *> &bb_list);
  long double nonCodeScore(uint64_t entry);
  bool codeParent(BasicBlock *bb);
  void passAllProps(BasicBlock *bb);
  bool trueConflict(BasicBlock *cnf_bb);
  long double contextScore(BasicBlock *entry, BasicBlock *bb);
  bool nonConflictingRoot(BasicBlock *bb);
  bool contextPreservesABI(BasicBlock *entry);
  bool isNopPadding(BasicBlock *bb);
  bool callTargetRoot(BasicBlock *bb);
  bool likelyTrueJmpTblTgt(BasicBlock *bb);
  bool likelyTrueFunction(BasicBlock *bb);
  void entryValidation(BasicBlock *entry);
  void binarySearchValidation(BasicBlock *entry,
                                        vector <BasicBlock *> &parent_path,
                                        vector <BasicBlock *> &ind_set);
  void indTgtValidation(BasicBlock *entry,
                                  vector <BasicBlock *> &parent_path,
                                  vector <BasicBlock *> &ind_set);
  void recursiveIndTgtValidation(BasicBlock *entry,
                                 BasicBlock *intermediate_ind,
                                 vector <BasicBlock *> &parent_path,
                                 unordered_set <uint64_t> &passed);

};
}
#endif
