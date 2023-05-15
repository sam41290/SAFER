#ifndef _CFGELEMS_H
#define _CFGELEMS_H

#include "JumpTable.h"
#include "BasicBlock.h"
#include "config.h"
#include "Instruction.h"
#include "Pointer.h"
#include "Function.h"
#include "libutils.h"
#include "libanalysis.h"
#include "Dfs.h"
#include "disasm.h"


using namespace std;

#ifdef DATADISASM
#define INVALID_CODE_PTR(addr) \
  (addr >= dataSegmntEnd_) || (validPtr(addr) == false) ? true : false
#else
#define INVALID_CODE_PTR(addr) \
  (validPtr(addr) == false) || addr >= codeSegEnd_ || withinRoSection(addr) ? true : false
#endif

#define PTRTYPE(c_type) \
  ((c_type == code_type::CODE) ? PointerType::CP :\
  (c_type == code_type::DATA) ? PointerType::DP : PointerType::UNKNOWN)


#ifdef KNOWN_CODE_POINTER_ROOT
#define ISCODE(src) \
  (((int)src == (int)PointerSource::KNOWN_CODE_PTR) ? code_type::CODE :\
   ((int)src == (int)PointerSource::CALL_TGT_2) ? code_type::CODE :\
   ((int)src == (int)PointerSource::GAP_PTR) ? code_type::GAP : code_type::UNKNOWN)
#endif

#ifdef STRINGS
#define ISCODE(src) \
  (((int)src == (int)PointerSource::KNOWN_CODE_PTR) ?\
               code_type::CODE : code_type::UNKNOWN)
#endif
#ifdef DATADISASM
#define ISCODE(src) \
  (((int)src == (int)PointerSource::KNOWN_CODE_PTR) ?\
               code_type::CODE : code_type::UNKNOWN)
#endif

#ifdef GROUND_TRUTH
#define ISCODE(src) code_type::CODE
#endif

#ifdef EH_FRAME_DISASM_ROOT
#define ISCODE(src) ((int)src == (int)PointerSource::KNOWN_CODE_PTR ?\
                    code_type::CODE : code_type::UNKNOWN)
#endif
/*
#ifdef EH_FRAME_DISASM_ROOT
#define ISCODE(src) (((int)src == (int)PointerSource::KNOWN_CODE_PTR ||\
                   (int)src == (int)PointerSource::EH ||\
                   (int)src == (int)PointerSource::EHFIRST) ?\
                    code_type::CODE : code_type::UNKNOWN)
#endif
*/
#define ADDBBTOFN(bb,func,src) \
  bb->codeType(ISCODE(src));\
  if(code_type::CODE == ISCODE(src)) {\
    func->addDefCodeBB(bb);\
  }\
  else {\
    func->addUnknwnCodeBB(bb);\
  }

#define ADDENTRY(fn, addrs, code)\
  if(code == code_type::CODE)\
    fn->addEntryPoint(addrs); \
  else\
    fn->addProbableEntry(addrs);

#define ADDSYMBOLCANDIDATE(addrs,storage,symbolize,t,symtype) {\
  if(pointerMap_[addrs]->symExists(storage) == false) {\
    Symbol s1(storage,symtype);\
    pointerMap_[addrs]->symCandidate(s1);\
  }\
  if(symbolize && (t == PointerType::CP))\
    pointerMap_[addrs]->symbolize(SymbolizeIf::SYMLOCMATCH,storage);\
}

#define ADDPOINTER(addrs,t,src,storage) {\
  if(if_exists(addrs,pointerMap_)) {\
    if((int)src > (int)pointerMap_[addrs]->source())\
      pointerMap_[addrs]->source(src);\
    if(t == PointerType::CP)\
      pointerMap_[addrs]->type(t);\
  }\
  else {\
    Pointer *p = new Pointer(addrs,t,src);\
    pointerMap_[addrs] = p;\
  }\
  if(storage != 0) {\
    switch(src) {\
     case PointerSource::SYMTABLE : \
       break;\
     case PointerSource::DEBUGINFO : \
       break;\
     case PointerSource::EH : \
       break;\
     case PointerSource::POSSIBLE_RA :\
       break;\
     case PointerSource::JUMPTABLE : \
     {\
       bool symbolize = true;\
       SymbolType stype = SymbolType::JMP_TBL_TGT;\
       ADDSYMBOLCANDIDATE(addrs,storage,symbolize,t,stype);\
       break;}\
     case PointerSource::RIP_RLTV : \
     {\
       bool symbolize = true;\
       SymbolType stype = SymbolType::RLTV;\
       ADDSYMBOLCANDIDATE(addrs,storage,symbolize,t,stype);\
       break;}\
     case PointerSource::CONSTMEM : \
     {\
       bool symbolize = false;\
       SymbolType stype = SymbolType::OPERAND;\
       ADDSYMBOLCANDIDATE(addrs,storage,symbolize,t,stype);\
       break;}\
     case PointerSource::CONSTOP : \
     {\
       bool symbolize = false;\
       SymbolType stype = SymbolType::OPERAND;\
       ADDSYMBOLCANDIDATE(addrs,storage,symbolize,t,stype);\
       break;}\
     case PointerSource::GAP_PTR : \
     {\
       bool symbolize = false;\
       SymbolType stype = SymbolType::LINEAR_SCAN;\
       ADDSYMBOLCANDIDATE(addrs,storage,symbolize,t,stype);\
       break;}\
     default : \
     {\
       bool symbolize = true;\
       SymbolType stype = SymbolType::CONSTANT;\
       ADDSYMBOLCANDIDATE(addrs,storage,symbolize,t,stype);\
       break;}\
    }\
  }\
}

#define ADDPOINTERWITHROOT(addrs,t,src,root,storage) { \
  ADDPOINTER(addrs,t,src,storage)\
  if((int)root > (int)pointerMap_[addrs]->rootSrc())\
    pointerMap_[addrs]->rootSrc(root); \
}

namespace SBI {

  struct Hint {
    uint64_t addrs_;
    long double score_ = 0;
    Hint(uint64_t s, long double scr) {
      addrs_ = s;
      score_ = scr;
    }
  };

  struct CompareHint {
    bool operator()(Hint &c1, Hint &c2) {
      return c1.score_ < c2.score_;
    }
  };

  struct Gap {
    uint64_t start_;
    uint64_t end_;
    long double score_ = 0;
    long double minScore_ = 0;
    priority_queue<Hint, vector<Hint>, CompareHint> hintQ_;
    Gap(uint64_t s, uint64_t e) {
      start_ = s;
      end_ = e;
    }
  };
  struct CompareGap {
    bool operator()(Gap &c1, Gap &c2) {
      return c1.score_ < c2.score_;
    }
  };

  enum class JumpType {
    SCJ,
    SUJ,
    LUJ,
    LCJ,
    CALL
  };

  class CfgElems : public Instrument, public virtual Dfs {
    map <uint64_t, Pointer *> pointerMap_;
    map <uint64_t, Function *> funcMap_;
    set <uint64_t> exitCallPlt_;
    set <uint64_t> mayExitPlt_;
    set <uint64_t> allPltSlots_;
    vector <JumpTable> jmpTables_;
    vector <section> roSections_;
    vector <section> rxSections_;
    vector <section> rwSections_;
    vector <Reloc> pcrelReloc_;
    vector <Reloc> xtraConstReloc_;
    vector <Reloc> picConstReloc_;
    set<uint64_t> invalidPtr_;
    unordered_set <uint64_t> conflictingRoots_;
    unordered_map <uint64_t, long double> cftTgtsInGaps_;
    unordered_map <uint64_t, JumpType> cftsInGaps_;
    unordered_set <uint64_t> entryPropagated_;
    unordered_map <uint64_t, BasicBlock *> bbCache_;
  public:
    DisasmEngn *disassembler_;
    exe_type type_;
    uint64_t entryPoint_ = 0;
    uint64_t codeSegEnd_ = 0;
    uint64_t libcStrtMain_ = 0;
    uint64_t dataSegmntStart_ = 0;
    uint64_t dataSegmntEnd_ = 0;
    uint64_t textSectionEnd_ = 0;
    string exePath_;
    string exeName_;
    void exePath(string p) { 
      exePath_ = p;
      string key("/");
      size_t found = exePath_.rfind(key);
      exeName_ = exePath_.substr(found + 1);
    }
    string exePath() {
      return exePath_;
    }

    string exeName() {
      return exeName_;
    }
    void type(exe_type t) { 
      LOG("Exe Type: "<<dec<<(int)t);
      type_ = t; 
    }
    uint64_t sectionEnd(uint64_t addrs);
    void picConstReloc(vector <Reloc> & r) { picConstReloc_ = r; }
    vector <Reloc> picConstReloc() { return picConstReloc_; }
    void pcrelReloc(vector <Reloc> & r) { pcrelReloc_ = r; }
    vector <Reloc> pcrelReloc() { return pcrelReloc_; }
    void xtraConstReloc(vector <Reloc> & r) { xtraConstReloc_ = r; }
    vector <Reloc> xtraConstReloc() { return xtraConstReloc_; }
    void functions(map <uint64_t, Function *>&functions) {
      funcMap_ = functions;
    }
    void newPointer(uint64_t val, PointerType t, PointerSource src, 
        uint64_t storage) {
      ADDPOINTER(val,t,src,storage);
    }
    void newPointer(uint64_t val, PointerType t, PointerSource src, 
        PointerSource root,uint64_t storage) {
      ADDPOINTERWITHROOT(val,t,src,root,storage);
    }
    void exitCall(set <uint64_t> &exit_call) {
      exitCallPlt_ = exit_call;
    }
    bool exitCall(uint64_t addr) {
      if(exitCallPlt_.find(addr) != exitCallPlt_.end())
        return true;
      return false;
    }
    void mayExitPlt(set <uint64_t> &exit_call) {
      mayExitPlt_ = exit_call;
    }
    void allPltSlots(set <uint64_t> &all_plt) {
      allPltSlots_ = all_plt;
    }
    bool isPlt(uint64_t slot) {
      if(allPltSlots_.find(slot) != allPltSlots_.end())
        return true;
      return false;
    }
    bool mayExitCall(uint64_t addr) {
      if(mayExitPlt_.find(addr) != mayExitPlt_.end())
        return true;
      return false;
    }
    void roSection(vector <section> &ro_data) {
      roSections_ = ro_data;
    }
    void entryPoint(uint64_t epoint) {
      entryPoint_ = epoint;
    }
    void rwSections(vector <section> &data_segment) {
      rwSections_ = data_segment;
      for (auto & sec : rwSections_) {
        if((sec.vma + sec.size) > dataSegmntEnd_)
          dataSegmntEnd_ = sec.vma + sec.size;
      }
      LOG("data segment end: "<<hex<<dataSegmntEnd_);
    }
    vector <section> rwSections() { return rwSections_; }
    void dataSegmntStart(uint64_t data_seg) {
      dataSegmntStart_ = data_seg;
    }
    uint64_t dataSegmntStart() { return dataSegmntStart_; }
    void rxSections(vector <section> &rxSections) {
      rxSections_ = rxSections;
      for(auto sec : rxSections_) {
        if(sec.name == ".text")
          textSectionEnd_ = sec.vma + sec.size;
      }
    }
    vector <section> rxSections() { return rxSections_; }
    map <uint64_t, Function *> funcMap() {
      return funcMap_;
    }
    vector <section> roSections() {
      return roSections_;
    }
    map <uint64_t, Pointer *>&pointers() {
      return pointerMap_;
    }
    set<uint64_t> invalidPtr() { return invalidPtr_; }
    void invalidPtr(uint64_t addrs) { invalidPtr_.insert(addrs); }
    bool validPtr(uint64_t addrs) {
      if(invalidPtr_.find(addrs) == invalidPtr_.end())
        return true;
      return false;
    }
    void codeSegEnd(uint64_t code_end) {
      codeSegEnd_ = code_end;
    }
    void libcStartMain(uint64_t lib_start) {
      libcStrtMain_ = lib_start;
    }
    void pointers(map <uint64_t, Pointer *>pointers) {
      pointerMap_ = pointers;
    }
    unsigned int ptrCnt() { return pointerMap_.size(); }
    void functions(set <uint64_t> &function_list, uint64_t section_start,
      	      uint64_t section_end);
    bool definiteCode(uint64_t addrs);
    //bool assignLabeltoFn(string label, off_t func_addrs);
    BasicBlock *getBB(uint64_t addrs);
    void markAsDefCode(uint64_t addrs, bool force = false);
    bool conflictsDefCode(uint64_t addrs);
    BasicBlock *withinBB(uint64_t addrs);
    bool isValidAddress(uint64_t addrs);
    bool isValidIns(uint64_t addrs);
    void printOriginalAsm();
    void printDeadCode();
    void dump(); 
    void readCfg();
    bool isDataPtr(Pointer * ptr);
    void classifyPtrs();
    bool isCodePtr(Pointer * ptr);
    void prntPtrStats();
    uint64_t dataBlkEnd();
    void createFuncFrPtr(Pointer *ptr);
    BBType getBBType(uint64_t bbAddrs);
    void addBBtoFn(BasicBlock *bb, PointerSource t);
    void linkBBs(vector <BasicBlock *> &bbs);
    void linkAllBBs();
    void removeBB(BasicBlock *bb);
    bool withinRoSection(uint64_t addrs);
    bool withinRWSection(uint64_t addrs);
    bool withinCodeSec(uint64_t addrs);
    void populateRltvTgts();
    bool accessConflict(uint64_t addrs);
    bool validPtrAccess(Pointer *ptr, uint64_t loc);
    bool validPtrToPtrArray(uint64_t ptr,uint64_t end);
    bool validRead(Pointer *ptr);
    bool validPtrToPtr(uint64_t ptr);
    bool withinSymbolArray(uint64_t addrs);
    bool validEntry(uint64_t entry);
    void propagateAllRoots();
    void propagateRoots(vector <BasicBlock *> &bbs);
    void propagateEntries(set <uint64_t> &entries);
    bool isString(uint64_t addrs);
    uint64_t isValidRoot(uint64_t addrs,code_type t);
    uint64_t nextPtr(uint64_t addrs);
    bool zeroDefCodeConflict(vector <BasicBlock *> &bb_list);
    void createFn(bool is_call, uint64_t target_address,uint64_t ins_addrs,
        code_type t);
    void saveCnsrvtvCode() {
      for(auto & fn : funcMap_)
        fn.second->saveCnsrvtvCode();
    }
    bool withinFn(uint64_t addrs) {
      auto fn = is_within(addrs,funcMap_);
      if(fn == funcMap_.end() || fn->second->end() <= addrs)
        return false;
      return true;
    }
    Pointer *ptr(uint64_t addrs) { 
      if(if_exists(addrs,pointerMap_))
        return pointerMap_[addrs]; 
      else
        return NULL;
    }
    void instrument();
    void shadowStackInstrument(pair<InstPoint,string> &x);
    void shadowStackRetInst(BasicBlock *bb,pair<InstPoint,string> &x);
    void instrument(uint64_t hook_point,string code);
    vector <JumpTable> jumpTables() { return jmpTables_; }
    void jumpTable(JumpTable j) { jmpTables_.push_back(j); }
    bool rewritableJmpTblLoc(uint64_t addrs);
    bool rewritableJmpTblBase(uint64_t addrs);
    bool sameLocDiffBase(uint64_t loc, uint64_t base);
    bool jmpTblExists(JumpTable &j);
    bool isJmpTblLoc(uint64_t addrs);
    bool isJmpTbl(uint64_t addrs);
    bool isJmpTblBase(uint64_t addrs);
    unsigned int jumpTableCnt() { return jmpTables_.size(); }
    void updateJmpTblTgts() {
      for(auto & j : jmpTables_) {
        linkCFToJumpTable(&j, j.cfLoc());
        vector<uint64_t> targets = j.targets();
        for(auto tgt : targets) {
          auto bb = getBB(tgt);
          if(bb == NULL) {
            LOG("Not BB for jump table target: "<<hex<<tgt);
            exit(0);
          }
          j.addTargetBB(bb);
          auto cf_loc = j.cfLoc();
          for(auto & c : cf_loc)
            addIndrctTgt(c, bb);
        }
      }
    }
    bool isMetadata(uint64_t addrs);
    string getSymbol(uint64_t addrs);
    void updateBBTypes();
    void markAsDefData(uint64_t addrs);
    bool readableMemory(uint64_t addrs);
    void addIndrctTgt(uint64_t ins_loc, BasicBlock *tgt);
    void linkCFToJumpTable(JumpTable *j, vector<uint64_t> &ins_loc);
    uint64_t nextCodeBlock(uint64_t addrs);
    vector<Gap> getGaps();
    BasicBlock *getDataBlock(uint64_t addrs);
    bool isData(uint64_t addrs);
    long double probScore(uint64_t addrs);
    long double jumpScore(vector <BasicBlock *> &lst);
    long double crossingCft(vector <BasicBlock *> &lst);
    bool conflicts(uint64_t addrs);
    vector <BasicBlock *> conflictingBBs(uint64_t addrs);
    void disassembler(DisasmEngn *disasm) { disassembler_ = disasm; }
    long double fnSigScore(BasicBlock *bb);
    long double regionScore(vector <BasicBlock *> &bb_lst);
    void phase1NonReturningCallResolution();
    void markAllCallTgtsAsDefCode();
    void markCallTgtAsDefCode(BasicBlock *bb);
    long double fnSigScore(vector <Instruction *> &ins_list);
    void chkJmpTblRewritability();
    uint64_t dataSegmntEnd (uint64_t addrs);
    unordered_set <uint64_t> allReturnAddresses();
    vector <string> allReturnSyms();
    vector <BasicBlock *> allIndrctTgt(uint64_t ins_loc);
    int offsetFrmCanaryAddToRa(uint64_t add_loc, BasicBlock *bb);
  private:
    void readIndrctTgts(BasicBlock *bb,uint64_t fn_addrs);
    BasicBlock *readBB(ifstream & file);
    bool isDatainCode(uint64_t addrs);
    void jumpTgtsInGap(uint64_t g_start, uint64_t g_end);
    vector <uint64_t> crossingCftsInGap(uint64_t g_start, uint64_t g_end);
    void gapScore(Gap &g);
    vector <uint64_t> defCodeCFTs(uint64_t g_start, uint64_t g_end);
    uint64_t jumpTgt(uint8_t *bytes, int size, uint64_t ins_addrs);
    unordered_map <uint64_t, long double> fnSigInGap(uint64_t g_start, uint64_t g_end);
    long double defCodeCftScore(vector <BasicBlock *> &bb_lst);
    bool otherUseOfJmpTbl(JumpTable &j);
    vector <Instruction *> canaryCheckWindow(BasicBlock *bb);
  };

}

#endif
