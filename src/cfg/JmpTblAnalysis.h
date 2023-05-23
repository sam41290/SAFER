
#ifndef _JMPTBLANALYSIS_H
#define _JMPTBLANALYSIS_H

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

using namespace std;


#define TARGET(offt, start, type, base,size) \
  ((size == 4) ? (uint32_t)COMPUTE(offt, start, type, base) :\
   COMPUTE(offt, start, type, base))

#define COMPUTE(offt, start, type, base)\
  ((type == 1) ? offt + base :\
   (type == 2) ? start : offt)

namespace SBI {
  class JmpTblAnalysis : public virtual CFValidity, public virtual CfgElems,
  public virtual SaInput {
    set <string> leaToJmpPairs;
    unordered_map<uint64_t,vector <JumpTable>> cachedJTables_;
  public:
    JmpTblAnalysis (uint64_t memstrt, uint64_t memend);
    void analyze();
    void jmpTblAnalysis();
    void analyzeAddress(vector <int64_t> &entries);
    void preCachedJumpTables();
    virtual bool addToCfg(uint64_t addrs, PointerSource src) = 0;
    virtual void addToDisasmRoots (uint64_t address) = 0;
    virtual void rootSrc(PointerSource root) = 0;
  private:
    //-----------OLD jump table code--------------------------

    void fillBlocks(vector <BasicBlock *> &lea_locs,vector <BasicBlock *>
        &ind_jmp_locs,vector <BasicBlock *> &bbList);
    vector <string> pairUp(vector <BasicBlock *> &lea_locs,
                           vector <BasicBlock *> &ind_jmp_locs);
    void genFile(vector <BasicBlock *> &basic_block_path,
                   uint64_t source, uint64_t target,
                   vector <string> &pathFIles);
    bool findPath(BasicBlock *bb_source, BasicBlock *bb_target,map <uint64_t,bool>
        &visited,stack <BasicBlock *> &path);
    void processPathFiles (vector < string > JumpTable_files);
    void decode ();
    void updateTargets(JumpTable & jt, BasicBlock *bb);
    
    //---------------------------------------------------------
    void analyzeFn(Function *fn);
    void processJTable(JumpTable &j);
    void decodeJmpTblTgts(analysis::JTable j_lst);
    void readTargets (JumpTable & jt, uint64_t jloc);
    //uint64_t dataSegmntEnd(uint64_t addrs);
  };
}

#endif
