#ifndef CFG_H
#define CFG_H
#include "PhrRand.h"
#include "BbrRand.h"
#include "disasm.h"
#include "BasicBlock.h"
#include "PointerAnalysis.h"
#include "config.h"
#include "Instruction.h"
#include "Frame.h"
#include "Pointer.h"
#include "Function.h"
#include "exe_manager.h"
#include "exception_handler.h"
#include "libutils.h"
#include "Rand.h"
#include "NoBBRand.h"
#include "LlrkRand.h"
#include "PbrRand.h"
#include "CfgElems.h"
#include <vector>
#include <map>
#include <string>
#include <queue>
#include <set>

/* Class cfg represents the Control Flow Graph of the program.
 * Class cfg is responsible for disassembly and Control Flow Graph generation.
 */

using namespace std;



#define PTR_ACCESS(ins) \
  ins->isRltvAccess() ? ins->ripRltvOfft() \
  : ((type_ == exe_type::NOPIE) ? ins->constOp() : 0)

#define NEWBB(bb,bbend, ins_list,fall,tgt,isLea)\
  bb->end(bbend); bb->insList(ins_list);\
  bb->fallThrough(fall); \
  bb->target(tgt);\
  bb->isLea(isLea);



#define ADD_PTR_TO_MAIN(ptr) \
  if(ptr > 0) { \
    addToDisasmRoots(ptr);\
    createFn(true, ptr,ptr,code_type::CODE);;\
    newPointer(ptr,PointerType::CP,PointerSource::KNOWN_CODE_PTR,insList[ind]->location());\
  }
namespace SBI {

class Cfg:public PointerAnalysis 
{
  //map <uint64_t, BasicBlock *> basicBlkMap_;
  priority_queue <int, vector <int>, greater <int>> disasmRoots_;
  set <PointerSource> ignoreRoots_;
  Rand *randomizer_;
  PointerSource rootSrc_ = PointerSource::NONE;
  uint64_t currentRoot_;
public:
    Cfg(uint64_t memstrt, uint64_t memend,string exepath);
   ~Cfg() {};
  void rootSrc(PointerSource src) { rootSrc_ = src; } 
  bool addToCfg(uint64_t addrs, PointerSource t);
  void disasmRoots(PointerType p_type);
  void disassemble();
  void functionRanges();
  void printFunc(uint64_t function, string file_name);
private:
  void cnsrvtvDisasm();
  void randomizer();
  void createBB(BasicBlock *bb, vector <Instruction *>
      &ins_list,uint64_t chunk_end,
      code_type t);
  void genCFG();
  void addToDisasmRoots(uint64_t address);
  void checkLockPrefix(BasicBlock *bb,code_type t);
  bool processFallThrough(BasicBlock *bb, PointerSource t);
  bool processTarget(BasicBlock *bb, PointerSource t);
  void processAllRoots();
  void possibleCodeDisasm();
  void EHDisasm();
  void groundTruthDisasm();
  void randomPointDisasm(int min,int max);
  void scanPsblPtrs();
  void scanMemForPtr (uint64_t start,uint64_t start_addr,uint64_t size);
  void scanPsblPtrsGT();
  void scanMemForPtrGT (uint64_t start,uint64_t start_addr,uint64_t size);
  void jmpTblGroundTruth(int type);
  void checkForPtr(Instruction *ins);
  void processIndrctJmp(Instruction *call_ins, BasicBlock * bb,code_type t);
  void scanForCalls(int call_cnt);
  void disassembleGaps();
  void checkFirstUseDef(vector <uint64_t> &psbl_entries);
  void checkPsblEntries(uint64_t psbl_fn_start, uint64_t gap_end);
  void addHintBasedEntries();
  void handleLoopIns(vector <BasicBlock *> &bb_list);
  void reAddFallThrough(vector <BasicBlock *> &bb_list);
  void guessJumpTable();
};
}
#endif
