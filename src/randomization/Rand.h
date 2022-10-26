#ifndef _BBRAND_H
#define _BBRAND_H

#include "BasicBlock.h"
#include "Pointer.h"
#include "Instruction.h"
#include "Function.h"
#include "config.h"
using namespace SBI;

/**
 * @brief class Rand represents randomization interface. It randomizes a given
 * list of basic blocks.
 * How to use? - User needs to call the virtual function print with a list of
 * basic blocks as input.
 *
 * There is one base class per randomization mode (NoBBRand, ZjrRand, PbrRand or
 * LlrkRand). Each base class implements its own version of virtual functions
 * randomizeBasicBlks and print.  
 *
 * User can typecast a Pointerof Rand type to any of the base class type and
 * call the respective "print" function.
 */
class Rand
{
private:
  uint64_t dataSegmentStart_ = 0;
  map <uint64_t, Pointer*> pointerMap_;
  map <uint64_t, Function *> functionMap_;
  uint64_t programEnd_ = 0;
  map <uint64_t, vector<uint64_t>> callSiteEndMap_;
public:

  Rand(map <uint64_t, Pointer*> pointers,
                map < uint64_t, Function * > &functions,
                uint64_t data_seg, uint64_t progEnd);
  void printBasicBlocks(vector <BasicBlock *> &bbs, string fileName,
                        uint64_t fstart);
  //BasicBlock *getBasicBlk(uint64_t start);
  uint64_t getProgramEnd() {  return programEnd_; };

  Function *getFunction(uint64_t fstart) {
    return functionMap_[fstart];
  }
  vector <BasicBlock *> removeDuplication(vector <BasicBlock *> &bb_list);
  /**
   * @brief addJmpToFallThru checks if a basic block at address bbAddrs has
   * a fall-through. If yes, then adds an ASM jump instruction with target as
   * fall-through.
   *
   * @param bbAddrs: start address of basic block.
   */
  void addJmpToFallThru(BasicBlock *bb);
  
  /**
   * @brief brkBasicBlk Takes a set of break points as input. It checks if the
   * break point is a basic block start. If not, it splits the basic block to
   * which the break point belongs.
   *
   * @param bigBlkStarts: brkBasicBlk populates this vector while splitting the
   * basic blocks. 
   * @param brkPoints: set of break points.
   */
  vector <BasicBlock *> brkBasicBlk(vector <uint64_t> &bigBlkStarts,set
      <uint64_t> &brkPoints,
      vector<BasicBlock *> bbs);

  /**
   * @brief getFinalBasicBlks takes a shuffled vector of break points or big
   * block starts as input. Assigns basic blocks to each big block.
   *
   * @param breakPoints: Shuffled vector of big blocks or break points.
   * @param finalBasicBlks: Final list of basic blocks present in the same order
   * as the big blocks to which they belong.
   * @param end: Function end
   */
  void getFinalBasicBlks(vector <uint64_t> &brkPoints,
                 vector <BasicBlock *> &finalBasicBlks,
                 vector <BasicBlock *> &bbList);

  void addTramps(vector <BasicBlock *> &bbList);
  void addTrampForBB(BasicBlock *bb);
  virtual vector <BasicBlock *> randomizeBasicBlks(vector <BasicBlock *> &bbs) = 0;
  virtual void print(vector <BasicBlock *> bbs, string fileName, uint64_t fstart)
    = 0;
  virtual void initMembers(){}
private:

  /**
   * @brief printUnwindRec: Prints stack unwinding metadata for a given basic
   * block.
   *
   * @param frame: Function address
   * @param bb: Pointerto basic block.
   */
  void printUnwindRec(uint64_t frame, BasicBlock * bb);
};

#endif
