#ifndef PBRRAND_H
#define PBRRAND_H

#include "Rand.h"
#include "BasicBlock.h"
using namespace SBI;
/**
 * @brief Class implementation for Phantom blocks randomization. Inherits class
 * Rand and implements two virtual functions print and randomizeBasicBlks.
 * 1. User just needs to call the function print with a list of Basic Blocks as
 *    input.
 * 2. PbrRand breaks at all calls first.
 * 3. Checks if required number of blocks is achieved and then breaks at all
 *    BBs.
 * 4. Checks again and if the required number of blocks is still not achieved,
 *    it introduces phantom blocks.
 * 5. Phantom blocks: Blocks with random number of trap instructions.
 */
class PbrRand:public Rand
{
private:
  uint64_t phantomBlkStrt_ = 0;

  set <uint64_t> brkPoints_;
  set <uint64_t> trampAdded_;

public:
  PbrRand(map <uint64_t, Pointer *> pointers,
                map <uint64_t, Function *> &functions,
                uint64_t data_seg, uint64_t progEnd)
    :Rand(pointers,functions,data_seg,progEnd)
  {
    initMembers();
  }

  vector <BasicBlock *> randomizeBasicBlks(vector <BasicBlock *> &bbs);
  void print(vector <BasicBlock *> bbs, string file_name, uint64_t fstart);
  void initMembers();

private:
  void brkAtCalls (vector <BasicBlock *> &bbs);
  void brkAtAllBBs (vector <BasicBlock *> &bbs);
  vector <BasicBlock *> getFinalBBList (vector <BasicBlock *> &bb);
  void addPhantomBlks (vector <BasicBlock *> &bbs, int no_of_blocks);
  Instruction *createJmp (uint64_t jump_address);
  void addPhantomBlkAtFuncStrt (vector <BasicBlock *> &bbs,
                        uint64_t fstart);
  Instruction *getPhantomIns();

};
#endif
