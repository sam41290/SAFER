#ifndef NOBBRAND_H
#define NOBBRAND_H

#include "Rand.h"
using namespace SBI;
/*
	Class implementation for No randomization
*/
class NoBBRand:public Rand
{
private:

public:
  NoBBRand(map <uint64_t, Pointer *>pointers,
                map <uint64_t, Function *> &functions,
                uint64_t data_seg, uint64_t progEnd)
    :Rand(pointers,functions,data_seg,progEnd){}

  /**
   * @brief randomizeBasicBlks returns the same basic block list in the same
   * order as in the input
   *
   * @param bbs: list of basic blocks.
   *
   * @return 
   */
  vector <BasicBlock *> randomizeBasicBlks (vector <BasicBlock *> &bbs);
  void print(vector <BasicBlock *> bbs, string file_name, uint64_t fstart);
};
#endif
