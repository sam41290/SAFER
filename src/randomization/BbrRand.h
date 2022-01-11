#ifndef BBRRAND_H
#define BBRRAND_H

#include "Rand.h"

using namespace SBI;

/**
 * @brief Class implementation for Zero Jump Randomization. Inherits class
 * Rand and implements the pure virtual functions print and
 * randomizeBasicBlocks.
 *
 * User needs to call the function print with a list of basic blocks as input.
 * ZJR approach:
 * 1. Breaks at unconditional control flow transfers.
 */
class BbrRand:public Rand
{
public:
  BbrRand(map <uint64_t, Pointer *>pointers,
                map <uint64_t, Function *> &functions,
                uint64_t data_seg, uint64_t progEnd)
    :Rand(pointers,functions,data_seg,progEnd){}
  vector <BasicBlock *> randomizeBasicBlks(vector <BasicBlock *> &bbs);
  void print(vector <BasicBlock *> bbs, string fileName, uint64_t fnStart);
};
#endif
