#ifndef _LLRKRAND_H
#define _LLRKRAND_H

#include "Rand.h"
#include "ZjrRand.h"

using namespace SBI;
/*
	Class implementation for Length limiting randomization.
    inherits ZjrRand randomization class and implements two virtual functions
    print and randomizeBasicBlks. User needs to call the function print with
    a list of basic blocks as inputs.

    1. Applys ZJR fiest.
    2. Calculates number of further breaks based on parameter set in config.h
       file.
    3. Selects random points to break.

*/

class LlrkRand:public ZjrRand
{
private:
  set <uint64_t> brkPoints_;

  /**
   * @brief populateLlrkBrkPoints checks numbers of breaks required and applies
   * breaks at random locations.
   *
   * @param all_instructions: List of addresses of all instructions in the
   * function.
   */
  void populateLlrkBrkPoints(vector <uint64_t> &all_instructions);
  vector <BasicBlock *> randomizeBasicBlks(vector <BasicBlock *> &bbs);
public:
  LlrkRand(map <uint64_t, Pointer *>pointers,
                map <uint64_t, Function *> &functions,
                uint64_t data_seg, uint64_t progEnd)
    :ZjrRand(pointers,functions,data_seg,progEnd){}
  void print(vector <BasicBlock *> bbs, string file_name, uint64_t fstart);
};
#endif
