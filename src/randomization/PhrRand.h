#ifndef _PHRRAND_H
#define _PHRRAND_H

#include "Rand.h"
#include "ZjrRand.h"
using namespace SBI;
class PhrRand:public ZjrRand
{
private:
  set <uint64_t> brkPoints_;
  vector <BasicBlock *> randomizeBasicBlks(vector <BasicBlock *> &bbs);
public:
  PhrRand(map <uint64_t, Pointer *>pointers,
                map <uint64_t, Function *> &functions,
                uint64_t data_seg, uint64_t progEnd)
    :ZjrRand(pointers,functions,data_seg,progEnd){}
  void addPhrBrkPoints(vector <uint64_t> &allIns, vector <BasicBlock *> &bbs);
  void print(vector <BasicBlock *> bbs, string file_name, uint64_t fstart);
};
#endif
