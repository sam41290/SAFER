#include "NoBBRand.h"

vector <BasicBlock *> NoBBRand::randomizeBasicBlks (vector <BasicBlock *> &bbs)
{
  return bbs;
}

void
NoBBRand::print (vector <BasicBlock *> bbs, string file_name, uint64_t fstart)
{
  //DEF_LOG("printing bbs cnt: "<<bbs.size());
  if(bbs.size() <= 0)
    return;
  //bbs = removeDuplication(bbs);
  BasicBlock *prevBB = NULL;
  for(auto bb : bbs) {
    if(prevBB != NULL && prevBB->fallThrough() != bb->start()) {
      addJmpToFallThru(prevBB);
    }
    prevBB = bb;
  }
  if(prevBB != NULL && prevBB->fallThrough() != 0)
    addJmpToFallThru(prevBB);
  vector<uint64_t> brkPoints;
  brkPoints.push_back(bbs[0]->start());
  //DEF_LOG("Getting final bb list");
  vector<BasicBlock *> finalbbs;
  getFinalBasicBlks(brkPoints,finalbbs,bbs);
  //DEF_LOG("Printing bbs");
  printBasicBlocks(finalbbs, file_name, fstart);
}
