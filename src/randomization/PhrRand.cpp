#include "PhrRand.h"
#include "libutils.h"
#include <set>
#include "Instruction.h"
#include "exception_handler.h"
extern map <uint64_t, call_site_info> all_call_sites;

void
PhrRand::addPhrBrkPoints(vector <uint64_t> &allIns,
                         vector <BasicBlock *> &bbs) {

  unordered_set <uint64_t> insSet;
  insSet.insert(allIns.begin(),allIns.end());
  uint64_t last_bb = bbs[bbs.size() - 1]->start();
  for(auto & bb : bbs) {
    if(bb->isCall()) {
      if(insSet.find(bb->end()) != insSet.end())
        brkPoints_.insert(bb->end());
      if(bb->fallThrough() != 0 && bb->start() != last_bb &&
         insSet.find(bb->fallThrough()) != insSet.end())
        brkPoints_.insert(bb->fallThrough());
    }
  }

}


vector <BasicBlock *> 
PhrRand::randomizeBasicBlks(vector <BasicBlock *> &bbs) {
  
  LOG("Applying ZJR...");
  ZjrRand::populateZjrBreakPoints(bbs);

  brkPoints_ = ZjrRand::getZjrBrkPoints();
  vector <uint64_t> allIns = ZjrRand::getAllInstructions();
  addPhrBrkPoints(allIns,bbs);
  vector <uint64_t> bigBlks;
  bbs = brkBasicBlk(bigBlks, brkPoints_,bbs);
  addTramps(bbs);
  for(auto & bb : bbs) {
    if(bb->isTramp())
      bigBlks.push_back(bb->start());
  }
  //randomly shuffle basic blocks
  unsigned
    seed = std::chrono::system_clock::now().time_since_epoch().count();
  std::shuffle(bigBlks.begin(),
    bigBlks.end(), std::default_random_engine(seed));

  //function that generates the proper order of the basic blocks which is to be
  //returned
  vector <BasicBlock *> finalBasicBlks;
  getFinalBasicBlks(bigBlks, finalBasicBlks,bbs);
  return finalBasicBlks;

}


/* Virtual function defined for super class bb_rand */
void
PhrRand::print(vector <BasicBlock *> bbs, string fileName,
         uint64_t fstart) {
  bbs = removeDuplication(bbs);
  addJmpToFallThru(bbs[bbs.size() - 1]);
  vector <BasicBlock *> finalBBs = randomizeBasicBlks(bbs);

  printBasicBlocks(finalBBs, fileName, fstart);
}
