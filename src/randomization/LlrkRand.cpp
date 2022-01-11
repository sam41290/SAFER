#include "LlrkRand.h"
#include "libutils.h"
#include <set>
#include "Instruction.h"
#include "exception_handler.h"
extern map <uint64_t, call_site_info> all_call_sites;

void
LlrkRand::populateLlrkBrkPoints(vector <uint64_t> &allIns) {

  /*Chooses random locations to introduce breaks
   */

  LOG("Splitting at random locations");
  int blkCount;

  int insCount = allIns.size();

  LOG("Total instruction count: " <<insCount);
  int blkSize = insCount / brkPoints_.size();  //Calculate ZJR block size
  LOG("ZJR block size: " <<blkSize);
  if(blkSize <= LLRK_COMMON_CONSTANT_VALUE) {
    LOG("No further split required");
    return;
  }
  //Calculate required number of breaks.
  blkCount = allIns.size() / LLRK_COMMON_CONSTANT_VALUE - brkPoints_.size();

  //Remove ZJR break points from possible candidate list.
  vector <uint64_t> psbl_candidates;

  for(auto ins : allIns) {
    if(brkPoints_.find(ins) == brkPoints_.end())
      psbl_candidates.push_back(ins);
  }

  //for(auto it = brkPoints_.begin();it != brkPoints_.end();it++)
  //{
  //  LOG("Erasing "<<hex<<*it<<" from candidate list");
  //  allIns.erase(find(allIns.begin(), allIns.end(), *it));
  //}


  int possibleCandidatesCnt = psbl_candidates.size();

  if(possibleCandidatesCnt <(blkCount - 1)) {
    LOG("number of candidates <required break points. No further split possible");
    return;
  }


  //Shuffle the rest of the candidates and choose first n break points.

  unsigned seed =
    std::chrono::system_clock::now().time_since_epoch().count();
  std::shuffle(psbl_candidates.begin(), psbl_candidates.end(),
    std::default_random_engine(seed));

  for(int i = 0; i <(blkCount - 1); i++) {
    uint64_t address = psbl_candidates[i];
    LOG("LLRK break point: " <<hex <<address);
    brkPoints_.insert(address);
    i++;
  }
}


vector <BasicBlock *> LlrkRand::randomizeBasicBlks(vector <BasicBlock *> &bbs) {
  
  LOG("Applying ZJR...");
  ZjrRand::populateZjrBreakPoints(bbs);
  vector <uint64_t> allIns = ZjrRand::getAllInstructions();

  brkPoints_ = ZjrRand::getZjrBrkPoints();
  populateLlrkBrkPoints(allIns);

  vector <uint64_t> bigBlks;
  bbs = brkBasicBlk(bigBlks, brkPoints_,bbs);

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
LlrkRand::print(vector <BasicBlock *> bbs, string fileName,
         uint64_t fstart) {
  bbs = removeDuplication(bbs);
  addJmpToFallThru(bbs[bbs.size() - 1]);
  vector <BasicBlock *> finalBBs = randomizeBasicBlks(bbs);

  printBasicBlocks(finalBBs, fileName, fstart);
}
