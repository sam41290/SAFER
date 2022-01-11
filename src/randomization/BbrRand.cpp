#include "BbrRand.h"
#include "Instruction.h"
#include "exception_handler.h"
#include <set>

extern map <uint64_t, call_site_info> all_call_sites;

vector <BasicBlock *> BbrRand::randomizeBasicBlks(vector <BasicBlock *> &bbs) {

  vector <uint64_t> brkPoints;
  uint64_t callSiteEnd = 0;
  for(auto & bb : bbs) {

    auto it = all_call_sites.find(bb->start());
    if(it != all_call_sites.end()) {
      callSiteEnd = it->first + it->second.length;
    }

    if(bb->start() >= callSiteEnd) {
      addJmpToFallThru(bb);
      brkPoints.push_back(bb->start());
    }
    else if(bb->boundary() >= callSiteEnd)
      addJmpToFallThru(bb);
  }

  unsigned
    seed = std::chrono::system_clock::now().time_since_epoch().count();
  std::shuffle(brkPoints.begin(),
		brkPoints.end(), std::default_random_engine(seed));
  vector <BasicBlock *> finalBasicBlks;
  getFinalBasicBlks(brkPoints, finalBasicBlks,bbs);


  return finalBasicBlks;
}

void
BbrRand::print(vector <BasicBlock *> bbs, string file_name, uint64_t fstart) {
  bbs = removeDuplication(bbs);
  addJmpToFallThru(bbs[bbs.size() - 1]);
  vector <BasicBlock *> rand_bbs = randomizeBasicBlks(bbs);
  printBasicBlocks(rand_bbs, file_name, fstart);
}
