#include "ZjrRand.h"
#include "Instruction.h"
#include "exception_handler.h"
#include <set>

extern map <uint64_t, call_site_info> all_call_sites;


void
ZjrRand::populateZjrBreakPoints(vector <BasicBlock *> &bbs) {
  /* Introduce breaks after unconditional control transfers(excluding calls).
   */

  allInstructions_.clear();
  zjrBreakPoints_.clear();
  uint64_t callSiteEnd = 0;
  bool brkPoint = true;
  for(auto bb : bbs) {
    uint64_t bbAddrs = bb->start();
    if(brkPoint == true) {
      LOG("ZJR break point: " <<hex <<bbAddrs);
      zjrBreakPoints_.insert(bbAddrs);
      brkPoint = false;
    }

    vector <uint64_t> bbIns = bb->allInsLoc();
    LOG("BB: " <<hex <<bbAddrs <<" ins count: " <<bbIns.size());
    auto it = all_call_sites.find(bbAddrs);
    if(it != all_call_sites.end()) {
      callSiteEnd = it->first + it->second.length;
      LOG("Callsite: "<<hex<<it->first<<" - "<<hex<<callSiteEnd);
    }
    if(bbAddrs >= callSiteEnd)	{
      //Ignoring EH call site blocks to keep them unchanged.
      if(bb->lastIns()->isUnconditionalJmp() == 1 &&
          bb->lastIns()->isCall() == 0) {
        LOG("Unconditional jump found at: "<<hex<<bb->start());
        brkPoint = true;
      }
      allInstructions_.insert(allInstructions_.end(), bbIns.begin(),
  			   bbIns.end());

    //allInstructions_ will be used by child randomizations of ZJR, such
    //as LLRK. 
    //LLRK will choose k random locations to break from this list.
    }

  }
  //for(int i = 0; i <allInstructions_.size();i++)
  //{
  //      LOG("INS: "<<hex<<allInstructions_[i]);
  //}
}


vector <BasicBlock *> ZjrRand::randomizeBasicBlks(vector <BasicBlock *> &bbs) {
  populateZjrBreakPoints(bbs);

  vector <uint64_t> brkPoints;

  for(auto it : zjrBreakPoints_)
    brkPoints.push_back(it);

  unsigned
    seed = std::chrono::system_clock::now().time_since_epoch().count();
  std::shuffle(brkPoints.begin(),
		brkPoints.end(), std::default_random_engine(seed));
  vector <BasicBlock *> finalBasicBlks;
  getFinalBasicBlks(brkPoints, finalBasicBlks,bbs);

  /* getFinalBasicBlks is a function of parent class bb_rand.
   * It takes the randomized list of big blocks.
   * Assigns smaller BBs to big blocks and arranges the smaller BBs according
   * to the randomized order of big blocks.
   */


  return finalBasicBlks;
}

void
ZjrRand::print(vector <BasicBlock *> bbs, string file_name, uint64_t fstart) {
  bbs = removeDuplication(bbs);
  addJmpToFallThru(bbs[bbs.size() - 1]);
  vector <BasicBlock *> rand_bbs = randomizeBasicBlks(bbs);
  printBasicBlocks(rand_bbs, file_name, fstart);
}
