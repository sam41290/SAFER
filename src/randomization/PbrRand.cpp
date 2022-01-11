#include "PbrRand.h"
#include "libutils.h"
#include <set>
#include "Instruction.h"
#include "exception_handler.h"
extern map <uint64_t, call_site_info> all_call_sites;


/* We need to assign some address to the newly created phantom blocks since
 * address is the key used in map_of_basic_blocks.
 * init_members initializes phantomBlkStrt_ to the end of data segment.*/

void
PbrRand::initMembers() {
  phantomBlkStrt_ = getProgramEnd() + 1;
}

/* PBR steps:
 * 1. Break at calls.
 * 2. If number of breaks <than required, break at basic blocks.
 * 3. If number of breaks still <required, introduce phantom blocks.
 * 4. Introduce trampolines to the entry point.
 */

void
PbrRand::brkAtCalls(vector <BasicBlock *> &bbs) {
  LOG("Introducing breaks at calls...");

  //kept true for the first iteration so that the first address of the function
  //is always inserted as a break point by default.
  bool isCall = true;

  for(unsigned int i = 0; i < bbs.size(); i++) {
    uint64_t bbAddrs = bbs[i]->start();
    LOG("BB: " <<hex <<bbAddrs);
    if(isCall) {
      brkPoints_.insert(bbAddrs);
      isCall = false;
    }
    auto it = all_call_sites.find(bbAddrs);
    if(it != all_call_sites.end()) {
      uint64_t callSiteEnd = it->first + it->second.length;

      //Skipping basic blocks belonging to a EH call sites.
      //Current implementation keeps all call sites unchanged.

      while(i < bbs.size() && bbAddrs < callSiteEnd) {
        bbAddrs = bbs[i]->start();
        i++;
      }

      i--;			
      //no harm in breaking after last BB in the call site block.
    }
    BasicBlock *bb_ptr = bbs[i];//getBasicBlk(bbAddrs);
    if(bb_ptr->lastIns()->isCall()) {
      //basic block ending with a call instruction
      isCall = true;
      LOG("breaking here");
    }

  }
}

void
PbrRand::brkAtAllBBs(vector <BasicBlock *> &bbs) {
  for(unsigned int i = 0; i < bbs.size(); i++) {
    uint64_t bbAddrs = bbs[i]->start();
    brkPoints_.insert(bbAddrs);
    auto it = all_call_sites.find(bbAddrs);
    if(it != all_call_sites.end()) {
      uint64_t callSiteEnd = it->first + it->second.length;
      //Skipping basic blocks belonging to a call site
      while(i < bbs.size() && bbAddrs < callSiteEnd) {
        bbAddrs = bbs[i]->start();
        i++;
      }
    }
  }

}

vector <BasicBlock *> 
PbrRand::randomizeBasicBlks(vector <BasicBlock *> &bbs) {
  if(bbs.size() == 0)
    return bbs;

  //First break at all call instructions.

  brkAtCalls(bbs);
  if(brkPoints_.size()>=(PBR_COMMON_CONSTANT_VALUE - 1))
    return getFinalBBList(bbs);

  //Add all basic blocks as break points
  brkAtAllBBs(bbs);

  if(brkPoints_.size()>=(PBR_COMMON_CONSTANT_VALUE - 1)) 
    return getFinalBBList(bbs);
    

  //Introduce phantom blocks.

  addPhantomBlks(bbs, PBR_COMMON_CONSTANT_VALUE - bbs.size());

  return getFinalBBList(bbs);

}

vector <BasicBlock *> 
PbrRand::getFinalBBList(vector<BasicBlock *> &bbs) {

  /* Randomize the big blocks and assign BBs to each big block */

  vector <BasicBlock *> finaBasicBlks;
  vector <uint64_t> bigBlks;

  bbs = brkBasicBlk(bigBlks, brkPoints_,bbs);
  unsigned
    seed = std::chrono::system_clock::now().time_since_epoch().count();
  std::shuffle(bigBlks.begin(),
		bigBlks.end(), std::default_random_engine(seed));

  getFinalBasicBlks(bigBlks, finaBasicBlks, bbs);

  /* get_finaBasicBlks is a function of parent class bb_rand.
   * It takes the randomized list of big blocks.
   * Assigns smaller BBs to big blocks and arranges the smaller BBs according
   * to the randomized order of big blocks.
   */

  return finaBasicBlks;
}


/* Adding phantom block to the function start*/
void
PbrRand::addPhantomBlkAtFuncStrt(vector <BasicBlock *> &bbs,
						  uint64_t fstart) {
  LOG("Adding phantom blocks and trampolines to function entry...");
  if(trampAdded_.find(fstart) != trampAdded_.end()) {
    LOG("Trampoline already exists...");
    return;
  }
  trampAdded_.insert(fstart);
  Function *fptr = getFunction(fstart);
  set <uint64_t> entryPoints = fptr->entryPoints();

  auto it = entryPoints.begin();

  while(it != entryPoints.end()) {
    /* Change the label of the entry basic block. So that any call or jmp
     * won't reach it directly.
     * Create a phantom block with trampoline jump.
     * Assign the original label to the trampoline jump.
     */

    uint64_t entry = *it;
    LOG("entry point: " <<hex <<entry);
    for(auto bb : bbs) {
      if(bb->start() == entry) {
        uint64_t strtLoc = bb->start();
        Instruction *firstIns = bb->getIns(strtLoc);
        firstIns->label("." + to_string(strtLoc) + "_ph");

        //uint64_t phBBStrt = phantomBlkStrt_;

        BasicBlock *phBB = new BasicBlock(phantomBlkStrt_,phantomBlkStrt_
            + 1,PointerSource::PHANTOM, PointerSource::NONE);
        Instruction *ins = createJmp(entry);	//jmp instruction the strtLoc is
                                                //created
        phBB->addIns(ins);	//instruction added to the phantom block
        phantomBlkStrt_ += 2;
        Instruction *phIns = getPhantomIns();
        phBB->addIns(phIns);	//phantom instruction is added to the phantom
                                //block

        phantomBlkStrt_ += 2;
        phBB->codeType(code_type::CODE);
        phBB->end(phantomBlkStrt_);
        bbs.push_back(phBB);
      break;
      }
    }
    it++;
  }

}

/* Return an instructions containing phantom instruction */
Instruction *
PbrRand::getPhantomIns() {
  //random number of 0xcc instructions
  int randPh = 1 + rand() % MAX_PBR_PER_BLOCK;	
  Instruction *phIns = new Instruction();
  //Location is set of current phantom block start
  phIns->location(phantomBlkStrt_);	
  vector <uint8_t> bytes;
  while(randPh> 0) {
      bytes.push_back(0xcc);
      randPh--;
    }

  phIns->insBinary(bytes);
  phIns->label("." + to_string(phantomBlkStrt_));
  return phIns;
}

//Creates an instruction with a jmp instruction to the jmpAddrs mentioned
Instruction *
PbrRand::createJmp(uint64_t jmpAddrs) {
  Instruction *ins = new Instruction();
  string jump_location = "jmp ." + to_string(jmpAddrs) + "_ph";
  ins->location(phantomBlkStrt_);
  ins->asmIns(jump_location);
  ins->isJump(1);
  ins->label("." + to_string(jmpAddrs));

  return ins;
}


/* Adding phantom blocks*/
void
PbrRand::addPhantomBlks(vector <BasicBlock *> &bbs, int blkCnt) {
  srand(time(0));

  /* blkCnt is the required number of phantom blocks.
   * chooses blkCnt number of random BBs and adds phantom instructions
   * to their end.
   */

  for(int i = 0; i <blkCnt; i++) {
    int index = rand() % bbs.size();
    BasicBlock *bb_ptr = bbs[index];
    bb_ptr->traps(1 + rand() % MAX_PBR_PER_BLOCK);
  }
}


/* Virtual function defined for super class bb_rand */
void
PbrRand::print(vector <BasicBlock *> bbs, string fileName, uint64_t fstart) {
  brkPoints_.clear();
  //addPhantomBlkAtFuncStrt(bbs,fstart);
  bbs = removeDuplication(bbs);
  addJmpToFallThru(bbs[bbs.size() - 1]);
  vector <BasicBlock *> finalBBs = randomizeBasicBlks(bbs);
  addPhantomBlkAtFuncStrt(finalBBs, fstart);
  printBasicBlocks(finalBBs, fileName, fstart);
}
