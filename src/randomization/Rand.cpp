#include "Rand.h"
#include "libutils.h"
#include "exception_handler.h"
extern map < uint64_t, call_site_info > all_call_sites;
extern exception_handler eh_frame;
extern map < uint64_t, cfi_table > unwinding_info;

Rand::Rand(map <uint64_t, Pointer *>pointers,
                map < uint64_t, Function * >&functions,
                uint64_t data_seg, uint64_t progEnd) {
  pointerMap_ = pointers;
  functionMap_ = functions;
  dataSegmentStart_ = data_seg;
  programEnd_ = progEnd;
}


/* 
	Basic print function which will simply print all basic blocks.
	This function accepts a vector of basic blocks and it prints basic blocks
	in the order in which it is present in the vector.
*/
void
Rand::printBasicBlocks(vector <BasicBlock *> &bbs, string fileName, 
    uint64_t fStart) {

  for(auto bb : bbs) {
    uint64_t randBBStrt = bb->start();
    //DEF_LOG("Printing basic block: " << hex << randBBStrt);
    auto callSiteIt = all_call_sites.find(randBBStrt);
    if(callSiteIt != all_call_sites.end()) {
      //utils::bindLabel(randBBStrt, bb->label());
   //   eh_frame.print_call_site_tbl(callSiteIt->second.start,
   // 				callSiteIt->second.start, fStart);
      utils::printLbl(".call_site_" + to_string(callSiteIt->first),fileName);
    }

    bb->adjustRipRltvIns(dataSegmentStart_, pointerMap_);

    bb->print(fileName, pointerMap_);
    printUnwindRec(fStart, bb);
    if(if_exists(bb->start(), callSiteEndMap_) == true) {
      vector<uint64_t> call_sites = callSiteEndMap_[bb->start()];
      for(auto addr : call_sites)
        utils::printLbl(".call_site_" + to_string(addr) + "_end",fileName);
    }
  }
}


extern uint64_t xtraJmp;

extern int unwndBlkSz;

void
Rand::printUnwindRec(uint64_t frame, BasicBlock * bb) {

  /* Prints unwinding metadata for a given basic block.
   * Iterates over each instruction in the basic block.
   * Calls print_Cfi function that checks the register states for this
   * instruction and emits metadata accordingly.
   *
   * Becasue of randomization, the metadata has to be re-created for every
   * instruction.
   *
   * print_cfi maintains a state machine that keeps updated state of every
   * register while emitting the metadata. 
   *
   * For a given instruction, it compares the required register state with the
   * present state and then emits the required metadata.
   * 
   * unwndBlkSz and extra_jmp variables help in estimating the size of
   * newly created unwinding blocks.
   */

  vector <Instruction *> insList = bb->insList();

  for(auto & it : insList) {
    string label = it->label() + bb->lblSuffix();
    if(if_exists(it->location(), functionMap_) == true ||
       if_exists(it->location(), pointerMap_) == true)
      unwndBlkSz += 16;
    if(if_exists(frame, unwinding_info) == true) {
      if(unwinding_info[frame].
         print_cfi(it->location(),
      	 "tmp/" + to_string(frame) + "_unwind.s",
      	 unwndBlkSz + xtraJmp, label) == 1) {
        unwndBlkSz = 0;
        xtraJmp = 0;
      }
    }
    if(it->isRltvAccess() == 1) {
      unwndBlkSz += 15;
    }
    else if(it->isJump() == 1 || it->isCall() == 1) {
      unwndBlkSz += 10;
    }
    else {
      unwndBlkSz += it->insSize();
    }
  }

}

void
Rand::addJmpToFallThru(BasicBlock *bb) {
  //DEF_LOG("Adding fall throughs");
  if(bb != NULL && bb->fallThroughBB() != NULL) {
    //DEF_LOG("Adding fall through: "<<hex<<bb->start()<<"->"<<hex<<bb->fallThrough());
    Instruction ins;
    string jmpLoc =
      "jmp " + bb->fallThroughBB()->label();//to_string(bb->fallThrough());
    ins.asmIns(jmpLoc);
    ins.isJump(1);
    bb->fallThroughIns(ins);
  }
  //DEF_LOG("Adding fall through complete!!!");
}

vector<BasicBlock *> 
appendBBs(vector <BasicBlock *> bbList1, vector <BasicBlock*> bbList2) {
  unsigned int i = 0, j = 0;
  vector <BasicBlock *> finBBs;
  while( i < bbList1.size() && j < bbList2.size() ) {
    if(bbList1[i]->start() < bbList2[j]->start()) {
      finBBs.push_back(bbList1[i]);
      i++;
    }
    else if(bbList2[j]->start() < bbList1[i]->start()) {
      finBBs.push_back(bbList2[j]);
      j++;
    }
  }
  if( i < bbList1.size() ) {
    while( i < bbList1.size() ) {
      finBBs.push_back(bbList1[i]);
      i++;
    }
  }
  if( j < bbList2.size() ) {
    while( j < bbList2.size() ) {
      finBBs.push_back(bbList2[j]);
      j++;
    }
  }
  return finBBs;
}

extern bool
compareBB(BasicBlock *A, BasicBlock *B);

vector <BasicBlock *>
Rand::removeDuplication(vector <BasicBlock *> &bb_list) {
  //DEF_LOG("Removing duplicates");
  int bb_cnt = bb_list.size();
  //DEF_LOG("BB cnt: "<<hex<<bb_cnt);
  if(bb_cnt <= 0 || bb_list[0]->isCode() == false)
    return bb_list;
  //DEF_LOG("BB cnt: "<<hex<<bb_cnt<<" first bb: "<<bb_list[0]->start());
  unordered_set <uint64_t> bbs_to_remove;
  for(int i = 0; i < bb_cnt; i++) {
    bool overlapping = false;
    //DEF_LOG("Ctr: "<<i);
    //DEF_LOG("BB: "<<hex<<bb_list[i]->start());
    for(int j = i + 1; j < bb_cnt && bb_list[i]->boundary() >
        bb_list[j]->start(); j++) {
      overlapping = true;
      //DEF_LOG("Overlapping found: "<<hex<<bb_list[j]->start()<<" x "
              //<<hex<<bb_list[i]->start()<<"-"<<hex<<bb_list[i]->boundary());
      if(bb_list[i]->isValidIns(bb_list[j]->start())) {
        //DEF_LOG("Removing duplicated BB: "<<hex<<bb_list[j]->start());
        bbs_to_remove.insert(bb_list[j]->start());
      }
      else {
        vector <Instruction *> ins_list = bb_list[j]->insList();
        for(auto & ins : ins_list) {
          auto ins2 = bb_list[i]->getIns(ins->location());
          if(ins2 != NULL) {
            //DEF_LOG("Adjusting overlapping BB "<<hex<<bb_list[j]->start()<<" at "
                 //<<hex<<ins2->location()<<" bigger BB: "<<hex<<bb_list[i]->start());
            bb_list[j]->split(ins2->location());
            Instruction ins;
            string jmpLoc =
              "jmp " + ins2->label() + bb_list[i]->lblSuffix();//to_string(bb->fallThrough());
            ins.asmIns(jmpLoc);
            ins.isJump(1);
            bb_list[j]->fallThroughIns(ins);
            //addJmpToFallThru(bb_list[j]);
            break;
          }
        }
      }
    }
    if(overlapping) {
      addJmpToFallThru(bb_list[i]);
    }
  }
  vector <BasicBlock *> new_bbs;
  for (auto & bb : bb_list) {
    if(bbs_to_remove.find(bb->start()) == bbs_to_remove.end())
      new_bbs.push_back(bb);
  }
  return new_bbs;
}


vector<BasicBlock *>
Rand::brkBasicBlk(vector <uint64_t> &bigBlks,set <uint64_t> &brkPoints,
    vector <BasicBlock *>bbs) {

  /* Given a set of break points, it checks if a BB already exits for each
   * break point. 
   * If some break point falls within a pre-defined BB, it splits the BB.
   */
  //vector<BasicBlock *> newBBs;
  //DEF_LOG("Breaking basic blocks");

  //set <uint64_t> to_be_processed = brkPoints;
  //unordered_set <uint64_t>

  //while(to_be_processed.size() > 0) {
    //vector<BasicBlock *> newBBs;
    for(auto & start : brkPoints) {
     // if(to_be_processed.find(start) != to_be_processed.end()) {
        //bigBlks.push_back(start);
        //auto it = basicBlkMap_.find(start);
        //if break point is already a basic block start then skip
        //DEF_LOG("Breaking at "<<hex<<start);
        BasicBlock *prevBB = NULL;
        bool brk_found = false;
        for(auto & bb : bbs) {
          //LOG("BB: "<<hex<<bb->start()<<" - "<<bb->end());
          if(bb->start() == start) {
            addJmpToFallThru(prevBB);
            //to_be_processed.erase(start);
            bigBlks.push_back(start);
            brk_found = true;
            break;
          }
          prevBB = bb;
        }
        if(brk_found == false) {
          //DEF_LOG("Could not find break point...looking for BB to split");
          for(auto & bb : bbs) {
            if(bb->start() < start && bb->end() >= start) {
              //DEF_LOG("Splitting BB: "<<hex<<bb->start()<<" at "<<hex<<start);
              BasicBlock *newBB = bb->split(start);
              if(newBB != NULL) {
                addJmpToFallThru(bb);
                bbs.push_back(newBB);
                //to_be_processed.erase(start);
                bigBlks.push_back(start);
              }
              break;
            }
          }
          //DEF_LOG("Sorting bbs");
          sort(bbs.begin(),bbs.end(),compareBB);
          //DEF_LOG("Sorting done");
        }
     // }
    }

 // }
  DEF_LOG("Breaking basic blocks complete");
  return bbs;
}

void
Rand::addTrampForBB(BasicBlock *bb) {
  LOG("Adding tramp for bb: "<<hex<<bb->start());
  bb->addTramp(programEnd_ + 1);
  programEnd_++;
}

void
Rand::addTramps(vector <BasicBlock *> &bbList) {
  //uint64_t tramp_start = programEnd_ + 1;
  vector <BasicBlock *> tramp_bbs;
  for(auto & bb : bbList) {
    if(pointerMap_.find(bb->start()) != pointerMap_.end()) {
      addTrampForBB(bb);
      tramp_bbs.push_back(bb->tramp());
    }
  }
  bbList.insert(bbList.end(),tramp_bbs.begin(),tramp_bbs.end());
}

void
Rand::getFinalBasicBlks(vector <uint64_t> &brkPoints,
				 vector <BasicBlock *> &finalBasicBlks,
				 vector <BasicBlock *> &bbList) {
  /* Given a randomized order of break points(or big block starts), it
   * arranges smaller BBs accordingly.
   */

  //DEF_LOG("Creating final basic block list");
  set <uint64_t> bbSet(brkPoints.begin(), brkPoints.end());
  for(auto & bbStart:brkPoints) {
    LOG("big block: " << hex << bbStart);
    /*
       searches for the current break point in basic block set, adds all
       future basic block till it finds any basic block which is present
       in the set. In this way it maintains order of any basic blocks where
       order is supposed to be maintained.
     */
    stack<uint64_t> callSiteEnd;
    stack<uint64_t> curCallSite;
    BasicBlock *prevBB = NULL;
    for(auto & bb : bbList) {
      if(bb->start() >= bbStart) {
        if(bb->start() != bbStart && bbSet.find(bb->start()) != bbSet.end())
          break;
        else {
          LOG("BB: "<<hex<<bb->start());
          finalBasicBlks.push_back(bb);
        }
        auto callSiteIt = all_call_sites.find(bb->start());
        if(callSiteIt != all_call_sites.end()) {
          curCallSite.push(callSiteIt->first);
          callSiteEnd.push(callSiteIt->second.start
              + callSiteIt->second.length);
          LOG("Call site start: "<<hex<<callSiteIt->first);
        }
        if(prevBB != NULL && callSiteEnd.size() > 0 && bb->start()
            >= callSiteEnd.top()) {
          callSiteEndMap_[prevBB->start()].push_back(curCallSite.top());
          LOG("Call site end: "<<hex<<curCallSite.top()<<" - "<<hex<<prevBB->start());
          curCallSite.pop();
          callSiteEnd.pop();
        }
        prevBB = bb;
      }
    }
    while(curCallSite.size() > 0 && prevBB != NULL) {
      callSiteEndMap_[prevBB->start()].push_back(curCallSite.top());
      curCallSite.pop();
    }
  }
}
