#include "Frame.h"
#include "libutils.h"
#include "PointerAnalysis.h"

using namespace SBI;

bool
compareBB(BasicBlock *A, BasicBlock *B)
{
  return (A->start() < B->start());
}

Frame::Frame (uint64_t p_start, uint64_t p_end, bool p_dummy)
{
  start_ = p_start;
  end_ = p_end;
  dummy_ = p_dummy;
}

vector <BasicBlock *>
Frame::getDefCode()
{
  sort(defCodeBBs_.begin(),defCodeBBs_.end(),compareBB);
  return defCodeBBs_;
}

uint64_t
Frame::firstCodeAddress() {
  if(defCodeBBs_.size() > 0) {
    sort(defCodeBBs_.begin(),defCodeBBs_.end(),compareBB);
    return defCodeBBs_[0]->start();
  }
  return 0;
}

vector <BasicBlock *> 
Frame::getUnknwnCode()
{
  sort(unknwnCodeBBs_.begin (), unknwnCodeBBs_.end (),compareBB);
  return unknwnCodeBBs_;
}

vector <BasicBlock *> 
Frame::getDataInCode()
{
  sort(defDataInCode_.begin (), defDataInCode_.end (),compareBB);
  return defDataInCode_;
}

bool
Frame::isDataInCode(uint64_t addrs) {
  for(auto & bb : defDataInCode_)
    if(addrs >= bb->start() && addrs < bb->boundary())
      return true;
  return false;
}

BasicBlock*
Frame::withinBB(uint64_t addrs) {
  //LOG("Within BB for: "<<hex<<addrs);
  for(auto & bb:defCodeBBs_) {
    if(addrs >= bb->start() && addrs <= bb->end()
       && bb->isValidIns(addrs))
      return bb;
  }
  for(auto & bb:unknwnCodeBBs_)
    if(addrs >= bb->start() && addrs <= bb->end()
       && bb->isValidIns(addrs))
      return bb;
  for(auto & bb:defCodeBBs_) {
    //LOG("BB: "<<hex<<bb->start()<<" - "<<bb->boundary());
    if(addrs >= bb->start() && addrs < bb->boundary())
      return bb;
  }
  for(auto & bb:unknwnCodeBBs_)
    if(addrs >= bb->start() && addrs < bb->boundary())
      return bb;
  return NULL;
}

unordered_map <uint64_t,string>
Frame::allReturnAddresses() {
  unordered_map <uint64_t,string> all_ras;
  for(auto & bb:defCodeBBs_) {
    if(bb->lastIns()->isCall()) {
      auto f = bb->lastIns()->fallThrough();
      auto s = bb->fallSym();
      all_ras[f] = s;
    }
  }
  for(auto & bb:unknwnCodeBBs_) {
    if(bb->lastIns()->isCall()) {
      auto f = bb->lastIns()->fallThrough();
      auto s = bb->fallSym();
      if(all_ras.find(f) == all_ras.end())
        all_ras[f] = s;
    }
  }
  return all_ras;
}

vector <string>
Frame::allReturnSyms() {
  unordered_set <uint64_t> all_ras;
  vector <string> ra_syms;
  for(auto & bb:defCodeBBs_) {
    if(bb->isCall() && bb->fallThrough() != 0 && 
       all_ras.find(bb->fallThrough()) == all_ras.end()) {
      all_ras.insert(bb->fallThrough());
      ra_syms.push_back(bb->fallSym());
    }
  }
  all_ras.clear();
  for(auto & bb:unknwnCodeBBs_) {
    if(bb->isCall() && bb->fallThrough() != 0 &&
       all_ras.find(bb->fallThrough()) == all_ras.end()) {
      all_ras.insert(bb->fallThrough());
      ra_syms.push_back(bb->fallSym());
    }
  }
  return ra_syms;
}

bool
Frame::definiteCode(uint64_t addrs) {
  for(auto & bb : defCodeBBs_) {
    if(bb->start() == addrs)
      return true;
    else if(bb->start() <= addrs && bb->boundary() > addrs && bb->isValidIns(addrs))
      return true;
  }
  return false;
}

bool 
Frame::isValidIns(uint64_t address) {
  for(auto & bb:defCodeBBs_) {
    uint64_t start = bb->start();
    uint64_t end = bb->boundary();
    //LOG("BB:" <<hex<<start);
    if(address >= start && address < end) {
      if(bb->isValidIns(address))
        return true;
    }
  }
  return false;
}

vector <BasicBlock *>
Frame::leaBBs() {
  vector <BasicBlock *> all_leas;
  for(auto & bb:defCodeBBs_) 
    if(bb->isLea())
      all_leas.push_back(bb);
  for(auto & bb:unknwnCodeBBs_)
    if(bb->isLea())
      all_leas.push_back(bb);

  return all_leas;
}

bool 
Frame::bbExists(uint64_t addrs) {
  if(bbSet_.find(addrs) != bbSet_.end())
    return true;
  //for(auto & bb:defCodeBBs_) 
  //  if(addrs == bb->start())
  //    return true;
  //for(auto & bb:unknwnCodeBBs_)
  //  if(addrs == bb->start())
  //    return true;

  return false;
}

BasicBlock *
Frame::splitAndGet(uint64_t addrs) {
  LOG("Splitting and getting: "<<hex<<addrs<<" Function: "<<hex<<start_);
  for(auto & bb:defCodeBBs_) {
    uint64_t start = bb->start();
    if(start == addrs) {
      LOG("Found bb: "<<hex<<start);
      return bb;
    }
    if(start > addrs)
      continue;
    uint64_t end = bb->boundary();
    LOG("BB: "<<hex<<start<<"-"<<end);
    if(end < addrs)
      continue;
    if(addrs >= start && addrs < end) {
      BasicBlock * newbb = bb->split(addrs);
      if(newbb != NULL) { 
        LOG("Returning split bb: "<<hex<<bb->start()<<"->"<<newbb->start());
        addDefCodeBB(newbb);
        //bb->fallThroughBB(getBB(addrs));
        return newbb;
      }
    }
  }
  LOG("Looking in possible code");
  for(auto & bb : unknwnCodeBBs_) {
    uint64_t start = bb->start();
    if(start == addrs) {
      LOG("Found bb: "<<hex<<start);
      return bb;
    }
    if(start > addrs)
      continue;
    uint64_t end = bb->boundary();
    if(end < addrs)
      continue;
    LOG("BB: "<<hex<<start<<"-"<<end);
    if(addrs >= start && addrs < end) {
      BasicBlock * newbb = bb->split(addrs);
      if(newbb != NULL) {
        addUnknwnCodeBB(newbb);
        //bb->fallThroughBB(getBB(addrs));
        return newbb;
      }
    }
  }
  return NULL;
}

BasicBlock *
Frame::getDataBlock(uint64_t addrs) {
  for(auto & bb : defDataInCode_)
    if(addrs == bb->start())
      return bb;
  return NULL;
}

BasicBlock *
Frame::getBB(uint64_t addrs) {
  if(bbSet_.find(addrs) == bbSet_.end())
    return NULL;
  for(auto & bb:defCodeBBs_) {
    if(addrs == bb->start())
      return bb;
  }
  for(auto & bb:unknwnCodeBBs_) {
    if(addrs == bb->start())
      return bb;
  }
  //for(auto & bb : defDataInCode_)
  //  if(addrs == bb->start())
  //    return bb;
  return NULL;
}

void
Frame::splitBBs(uint64_t addrs, Frame *f, bool defCode,
    vector <BasicBlock *> &bblist) {
  vector <BasicBlock *> newbbList;
  sort(bblist.begin(),bblist.end(),compareBB);
  bool splitFound = false;
  for(auto it = bblist.begin(); it != bblist.end(); it++) {
    uint64_t start = (*it)->start();
    uint64_t end = (*it)->boundary();
    if(splitFound) {
      ADDBB(f,*it,defCode);
    }
    else if(start >= addrs) {
      ADDBB(f,*it,defCode);
      splitFound = true;
    }
    else if (addrs >= start && addrs < end) {
      newbbList.push_back(*it);
      BasicBlock * newbb = (*it)->split(addrs);
      if(newbb != NULL) {
        ADDBB(f,newbb,defCode);
        (*it)->fallThroughBB(f->getBB(addrs));
      }
    }
    else {
      //LOG("Stays in old function: "<<hex<<(*it)->start());
      newbbList.push_back(*it);
    }
  }
  if(defCode)
    defCodeBBs_ = newbbList;
  else
    unknwnCodeBBs_ = newbbList;
  LOG("BB split complete");
}

void
Frame::splitFrame(uint64_t addrs, Frame *f) {
  //DEF_LOG("Splitting frame: "<<hex<<start_<<" at "<<hex<<addrs);

  splitBBs(addrs,f,true,defCodeBBs_);
  //DEF_LOG("Splitting def code complete");
  splitBBs(addrs,f,false,unknwnCodeBBs_);

  //DEF_LOG("Splitting Unknwn code complete");
}

bool
Frame::conflictsCnsrvtvCode(uint64_t addrs) {
  for(auto & bb : defCodeBBs_) {
    uint64_t start = bb->start();
    uint64_t end = bb->boundary();
    if(start <= addrs && end > addrs) {
      if(bb->noConflict(addrs)) {
        return false;
      }
      else {
        LOG("address: "<<hex<<bb->start()<<" conflicts def code");
        return true;
      }
    }
  }
  return false;
}

vector <BasicBlock * >
Frame::conflictingBBs(uint64_t addrs) {
  LOG("getting conflicting bbs: "<<hex<<addrs<<" frame: "<<hex<<start_);
  vector <BasicBlock *> bb_list;
  for(auto & bb : defCodeBBs_) {
    if(bb->start() < addrs && bb->boundary() > addrs &&
       bb->noConflict(addrs) == false)
      bb_list.push_back(bb);
  }
  for(auto & bb : unknwnCodeBBs_) {
    if(bb->start() < addrs && bb->boundary() > addrs &&
       bb->noConflict(addrs) == false)
      bb_list.push_back(bb);
  }
  return bb_list;
}

bool
Frame::withinDefCode(uint64_t addrs) {
  for(auto & bb : defCodeBBs_) {
    uint64_t start = bb->start();
    uint64_t end = bb->boundary();
    if(start <= addrs && end > addrs) 
      return true;
  }
  return false;
}

bool
Frame::misaligned(uint64_t start) {
  LOG("Checking misalignment for "<<hex<<start);
  for(auto & bb : defCodeBBs_) {
    if(start > bb->start() && start < bb->boundary()) {
      if(bb->getIns(start) == NULL) {
        LOG("Misaligned with defcode: "<<hex<<bb->start());
        return true;
      }
      else {
        return false;
      }
    }
  }
  for(auto & bb : unknwnCodeBBs_) {
    if(start > bb->start() && start < bb->boundary()) {
      LOG("Within BB: "<<hex<<bb->start());
      if(bb->getIns(start) == NULL) {
        LOG("Misaligned with possible code: "<<bb->start());
        return true;
      }
      //else {
      //  if(bb->start() == 0x40f856) {
      //    DEF_LOG("Splitting due to misalignment!!");
      //  }
      //  bb->split(start);
      //  bb->fallThroughBB(getBB(start));
      //  //return false;
      //}
    }
  }
  return false;
}


void
Frame::removeDuplicates() {
  //DEF_LOG("Removing duplicates for fn: "<<hex<<start_);
  sort(unknwnCodeBBs_.begin (), unknwnCodeBBs_.end (),compareBB);
  vector<BasicBlock *> newBBs;
  BasicBlock *prevBB = NULL;
  for(auto & bb : unknwnCodeBBs_) {
    if(prevBB == NULL)
      newBBs.push_back(bb);
    else if(prevBB->start() != bb->start())
      newBBs.push_back(bb);
    else
      LOG("Duplicate BB found for address: "<<hex<<bb->start());
    prevBB = bb;
  }
  unknwnCodeBBs_ = newBBs;
  //DEF_LOG("Removing duplicates complete for fn: "<<hex<<start_);
}

void
Frame::markAsDefCode(BasicBlock *bb) {
  if(bb->isCode() == false) {
    //DEF_LOG("Marking as def code BB: "<<hex<<bb->start());
    bb->codeType(code_type::CODE);

    for(auto & bb2 : defCodeBBs_) {
      if(bb2->start() == bb->start())
        return;
      if(bb->isValidIns(bb2->start())) {
        //DEF_LOG("Splitting bb: "<<hex<<bb->start()<<" at "<<hex<<bb2->start());
        //if(bb2->start() == 0x40f856) {
        //  DEF_LOG("Splitting while marking as def code");
        //}
        bb->splitNoNew(bb2->start());
        bb->fallThroughBB(bb2);
      }
    }

    defCodeBBs_.push_back(bb);
    unknwnCodeBBs_.erase(std::remove(unknwnCodeBBs_.begin(),
          unknwnCodeBBs_.end(), bb), unknwnCodeBBs_.end());
    defDataInCode_.erase(std::remove(defDataInCode_.begin(),
          defDataInCode_.end(), bb), defDataInCode_.end());
  }
  //DEF_LOG("Def code bb added");
}

void
Frame::markAsDefData(BasicBlock *bb) {
  //DEF_LOG("Marking as def data BB: "<<hex<<bb->start());
  bb->codeType(code_type::DATA);
  defDataInCode_.push_back(bb);
  unknwnCodeBBs_.erase(std::remove(unknwnCodeBBs_.begin(),
        unknwnCodeBBs_.end(), bb), unknwnCodeBBs_.end());
}

void
Frame::removeBB(BasicBlock *bb) {
  LOG("Removing bb: "<<hex<<bb->start()<<" "<<bb<<" from frame: "<<hex<<start_);

  for(auto & bb2 : unknwnCodeBBs_)
    if(bb->start() == bb2->start()) {
      unknwnCodeBBs_.erase(std::remove(unknwnCodeBBs_.begin(),
            unknwnCodeBBs_.end(), bb2), unknwnCodeBBs_.end());
      break;
    }

  for(auto & bb2 : defCodeBBs_)
    if(bb->start() == bb2->start()) {
      defCodeBBs_.erase(std::remove(defCodeBBs_.begin(),
            defCodeBBs_.end(), bb2), defCodeBBs_.end());
      break;
    }
  /*
  for(auto & bb2 : unknwnCodeBBs_)
    if(bb2->fallThrough() == bb->start()) {
      bb->fallThrough(0);
    }

  for(auto & bb2 : defCodeBBs_)
    if(bb2->fallThrough() == bb->start()) {
      bb->fallThrough(0);
    }
    */
}

uint64_t
Frame::nxtDefCode(uint64_t addrs) {
  uint64_t nxtCode = INT_MAX;
  for(auto & bb:defCodeBBs_) {
    if(bb->start() > addrs && bb->start() < nxtCode)
      nxtCode = bb->start();
  }
  if(nxtCode == INT_MAX)
    return 0;
  else
    return nxtCode;
}

void
Frame::linkCFToJumpTable(JumpTable *j, uint64_t ins_loc) {
  for(auto & bb2 : defCodeBBs_) {
    if(bb2->end() == ins_loc) {
      j->cfBB(bb2);
      j->cfIns(bb2->lastIns());
      DEF_LOG("Removing AT instrumentation for: "<<hex<<bb2->start()<<"->"<<hex<<ins_loc<<" Jump table: "<<hex<<j->location());
      bb2->addrTransMust(false);
    }
      //bb2->jTable(j);
  }
  for(auto & bb2 : unknwnCodeBBs_) {
    if(bb2->end() == ins_loc) {
      j->cfBB(bb2);
      j->cfIns(bb2->lastIns());
      DEF_LOG("Removing AT instrumentation for: "<<hex<<bb2->start()<<"->"<<hex<<ins_loc<<" Jump table: "<<j->location());
      //DEF_LOG("Removing AT instrumentation for: "<<hex<<bb2->start()<<"->"<<hex<<ins_loc);
      bb2->addrTransMust(false);
    }
      //bb2->jTable(j);
  }
}
vector <BasicBlock *>
Frame::allIndrctTgt(uint64_t ins_loc) {
  vector <BasicBlock *> all_inds;
  for(auto & bb2 : defCodeBBs_) {
    if(bb2->end() == ins_loc) {
      auto inds = bb2->indirectTgts();
      all_inds.insert(all_inds.end(), inds.begin(), inds.end());
    }
  }
  for(auto & bb2 : unknwnCodeBBs_) {
    if(bb2->end() == ins_loc) {
      auto inds = bb2->indirectTgts();
      all_inds.insert(all_inds.end(), inds.begin(), inds.end());
    }
  }
  return all_inds;
}

void
Frame::addIndrctTgt(uint64_t ins_loc, BasicBlock *tgt) {
  for(auto & bb2 : defCodeBBs_) {
    if(bb2->end() == ins_loc) {
      bb2->addIndrctTgt(tgt);
    }
  }
  for(auto & bb2 : unknwnCodeBBs_) {
    if(bb2->end() == ins_loc) {
      bb2->addIndrctTgt(tgt);
    }
  }
}

vector <pair <uint64_t, uint64_t>>
Frame::gaps() {
  auto bb_list = defCodeBBs_;
  bb_list.insert(bb_list.end(), unknwnCodeBBs_.begin(), unknwnCodeBBs_.end());
  sort(bb_list.begin(),bb_list.end(),compareBB);
  
  uint64_t prev_bb_end = 0;
  vector <pair <uint64_t, uint64_t>> all_gaps;
  for(auto & bb : bb_list) {
    if(prev_bb_end != 0) {
      if((bb->start() - prev_bb_end) > 10)
        all_gaps.push_back(make_pair(prev_bb_end,bb->start()));
    }
    prev_bb_end = bb->boundary();
  }
  return all_gaps;
}

vector <BasicBlock *>
Frame::allBBs() {
  //DEF_LOG("getting all bbs for fn "<<hex<<start_);
  auto bb_list = defCodeBBs_;
  //for(auto & bb : unknwnCodeBBs_)
  //  if(PointerAnalysis::codeByProperty(bb))
  //    bb_list.push_back(bb);
  bb_list.insert(bb_list.end(), unknwnCodeBBs_.begin(), unknwnCodeBBs_.end());
  sort(bb_list.begin(),bb_list.end(),compareBB);
  return bb_list;
}

