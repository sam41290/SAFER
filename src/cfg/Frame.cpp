#include "Frame.h"
#include "libutils.h"

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

vector <BasicBlock *> 
Frame::getUnknwnCode()
{
  sort(unknwnCodeBBs_.begin (), unknwnCodeBBs_.end (),compareBB);
  return unknwnCodeBBs_;
}

BasicBlock*
Frame::withinBB(uint64_t addrs) {
  //LOG("Within BB for: "<<hex<<addrs);
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

bool
Frame::definiteCode(uint64_t addrs) {
  for(auto & bb : defCodeBBs_)
    if(bb->start() == addrs)
      return true;
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
  for(auto & bb:defCodeBBs_) 
    if(addrs == bb->start())
      return true;
  for(auto & bb:unknwnCodeBBs_)
    if(addrs == bb->start())
      return true;

  return false;
}

BasicBlock *
Frame::splitAndGet(uint64_t addrs) {
  for(auto & bb:defCodeBBs_) {
    uint64_t start = bb->start();
    uint64_t end = bb->boundary();
    if(addrs >= start && addrs < end) {
      //LOG("Within BB: "<<hex<<bb->start());
      BasicBlock * newbb = bb->split(addrs);
      if(newbb != NULL)
        defCodeBBs_.push_back(newbb);
      return newbb;
    }
  }
  for(auto & bb : unknwnCodeBBs_) {
    uint64_t start = bb->start();
    uint64_t end = bb->boundary();

    if(addrs >= start && addrs < end) {
      //LOG("Within BB: "<<hex<<bb->start());
      BasicBlock * newbb = bb->split(addrs);
      if(newbb != NULL) {
        unknwnCodeBBs_.push_back(newbb);
        return newbb;
      }
    }
  }
  return NULL;
}

BasicBlock *
Frame::getBB(uint64_t addrs) {
  for(auto & bb:defCodeBBs_) {
    if(addrs == bb->start())
      return bb;
  }
  for(auto & bb:unknwnCodeBBs_) {
    if(addrs == bb->start())
      return bb;
  }
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
  LOG("Splitting frame: "<<hex<<start_<<" at "<<hex<<addrs);

  splitBBs(addrs,f,true,defCodeBBs_);
  LOG("Splitting def code complete");
  splitBBs(addrs,f,false,unknwnCodeBBs_);

  LOG("Splitting Unknwn code complete");
}

bool
Frame::conflictsCnsrvtvCode(uint64_t addrs) {
  for(auto & bb : defCodeBBs_) {
    uint64_t start = bb->start();
    uint64_t end = bb->boundary();
    if(start <= addrs && end > addrs) {
      if(bb->noConflict(addrs))
        return false;
      else
        return true;
    }
  }
  return false;
}

vector <BasicBlock * >
Frame::conflictingBBs(uint64_t addrs) {
  LOG("getting conflicting bbs: "<<hex<<addrs);
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
      else {
        bb->split(start);
        bb->fallThroughBB(getBB(start));
        //return false;
      }
    }
  }
  return false;
}


void
Frame::removeDuplicates() {
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
}

void
Frame::markAsDefCode(BasicBlock *bb) {
  LOG("Marking as def code BB: "<<hex<<bb->start());
  if(bb->isCode() == false) {
    bb->codeType(code_type::CODE);

    for(auto & bb2 : defCodeBBs_) {
      if(bb->isValidIns(bb2->start())) {
        auto newbb = bb->split(bb2->start());
        bb->fallThroughBB(bb2);
        delete(newbb);
      }
    }

    defCodeBBs_.push_back(bb);
    unknwnCodeBBs_.erase(std::remove(unknwnCodeBBs_.begin(),
          unknwnCodeBBs_.end(), bb), unknwnCodeBBs_.end());
  }
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

