#include "CfgElems.h"

using namespace SBI;


bool
CfgElems::isString(uint64_t addrs) {
  //First check within RX sections

  for(auto & sec : rxSections_) {
    if(addrs >= sec.vma && addrs < (sec.vma + sec.size)) {
      return utils::is_string(sec.vma,sec.vma + sec.size,addrs,exePath_);
    }
  }
  for(auto & sec : rwSections_) {
    if(addrs >= sec.vma && addrs < (sec.vma + sec.size)) {
      return utils::is_string(sec.vma,sec.vma + sec.size,addrs,exePath_);
    }
  }
  for(auto & sec : roSections_) {
    if(addrs >= sec.vma && addrs < (sec.vma + sec.size)) {
      return utils::is_string(sec.vma,sec.vma + sec.size,addrs,exePath_);
    }
  }
  return false;
}

bool
CfgElems::validRead(Pointer *ptr) {
  if(ptr->symbolizable(SymbolizeIf::RLTV)) {
    vector<uint64_t> access_points = ptr->storages(SymbolType::RLTV);
    for(auto p : access_points) {
      //LOG("Accessing ins: "<<hex<<p);
      auto bb = withinBB(p);
      if(bb != NULL && bb->isCode()) {
        auto ins = bb->getIns(p);
        if(ins != NULL) {
          string asm_ins = ins->asmIns();
          int rip_pos = asm_ins.find("(%rip)");
          if(rip_pos != string::npos) {
            //int comma_pos = asm_ins.rfind(",",rip_pos);
            //if(comma_pos == string::npos || comma_pos > rip_pos) {
              if(ins->isLea() || ins->isIndirectCf() || asm_ins.find("mov") != string::npos
                 || asm_ins.find("cmp") != string::npos)
                return true;
            //}
          }
        }
      }
    }
  }
  else if(ptr->symbolizable(SymbolizeIf::IMMOPERAND))
    return true;

  return false;
}

bool
CfgElems::validPtrToPtr(uint64_t ptr) {
  auto bb = withinBB(ptr);
  if(bb == NULL || bb->isCode() == false) {
    for(auto & p : pointerMap_) {
      if(p.second->type() == PointerType::CP &&
         p.second->symbolizable(SymbolizeIf::SYMLOCMATCH,ptr)) {
        LOG("Valid ptr to code ptr: "<<hex<<ptr);
        return true;
      }
    }
  }
  return false;
}

bool
CfgElems::validPtrToPtrArray(uint64_t ptr, uint64_t end) {
  LOG("Checking if pointer to symbol array: "<<hex<<ptr);
  uint64_t entry_sz = 8;
  if((end - ptr) % entry_sz == 0) {
    return true;
    ptr += entry_sz;
  }
  else {
    LOG("Entry size not aligned with end: "<<hex<<end);
    return false;
  }
  while(ptr < end) {
    if(validPtrToPtr(ptr) == false) {
      LOG("invalid symbol at: "<<hex<<ptr);
      return false;
    }
    ptr += entry_sz;
  }
  return true;
}

bool
CfgElems::withinSymbolArray(uint64_t addrs) {
  LOG("Checking if within symbol array: "<<hex<<addrs);
  auto it = pointerMap_.lower_bound(addrs);
  if(it != pointerMap_.end() && it->first != addrs &&
     abs(int((int)it->first - (int)addrs)) < 4)
    return false;
  if(validPtrToPtr(addrs - 8) && validPtrToPtr(addrs + 8))
    return true;
  if(validPtrToPtr(addrs - 8) && validPtrToPtr(addrs - 16))
    return true;
  if(validPtrToPtr(addrs + 8) && validPtrToPtr(addrs + 16))
    return true;
  return false;
}

bool
CfgElems::validPtrAccess(Pointer *ptr, uint64_t ptr_loc) {
  if((ptr->type() != PointerType::CP && conflictsDefCode(ptr->address()) == false)
     && (ptr_loc == ptr->address() || validPtrToPtrArray(ptr->address(),ptr_loc))
     && validRead(ptr))
    return true;
  return false;
}

bool
CfgElems::accessConflict(uint64_t addrs) {
  LOG("Checking access conflict for "<<hex<<addrs);
  auto it = pointerMap_.lower_bound(addrs);
  if(it == pointerMap_.end()) {
    it = prev(it);
    LOG("Possible access point: "<<hex<<it->first<<" "<<(int)it->second->type());
    if(validPtrAccess(it->second,addrs))
      return false;
    else
      return true;
  }
  else if(it->first != addrs) {
    if(abs(int((int)it->first - (int)addrs)) < 4) {
      LOG("Access to middle: "<<hex<<it->first);
      return true;
    }
    it = prev(it);
    LOG("Possible access point: "<<hex<<it->first<<" "<<(int)it->second->type());
    if(validPtrAccess(it->second,addrs))
      return false;
    else
      return true;;
  }
  else if(it->first == addrs) {
    LOG("Possible access point: "<<hex<<it->first<<" "<<(int)it->second->type());
    if(validPtrAccess(it->second,addrs))
      return false;
    else
      return true;
  }
  return false;
}

void
CfgElems::markAsDefCode(uint64_t addrs) {
  auto bb = getBB(addrs);
  if(bb == NULL) {
    LOG("No BB for address: "<<hex<<addrs);
    exit(0);
  }
  auto fn = is_within(bb->start(),funcMap_);
  if(fn == funcMap_.end()) {
    LOG("No function for BB: "<<hex<<addrs);
    exit(0);
  }
  fn->second->markAsDefCode(bb);
}

bool
CfgElems::conflictsDefCode(uint64_t addrs) {
  auto fn = is_within(addrs, funcMap_);
  if(fn == funcMap_.end())
    return false;
  return fn->second->conflictsCnsrvtvCode(addrs);
}

bool
CfgElems::zeroDefCodeConflict(vector <BasicBlock *> &bb_list) {
  for(auto & bb : bb_list) {
    if(bb->isCode() == false && (conflictsDefCode(bb->start()) ||
          conflictsDefCode(bb->boundary())))
      return false;
  }
  return true;
}


void
CfgElems::createFuncFrPtr(Pointer * ptr) {
  if(INVALID_CODE_PTR(ptr->address()) || ptr->source() == PointerSource::EH)
    return;
  uint64_t address = ptr->address();
  //LOG("Creating function for pointer "<<hex<<address);
  auto fn = is_within(address, funcMap_);
  LOG("Is within: "<<hex<<fn->first);
  if(fn == funcMap_.end() || 
    (address != fn->first && address >= fn->second->end() 
     && ptr->source() != PointerSource::EXTRA_RELOC_PCREL)) {
    
    LOG("Function doesn't exist..creating a new one");
    Function *f = new Function(address,0,true);
    if(ptr->type() == PointerType::CP)
      f->addEntryPoint(address);
    else
      f->addProbableEntry(address);

    funcMap_[address] = f;
  }
  else {
    if(ptr->type() == PointerType::CP)
      fn->second->addEntryPoint(address);
    else
      fn->second->addProbableEntry(address);
  }
}


bool
CfgElems::withinCodeSec(uint64_t addrs) {
  for(auto & sec : rxSections_) {
    if(addrs >= sec.vma && addrs < (sec.vma + sec.size) 
        && sec.sec_type == section_types::RX) {
      //LOG(hex<<addrs<<" Within code section: "<<hex<<sec.vma<<" - "<<sec.vma + sec.size);
      return true;
    }
  }
  return false;
}

bool
CfgElems::validEntry(uint64_t entry) {
  auto fn = is_within(entry,funcMap_);
  if(fn == funcMap_.end())
    return false;
  return fn->second->validEntry(entry);
}

BBType
CfgElems::getBBType(uint64_t bbAddrs) {
  //LOG("Getting bb type: "<<hex<<bbAddrs);
  auto fn = is_within(bbAddrs,funcMap_);
  BasicBlock *bb = fn->second->getBB(bbAddrs);
  if(bb != NULL)
    return bb->type();
  return BBType::NA;
}

BasicBlock *
CfgElems::getBB(uint64_t addrs) {
  //LOG("Getting BB: "<<hex<<addrs);
  auto fn = is_within(addrs,funcMap_);
  if(fn == funcMap_.end())
    return NULL;
  //LOG("Within function: "<<hex<<fn->first);
  return fn->second->getBB(addrs);
}

BasicBlock *
CfgElems::withinBB(uint64_t addrs) {
  auto fn = is_within(addrs,funcMap_);
  if(fn == funcMap_.end())
    return NULL;
  return fn->second->withinBB(addrs);
}

void
CfgElems::addBBtoFn(BasicBlock *bb, PointerSource t) {
  uint64_t addrs = bb->start();
  auto fn = is_within(addrs,funcMap_);
  Function *curFn = fn->second;
  fn++;
  if(fn != funcMap_.end()) {
    if(bb->boundary() >= fn->first) {
      vector <Instruction *> insLst = bb->insList();
      for(auto ins : insLst) {
        uint64_t loc = ins->location();
        if(loc >= fn->first) {
          BasicBlock *newbb = bb->split(loc);
          bb->fallThroughBB(NULL);
          delete(newbb);
          //bb->fallThrough(0);
          //ADDBBTOFN(newbb,fn->second,t);
          break;
        }
      }
    }
  }
  ADDBBTOFN(bb,curFn,t);
  LOG("BB "<<hex<<addrs<<" added to function "<<hex<<curFn->start()
      <<" Type: "<<(int)(bb->isCode())<<" "<<bb);
}

void
CfgElems::removeBB(BasicBlock *bb) {
  LOG("Removing BB: "<<hex<<bb->start()<<" "<<hex<<bb);
  auto fn = is_within(bb->start(),funcMap_);
  fn->second->removeBB(bb);
}

uint64_t 
CfgElems::isValidRoot(uint64_t addrs, code_type t) {

  /* Takes an address and returns a gap/undiscovered code region starting from
   * that address.
   * end of the gap can be next basic block start or next pointer.
   * returns a 0 if a basic block already exists or the address conflicts with
   * definite code.
   */
  auto fn = is_within(addrs,funcMap_);
  if(fn == funcMap_.end())
    return 0;
  //LOG("Within function: "<<hex<<fn->first);
  BasicBlock *bb = fn->second->getBB(addrs);
  if(bb == NULL) {
    if(t == code_type::CODE || 
        fn->second->misaligned(addrs) == false) {

      //Try to split an existing BB
      BasicBlock *bb = fn->second->splitAndGet(addrs);

      if(bb != NULL) {
        LOG("returning splitted BB");
        return bb->start();
      }
      else {
        return 1; //No BB found, Disassemble.
      }
    }
    //else if(t == code_type::JUMPTABLE && fn->second->misaligned(addrs)) {
    //  LOG("Possibly invalid jump table target. Rejecting "<<hex<<addrs);
    //  return 0;
    //}
    else
      return 1; //If misaligned and code type is unknown, Disassemble
  }
  else
    return bb->start();
 
  return 1;
}

uint64_t CfgElems::nextPtr(uint64_t addrs) {
  //Returns the next pointer, given the address

  uint64_t chunk_end = 0;
  auto fn = funcMap_.lower_bound(addrs);
  if(fn->first == addrs)
    fn++;
  if(fn == funcMap_.end())
    chunk_end = codeSegEnd_;
  else
    chunk_end = fn->second->firstEntryPoint();
  if(chunk_end == 0) {
    auto it = pointerMap_.lower_bound(addrs);
    if(it->first == addrs)
      it++;
    if(it != pointerMap_.end() && it->first < codeSegEnd_)
      chunk_end = it->first;
    else
      chunk_end = codeSegEnd_;
  }
  return chunk_end;
}

void
CfgElems::createFn(bool is_call, uint64_t target_address,uint64_t ins_addrs,
    code_type t)
{
  if(INVALID_CODE_PTR(target_address))
    return;
  LOG("Creating function for address: " <<hex<<target_address);
  if(target_address != 0) {
    if(is_call) {
      auto f_it = is_within(target_address, funcMap_);
      if(f_it == funcMap_.end())
        return;
      uint64_t end = f_it->second->end();
      LOG("Previous function: " <<hex <<f_it->first <<" - " <<end);
      if(f_it->first == target_address) {
        LOG("Function exists");
        ADDENTRY(f_it->second,target_address,t);
        return;
      }
      else if(end > target_address) {
        //Multiple entry function.
        //Function already exists. Just add a new entry point.

        LOG("call target entry point added");
        ADDENTRY(f_it->second,target_address,t);
      }
      else {
        Function *f = f_it->second->splitFunction(target_address);
        ADDENTRY(f,target_address,t);
        funcMap_[target_address] = f;
        LOG("call target function created");
      }
    }
    else {
      //tail call handling
      //Check if the jump target goes out of current function's body. If
      //yes, create a new function.

      auto f_it = is_within(ins_addrs, funcMap_);
      if(f_it == funcMap_.end())
        return;
      LOG("Jmp ins function: "<<hex<<f_it->first);
      auto next_f_it = next_iterator(ins_addrs, funcMap_);
      if(next_f_it == funcMap_.end())
        return;
      LOG("Next function: "<<hex<<next_f_it->first);
      if(target_address <f_it->first || target_address>= next_f_it->first) {
        auto f_it2 = is_within(target_address, funcMap_);
        if(f_it2 == funcMap_.end())
          return;
        uint64_t end = f_it2->second->end();
        LOG("Previous function: " <<hex <<f_it2->first <<" - " <<end);
        if(f_it2->first == target_address) {
    	  LOG("Jump target function exists");
          ADDENTRY(f_it2->second,target_address,t);
    	  return;
    	}
        else if(end > target_address) {
    	  //Multiple entry function.
    	  //Function already exists. Just add a new entry point.

    	  LOG("jump target entry point added");
          ADDENTRY(f_it2->second,target_address,t);
    	}
        else {
    	  LOG("jump target function created");
    	  Function *f = f_it2->second->splitFunction(target_address);
          ADDENTRY(f,target_address,t);
    	  funcMap_[target_address] = f;
    	}

      }
    }
  }
  LOG("Function created");
  return;
}

BasicBlock *
CfgElems::readBB(ifstream & ifile) {
  string str;
  uint64_t start = 0, end = 0, target = 0, fall = 0;
  BBType t = BBType::NA;
  BBType call_type = BBType::NA;
  code_type ctype = code_type::UNKNOWN;
  vector <Instruction *> ins_list;
  vector <uint64_t> ind_tgts;
  while(getline(ifile,str)) {
    vector<string> words = utils::split_string(str,' ');
    if(words[0] == "start") {
      start = stoll(words[1]);
      end = stoll(words[2]);
      LOG("Reading BB: "<<hex<<start<<"-"<<hex<<end);
    }
    else if(words[0] == "type") {
      t = (BBType)(stoi(words[1]));
    }
    else if(words[0] == "calltype") {
      call_type = (BBType)(stoi(words[1]));
    }
    else if(words[0] == "codetype") {
      ctype = (code_type)(stoi(words[1]));
    }
    else if(words[0] == "target")
      target = stoll(words[1]);
    else if(words[0] == "fall")
      fall = stoll(words[1]);
    else if(words[0] == "indrc_tgt") {
      uint64_t addrs = stoll(words[1]);
      ind_tgts.push_back(addrs);
    }
    else if(words[0] == "ins") {
      uint64_t loc = stoll(words[1]);
      uint64_t size = stoll(words[2]);
      string ins = "";
      string mne = words[3];
      string operand = "";
      for(unsigned int i = 3; i < words.size(); i++) {
        ins += words[i] + " ";
      }
      for(unsigned int i = 4; i < words.size(); i++) {
        operand += words[i] + " ";
      }
      Instruction * in = new Instruction();
      in->location(loc);
      in->label("." + to_string(loc));
      in->op1(operand);
      in->insSize(size);
      in->chkConstOp();
      //in->isRltvAccess();
      int pos = operand.find("(%rip)");
      if(pos != string::npos) {
        in->setRltvAccess(true);
        int offset_pos = operand.rfind(".",pos);
        if(offset_pos != string::npos) {
          string off = operand.substr(offset_pos + 1, pos - offset_pos - 1);
          uint64_t rip_rltv_tgt = stoull(off,0,10);
          in->ripRltvOfft(rip_rltv_tgt);
        }
        if(mne.find("lea") != string::npos)
          in->isLea(true);
      }
      in->asmIns(ins);
      set <string> cf_ins_set = utils::get_cf_ins_set();
      set <string> uncond_cf_ins_set = utils::get_uncond_cf_ins_set();
      if(cf_ins_set.find(mne) != cf_ins_set.end()) {
        in->isJump(true);
      }
      if(uncond_cf_ins_set.find(mne) != uncond_cf_ins_set.end())
        in->isUnconditionalJmp(true);
      if(mne.find("call") != string::npos)
        in->isCall(true);

      if(mne.find("ret") != string::npos) {
        in->isFuncExit(true);
        in->isJump(true);
        in->isUnconditionalJmp(true);
      }
      else if(in->isJump() && operand.find("*") == string::npos) {
        LOG("Parsing jump target: "<<ins);
        long unsigned int dot_pos = operand.find(".");
        if(dot_pos != string::npos) {
          string tgt = operand.replace(dot_pos,1,"");
          in->target(stoll(tgt));
        }
      }

      ins_list.push_back(in);
      if(loc == end)
        break;
    }
  }
  BasicBlock *bb = new
    BasicBlock(start,end,PointerSource::NONE,PointerSource::NONE,ins_list);
  bb->target(target);
  bb->fallThrough(fall);
  bb->indTgtAddrs(ind_tgts);
  bb->type(t);
  bb->callType(call_type);
  bb->codeType(ctype);
  return bb;
}

void
CfgElems::readIndrctTgts(BasicBlock *bb, uint64_t fn_addrs) {
  JumpTable j;
  bool indrct_tgt = false;
  vector <uint64_t> ind_tgts = bb->indTgtAddrs();
  for(auto & addr : ind_tgts) {
    indrct_tgt = true;
    auto tgtbb = getBB(addr);
    if(tgtbb != NULL) {
      bb->addIndrctTgt(tgtbb);
      j.addTarget(addr);
      j.addTargetBB(tgtbb);
      ADDPOINTER(addr,PTRTYPE(tgtbb->codeType()),PointerSource::JUMPTABLE,bb->start());
    }
  }
  if(indrct_tgt) {
    j.function(fn_addrs);
    jumpTable(j);
  }
}

void
CfgElems::readCfg() {
  ifstream ifile;
  ifile.open("tmp/cfg/functions.lst");
  string str;
  while(getline(ifile,str)) {
    Function *cur_fn = NULL;
    ifstream fnfile;
    fnfile.open("tmp/cfg/" + str + ".fn");
    string fndata;
    while(getline(fnfile,fndata)) {
      vector<string> words = utils::split_string(fndata,' ');
      if(words[0] == "start") {
        uint64_t start = stoll(words[1]);
        uint64_t end = stoll(words[2]);
        LOG("Reading function: "<<hex<<start);
        Function *f = new Function(start,end,true);
        funcMap_[start] = f;
        cur_fn = f;
      }
      else if(words[0] == "def_entry" && cur_fn != NULL) {
        uint64_t entry = stoll(words[1]);
        cur_fn->addEntryPoint(entry);
        LOG("Definite entry: "<<hex<<entry);
        //ADDPOINTERWITHROOT(entry, PointerType::CP,
        //    PointerSource::NONE,PointerSource::NONE);
      }
      else if(words[0] == "psbl_entry" && cur_fn != NULL) {
        uint64_t entry = stoll(words[1]);
        cur_fn->addProbableEntry(entry);
        LOG("Possible entry: "<<hex<<entry);
        //ADDPOINTERWITHROOT(entry, PointerType::UNKNOWN,
        //    PointerSource::NONE,PointerSource::NONE);
      }
      else if(words[0] == "def_bb" && cur_fn != NULL) {
        BasicBlock *bb = readBB(fnfile);
        //bb->isCode(true);
        if(bb != NULL)
          cur_fn->addDefCodeBB(bb);
      }
      else if(words[0] == "psbl_bb" && cur_fn != NULL) {
        BasicBlock *bb = readBB(fnfile);
        //bb->isCode(false);
        if(bb != NULL)
          cur_fn->addUnknwnCodeBB(bb);
      }
    }
    fnfile.close();
  }
  ifile.close();
  //Adding indirect targets
  for(auto & fn : funcMap_) {
    vector <BasicBlock *>defBB = fn.second->getDefCode();
    for(auto & bb : defBB)
      readIndrctTgts(bb,fn.first);
    vector <BasicBlock *>psblBB = fn.second->getUnknwnCode();
    for(auto & bb : psblBB)
      readIndrctTgts(bb,fn.first);
  }

  //Reading pointers
  LOG("Reading pointers");
  uint64_t val = 0;
  PointerSource src = PointerSource::NONE, rootsrc = PointerSource::NONE;
  PointerType type = PointerType::UNKNOWN;
  ifile.open("tmp/cfg/pointers.lst");
  while(getline(ifile,str)) {
    vector<string> words = utils::split_string(str,' ');
    if(words[0] == "pointer") {
      LOG("Pointer: "<<str);
      val = stoll(words[1]);
      src = (PointerSource)stoi(words[2]);
      rootsrc = (PointerSource)stoi(words[3]);
      type = (PointerType)stoi(words[4]);
      ADDPOINTERWITHROOT(val,type,src,rootsrc,0);
    }
    else if(words[0] == "symcandidate") {
      LOG("Symbol: "<<str);
      uint64_t location = stoll(words[1]);
      SymbolType symtyp = (SymbolType)stoi(words[2]);
      bool symbolize = (bool)stoi(words[3]);
      Symbol s(location,symtyp);
      s.symbolize(symbolize);
      pointerMap_[val]->symCandidate(s);
    }
  }
  ifile.close();
}
void 
CfgElems::dump() {
  ofstream ofile;
  ofile.open("tmp/cfg/functions.lst");
  for(auto & fn : funcMap_) {
    fn.second->dump();
    ofile<<dec<<fn.second->start()<<endl;
  }
  ofile.close();

  ofile.open("tmp/cfg/pointers.lst");
  for(auto & ptr : pointerMap_) {
    ptr.second->dump(ofile);
  }
  ofile.close();
}

void
CfgElems::printDeadCode() {
  string key("/");
  size_t found = exePath_.rfind(key);
  string file_name = exePath_.substr(found + 1);
  string input_file_name = "tmp/" + file_name + "_deadcode.s";
  string psbl_jmp_tbl = "tmp/" + file_name + "_jmptbl.s";
  ofstream ofile1, ofile2;
  ofile1.open(input_file_name);
  ofile2.open(psbl_jmp_tbl);
  for(auto fn : funcMap_) {
    vector <BasicBlock *> bbList = fn.second->getDefCode();
    bool deadcode = false;
    for(auto & bb : bbList) {
      if(bb->source() == PointerSource::SYMTABLE ||
         bb->rootSrc() == PointerSource::SYMTABLE || deadcode) {
        if(deadcode == false)
          deadcode = true;
        vector <string> all_orig_ins = bb->allAsm();
        for(string & asm_ins:all_orig_ins)
          ofile1 <<asm_ins <<endl;
      }
      else if(bb->source() == PointerSource::JUMPTABLE ||
         bb->source() == PointerSource::EXTRA_RELOC_PCREL ||
         bb->rootSrc() == PointerSource::JUMPTABLE ||
         bb->rootSrc() == PointerSource::EXTRA_RELOC_PCREL) {
        
        vector <string> all_orig_ins = bb->allAsm();
        
        for(string & asm_ins:all_orig_ins) {
          ofile2 <<asm_ins <<endl;
        }
      }
      else if (bb->source() == PointerSource::DEBUGINFO ||
         bb->rootSrc() == PointerSource::DEBUGINFO) {
        vector <string> all_orig_ins = bb->allAsm();
        for(string & asm_ins:all_orig_ins)
          ofile1 <<asm_ins <<endl;
      }
      if(deadcode == false) {
        unordered_set <BasicBlock *> ind_bbs = bb->indirectTgts();
        for(auto & ind_bb : ind_bbs) {
          //vector<vector<BasicBlock *>> psbl_bb_seq = bbSeq(ind_bb);
          vector <BasicBlock *> lst = bbSeq(ind_bb);
          //for(auto & lst : psbl_bb_seq) {
            for(auto & bb2 : lst) {
              vector <string> all_orig_ins = bb2->allAsm();

              for(string & asm_ins:all_orig_ins) {
                ofile2 <<asm_ins <<endl;
              }
            }
          //}
        }
      }
    }
  }
  ofile1.close();
  ofile2.close();
}

void
CfgElems::printOriginalAsm() {
  //To be used for debugging purpose
  string key("/");
  size_t found = exePath_.rfind(key);
  string file_name = exePath_.substr(found + 1);
  string input_file_name1 = "tmp/" + file_name + "_defcode.s";
  string input_file_name2 = "tmp/" + file_name + "_gap.s";
  string input_file_name3 = "tmp/" + file_name + "_data_as_code.s";

  ofstream ofile1, ofile2, ofile3;
  ofile1.open(input_file_name1);
  ofile2.open(input_file_name2);
  ofile3.open(input_file_name3);

  for(auto & fn : funcMap_) {
    vector<BasicBlock *> defBBs = fn.second->getDefCode();
    for(auto & bb : defBBs) {
      vector <string> all_orig_ins = bb->allAsm();
      for(string asm_ins:all_orig_ins)
        ofile1 <<asm_ins <<endl;
    }
    vector<BasicBlock *>gapBB = fn.second->getUnknwnCode();
    for(auto & bb : gapBB) {
      vector <string> all_orig_ins = bb->allAsm();
      for(string asm_ins:all_orig_ins)
        ofile2 <<asm_ins <<endl;
    }
    set <uint64_t> psbl_entries = fn.second->probableEntry();
    for(auto & entry : psbl_entries) {
      auto ptr = pointerMap_.find(entry);
      if(ptr != pointerMap_.end() && ptr->second->type() == PointerType::DP) {
        auto bb = getBB(entry);
        if(bb != NULL && bb->isCode()) {
          vector <BasicBlock *> lst = bbSeq(bb);
          for(auto & bb2 : lst) {
            if(bb2->isCode()) {
              vector <string> all_orig_ins = bb2->allAsm();

              for(string & asm_ins:all_orig_ins) {
                ofile3 <<asm_ins <<endl;
              }
            }
          }
        }
      }
    }
  }

  ofile1.close();
  ofile2.close();
  ofile3.close();

}

bool 
CfgElems::withinRoSection(uint64_t addrs) {
  for(section & sec : rxSections_) {
    if(sec.sec_type == section_types::RONLY && sec.vma <= addrs && 
        (sec.vma + sec.size) > addrs) {
      return true;
    }
  }
  return false;
}


bool 
CfgElems::isMetadata(uint64_t addrs) {
  for(section & sec : rxSections_) {
    if(sec.vma <= addrs && (sec.vma + sec.size) > addrs
       && sec.is_metadata) {
      return true;
    }
  }
  //for(section & sec : rwSections_) {
  //  if(sec.vma <= addrs && (sec.vma + sec.size) > addrs 
  //     && sec.is_metadata) {
  //    return true;
  //  }
  //}
  return false;
}

bool 
CfgElems::withinRWSection(uint64_t addrs) {
  for(section & sec : rwSections_) {
    if(sec.vma <= addrs && (sec.vma + sec.size) > addrs) {
      return true;
    }
  }
  return false;
}

bool CfgElems::isDataPtr(Pointer * ptr) {
  /*Checks if a constant pointer lies within dats segment. If yes, marks it as
   * a data pointer.
   */
  
  uint64_t
    val = ptr->address();
  if(val >= codeSegEnd_ || isJmpTblLoc(val) == true 
     || withinRoSection(val) || withinRWSection(val))
    return true;

  return false;

}

bool CfgElems::isValidAddress(uint64_t addrs) {
  if((addrs >= dataSegmntStart_ && addrs < dataSegmntEnd_)){
    return true;
  }
  else if(withinRoSection(addrs) ||
          withinCodeSec(addrs)) {
    return true;
  }
  return false;
}

void
CfgElems::classifyPtrs() {
  /*Iterates over the list of pointers and classifies them as CP/DP/UNKNOWN.
   */

  //if(type_ != code_type::CODE)
  //  return;


  for(auto ptr_it = pointerMap_.begin(); ptr_it != pointerMap_.end();
       ptr_it++) {
    LOG("Classifying pointer: "<<hex<<ptr_it->first);
    Pointer *ptr = ptr_it->second;
    if(ptr->type() == PointerType::UNKNOWN ||
       ptr->type() == PointerType::DEF_PTR) {
      if(isCodePtr(ptr)) {
        ptr->type(PointerType::CP);
      }
      else if(isDataPtr(ptr)) {
        ptr->type(PointerType::DP);
      }
      else {
        vector <Symbol> sym_candidates = ptr->symCandidate();
        for(auto & s : sym_candidates) {
          if(s.type() == SymbolType::RLTV && definiteCode(s.location())) {
            ptr->type(PointerType::DEF_PTR);
            break;
          }
          else if(s.type() == SymbolType::CONSTANT) {
            for(auto & r : picConstReloc_) {
              if(r.storage == s.location()) {
                ptr->type(PointerType::DEF_PTR);
                break;
              }
            }
            if(ptr->type() == PointerType::DEF_PTR)
              break;
          }
        }
      }
    }
  }
  LOG("Classifying pointers complete");
}

bool CfgElems::isCodePtr(Pointer * ptr) {

  /*
   * Checks if a constant pointer is within EH frame boundary. If yes, marks
   * it as a code pointer.
   */
  uint64_t address = ptr->address();
  LOG("Checking if code ptr: "<<hex<<address);
  auto fn = is_within(address,funcMap_);
  if(fn != funcMap_.end())
    return fn->second->isValidIns(address);
  return false;
}


bool CfgElems::definiteCode(uint64_t addrs) {
  //LOG("Validating address: "<<hex<<addrs);
  auto it = is_within(addrs, funcMap_);
  if(it == funcMap_.end())
    return false;
  return it->second->definiteCode(addrs);
}


void
CfgElems::prntPtrStats() {
  //To be used for debugging purpose only.

  int unconfirmed_ptr = 0;
  int total_ptr = 0;
  for(auto ptr_it = pointerMap_.begin(); ptr_it != pointerMap_.end();
       ptr_it++) {
    LOG("Pointer value: " <<hex <<ptr_it->first);
    LOG(" source: " <<(int) ptr_it->second->source());
    LOG(" status: " <<(int) ptr_it->second->type());
    if(ptr_it->second->source() != PointerSource::EH) {
      Pointer *ptr = ptr_it->second;
      if(ptr->type() == PointerType::UNKNOWN) {
        unconfirmed_ptr++;
        LOG("Unconfirmed pointer: " <<hex <<ptr->address());
      }
      total_ptr++;
    }
  }
  LOG("Total pointers: " <<dec <<total_ptr);
  LOG("Total unconfirmed pointers: " <<unconfirmed_ptr);

  float fraction =(float) unconfirmed_ptr /(float) total_ptr;

  LOG("Fraction of unconfirmed pointers:" <<fraction);

}


void
CfgElems::functions(set <uint64_t> &function_list, uint64_t section_start,
		    uint64_t section_end) {
  /* Returns functions in the given range of addresses.
   */
  auto it = funcMap_.begin();
  while(it != funcMap_.end()) {
      if(it->first>= section_start && it->first <section_end)
	function_list.insert(it->first);
      it++;
    }
}

uint64_t CfgElems::dataBlkEnd() {
  uint64_t data_end = codeSegEnd_;
  if(rwSections_.size()> 0) {
      section
	sec = rwSections_[rwSections_.size() - 1];
      data_end = sec.offset + sec.size;
    }

  return data_end;
}
/*
bool CfgElems::assignLabeltoFn(string label, off_t func_addrs) {

  BasicBlock *bb = getBB(func_addrs);
  if(bb == NULL) {
      LOG("Function " <<hex <<func_addrs <<" doesn't exist in Cfg");
      return false;
    }

  bb->label(label);

  return true;
}
*/
void
CfgElems::populateRltvTgts() {
  LOG("Populating rltv tgts");
  for(auto & fn : funcMap_) {
    vector<BasicBlock *> defBBs = fn.second->getDefCode();
    for(auto & bb : defBBs) {
      vector <Instruction *> ins_list = bb->insList();
      for(auto & ins : ins_list) {
        uint64_t tgt = ins->ripRltvOfft();
        if(tgt != 0) {
          auto tgt_bb = getBB(tgt);
          if(tgt_bb != NULL) {
            //LOG("Adding rltv tgt: "<<hex<<tgt_bb->start());
            bb->rltvTgt(tgt_bb);
          }
        }
      }
    }
    vector<BasicBlock *> unknwnBBs = fn.second->getUnknwnCode();
    for(auto & bb : unknwnBBs) {
      //LOG("BB: "<<hex<<bb->start());
      vector <Instruction *> ins_list = bb->insList();
      for(auto & ins : ins_list) {
        uint64_t tgt = ins->ripRltvOfft();
        if(tgt != 0) {
          auto tgt_bb = getBB(tgt);
          if(tgt_bb != NULL) {
            //LOG("Adding rltv tgt: "<<hex<<tgt_bb->start());
            bb->rltvTgt(tgt_bb);
          }
        }
      }
    }
  }
  LOG("populating rltv tgts complete");
}

void
CfgElems::propagateEntries(set <uint64_t> &entries) {
  for(auto & e : entries) {
    auto bb = getBB(e);
    if(bb != NULL) {
      auto bb_list = bbSeq(bb,SEQTYPE::INTRAFN);
      LOG("propagating entry: "<<hex<<e<<" bb count: "<<bb_list.size());
      for(auto & bb2 : bb_list)
        bb2->entries(bb);
    }
  }
}

void
CfgElems::propagateAllRoots() {
  for (auto & p : pointerMap_) {
    if(p.second->type() == PointerType::CP ||
       p.second->symbolizable(SymbolizeIf::CONST) ||
       p.second->symbolizable(SymbolizeIf::RLTV) ||
       p.second->symbolizable(SymbolizeIf::IMMOPERAND) ||
       p.second->symbolizable(SymbolizeIf::JMP_TBL_TGT)) {
      LOG("Propagating root: "<<hex<<p.first);
      auto bb = getBB(p.first);
      if(bb != NULL) {
        bb->roots(bb);
      }
    }
  }

  for(auto & fn : funcMap_) {
    auto e = fn.second->entryPoints();
    propagateEntries(e);
    e = fn.second->probableEntry();
    propagateEntries(e);
  }
}

void
CfgElems::linkBBs(vector <BasicBlock *> &bbs) {
  //LOG("Linking BBs");
  for(auto bb : bbs) {
    if(bb->target() != 0 && bb->targetBB() == NULL) {
      auto tgtbb = getBB(bb->target());
      if(tgtbb == NULL) {
        LOG("No BB for address "<<hex<<bb->target());
        exit(0);
      }
      bb->targetBB(tgtbb);
      if(tgtbb->start() != bb->start()) {
        tgtbb->parent(bb);
      }
    }
    if(bb->fallThrough() != 0 && bb->fallThroughBB() == NULL) {
      auto fallbb = getBB(bb->fallThrough());
      if(fallbb == NULL) {
        LOG("No BB for address "<<hex<<bb->fallThrough());
        exit(0);
      }
      bb->fallThroughBB(fallbb);
      fallbb->parent(bb);
    }
  }
}

void
CfgElems::linkAllBBs() {
  LOG("linking BBs");
  for(auto & fn : funcMap_) {
    fn.second->removeDuplicates();
    vector<BasicBlock *> defBBs = fn.second->getDefCode();
    linkBBs(defBBs);
    vector<BasicBlock *> unknwnBBs = fn.second->getUnknwnCode();
    linkBBs(unknwnBBs);
  }
  LOG("Linking BBs complete");
}
void
CfgElems::instrument() {
  vector<pair<uint64_t, string>> tgtAddrs = targetAddrs();
  for(auto tgt:tgtAddrs) {
    auto bb = getBB(tgt.first);
    if(bb != NULL) {
      vector<InstArg> args = instArgs()[tgt.second];
      bb->registerInstrumentation(tgt.first,tgt.second,args);
    }
  }
  vector<pair<InstPoint,string>> targetPos = targetPositions();
  for(auto x:targetPos) {
    if(x.first == InstPoint::BASIC_BLOCK) {
      for(auto fn : funcMap_) {
        vector<BasicBlock *> bbs = fn.second->getDefCode();
        for(auto bb:bbs)
          bb->registerInstrumentation(bb->start(),x.second,instArgs()[x.second]);
        vector<BasicBlock *> bbs2 = fn.second->getUnknwnCode();
        for(auto bb:bbs2)
          bb->registerInstrumentation(bb->start(),x.second,instArgs()[x.second]);
      }
    }
    else if(x.first == InstPoint::ALL_FUNCTIONS) {
      for(auto fn:funcMap_) {
        set <uint64_t> entryPoint = fn.second->entryPoints();

        //Add instrumentation code at each entry of a function.
        //A function can have multiple entries.

        for(auto entry:entryPoint) {
          auto bb = fn.second->getBB(entry);
          bb->registerInstrumentation(entry,x.second,instArgs()[x.second]);
        }
      }
    }
    else {
      for(auto fn : funcMap_) {
        vector<BasicBlock *> bbs = fn.second->getDefCode();
        for(auto bb:bbs)
          bb->registerInstrumentation(x.first,x.second,instArgs()[x.second]);
        vector<BasicBlock *> bbs2 = fn.second->getUnknwnCode();
        for(auto bb:bbs2)
          bb->registerInstrumentation(x.first,x.second,instArgs()[x.second]);
      }
    }
  }
  for(auto fn : funcMap_) {
    vector<BasicBlock *> bbs = fn.second->getDefCode();
    for(auto bb:bbs)
      bb->instrument();
    vector<BasicBlock *> bbs2 = fn.second->getUnknwnCode();
    for(auto bb:bbs2)
      bb->instrument();
  }

}

void
CfgElems::instrument(uint64_t hook_point,string code) {
  auto bb = getBB(hook_point);
  if(bb != NULL) {
    bb->instrument(code);
  }
}

bool
CfgElems::isJmpTblLoc(uint64_t addrs) {
  for(unsigned int i = 0; i < jmpTables_.size (); i++) {
    if(jmpTables_[i].location () == addrs)
      return true;
  }
  return false;
}

string 
CfgElems::getSymbol(uint64_t addrs) {
  string sym = "";
  auto bb = withinBB(addrs);
  if(bb != NULL && bb->isValidIns(addrs))
    sym = "." + to_string(addrs) + bb->lblSuffix();
  return sym;
}
