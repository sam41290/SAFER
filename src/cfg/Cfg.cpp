#include "Cfg.h"
//#include "constant_ptr.h"
#include "disasm.h"
#include <stack>
#include <stdio.h>
#include <ctype.h>
#include "instrument.h"

using namespace SBI;

extern map <uint64_t, call_site_info> all_call_sites;
extern exception_handler eh_frame;
extern map <uint64_t, cfi_table> unwinding_info;

Cfg::Cfg(uint64_t memstrt, uint64_t memend):
     CFValidity(memstrt,memend,INSVALIDITY),
     PointerAnalysis(memstrt,memend) {}

void
Cfg::disassemble() {
  classifyPtrs();
  auto ptr_map = pointers(); 
  for(auto & ptr : ptr_map) {
    LOG("Creating function for pointer "<<hex<<ptr.second->address());
    createFuncFrPtr(ptr.second);
  }


  vector <Reloc> all_const_relocs = picConstReloc();
  all_const_relocs.insert(all_const_relocs.end(),xtraConstReloc().begin(),xtraConstReloc().end());
  allConstRelocs(all_const_relocs);
  genCFG();
  classifyPtrs();
  populateRltvTgts();
  randomizer();
  prntPtrStats();
}


void 
Cfg::scanMemForPtr (uint64_t start,uint64_t start_addr, uint64_t size) {
  LOG("Scanning memory space for const ptr: "<<hex<<start<<" size: "<<size);
  uint8_t *bytes = (uint8_t *)malloc(size);
  if(bytes != NULL) {
    utils::READ_FROM_FILE(exePath_,bytes,start,size);
    int read_lim = size - sizeof(uint64_t);
    for(int i = 0; i <= read_lim; i++,start++,start_addr++) {
      void *ptr = bytes + i;
      uint64_t psbl_ptr = *((uint64_t *)ptr);
      if(withinCodeSec(psbl_ptr)) {
        LOG("Possible stored code ptr: "<<hex<<psbl_ptr<<
            " location: "<<hex<<start<<" size: 8");
        auto bb = withinBB(psbl_ptr);
        if(bb != NULL)
          LOG("Withing bb: "<<hex<<bb->start()<<" code: "<<(int)bb->isCode());
        newPointer(psbl_ptr, PointerType::UNKNOWN,
            PointerSource::STOREDCONST,PointerSource::STOREDCONST,start_addr);
        if(bb == NULL || bb->isCode() == false || bb->isValidIns(psbl_ptr)) {
          createFn(true, psbl_ptr,psbl_ptr,code_type::UNKNOWN);
          disasmRoots_.push(psbl_ptr);
        }
      }
      if(withinCodeSec(start_addr)) {
        uint32_t psbl_ptr32 = *((uint32_t *)ptr);
        if(withinCodeSec((uint64_t)psbl_ptr32)) {
          LOG("Possible stored code ptr: "<<hex<<psbl_ptr32<<
              " location: "<<hex<<start<<" size: 4");
          uint64_t addr = psbl_ptr32;
          auto bb = withinBB(addr);
          if(bb != NULL)
            LOG("Withing bb: "<<hex<<bb->start()<<" code: "<<(int)bb->isCode());
          newPointer((uint64_t)psbl_ptr32, PointerType::UNKNOWN,
              PointerSource::STOREDCONST,PointerSource::STOREDCONST,start_addr);
          if(bb == NULL || bb->isCode() == false || bb->isValidIns(addr)) {
            createFn(true, addr,addr,code_type::UNKNOWN);
            disasmRoots_.push(psbl_ptr32);
          }
        }
      }

    }
    LOG("Finished reading pointers");
    free(bytes);
  }
}

void
Cfg::scanPsblPtrs() {
  auto ro_secs = roSections();
  for (auto & sec : ro_secs) {
    LOG("Scanning section: "<<sec.name);
    scanMemForPtr(sec.offset,sec.vma,sec.size);
  }
  auto rx_secs = rxSections();
  for (auto & sec : rx_secs) {
    LOG("Scanning section: "<<sec.name);
    scanMemForPtr(sec.offset,sec.vma,sec.size);
  }
  auto rw_secs = rwSections();
  for (auto & sec : rw_secs) {
    LOG("Scanning section: "<<sec.name);
    scanMemForPtr(sec.offset,sec.vma,sec.size);
  }
}

void
Cfg::processFallThrough(BasicBlock *bb, PointerSource t) {
  uint64_t fall = bb->fallThrough();
  if(fall != 0) {
    LOG("processing fall through: "<<hex<<fall);
    if(INVALID_CODE_PTR(fall)) {
      bb->fallThrough(0);
    }
    else if(addToCfg(fall,t) == false) {
      bb->fallThrough(0);
    }

  }

}

bool
Cfg::processTarget(BasicBlock *bb, PointerSource t) {
  uint64_t tgt = bb->target();
  if(tgt != 0) {
    LOG("Processing target: "<<hex<<tgt);
    if(addToCfg(tgt,t) == false) {
      //The jump target conflicts. Delete the current basic block.
      invalidPtr(tgt);
      LOG("invalid target: " <<hex <<bb->target());
      return false;
    }
    BBType tgt_type = getBBType(tgt);//tgtbb->type();
    Instruction *last_ins = bb->lastIns();
    if(last_ins->isCall()) {
      //bb->type(tgt_type);
      if(tgt_type == BBType::NON_RETURNING) {
        LOG("Marking bb non returining: " <<hex <<bb->start());
        bb->fallThrough(0);
        bb->fallThroughBB(NULL);
        bb->type(BBType::NON_RETURNING); 
      }
      //else
      //  bb->type(tgt_type);
      else if(tgt_type == BBType::MAY_BE_RETURNING)
        bb->type(BBType::MAY_BE_RETURNING);
      bb->callType(tgt_type);
    }
  }
  return true;
}

void
Cfg::checkLockPrefix(BasicBlock *bb ,code_type t) {
  uint64_t target = bb->target();
  uint64_t fall_through = bb->fallThrough();
  if(target != 0 && (target - fall_through) == 1) {
    //Lock prefix handling. Fall through and target locations will overlap
    //in case of a lock prefix.

    Instruction *last_ins = bb->lastIns();
    vector <Instruction *> fall_through_ins
      = disassembler_->getIns(fall_through,2);
    if(fall_through_ins[0]->prefix().find("lock") != string::npos) {
      target = 0;
      bb->target(0);
      string mnemonic = last_ins->mnemonic();
      last_ins->asmIns(mnemonic + " ." + to_string(fall_through) +
                 " + 1");
    }
  }
}

bool
Cfg::addToCfg(uint64_t addrs, PointerSource t) {
  /* Performs DFS along Cfg and adds the given address and the following basic
   * blocks in to the Cfg
   */
  LOG("Processing address: " <<hex <<addrs<<" code type: "<<(int)t);
  if(INVALID_CODE_PTR(addrs))
    return false;
  uint64_t chunk_end = isValidRoot(addrs,ISCODE(t));
  if(chunk_end == 0)
    return false;
  else if(chunk_end == addrs) {
    LOG("basic block at " <<hex <<addrs <<" already exists!!!");
    //processFallThrough(bb,t);
    processFallThrough(getBB(addrs),t);
    return true;
  }
  LOG("Chunk Start: " <<hex <<addrs <<" Chunk end: " <<hex <<chunk_end);
  vector <Instruction *> ins_list = disassembler_->getIns(addrs, 1000);
  if(ins_list.size() == 0) {
    LOG("No instruction found");
    return false;
  }
  //if(t == PointerSource::JUMPTABLE) {
  //  if(ins_list[0]->asmIns().find(".byte") != string::npos) {
  //    LOG("invalid instruction at addrs: "<<hex<<addrs);
  //    return false;
  //  }
  //}
  BasicBlock *bb = new BasicBlock(addrs,t,rootSrc_);
  createBB(bb,ins_list, chunk_end, ISCODE(t));
  BBType tgt_type;
  BBType fall_through_type;
  checkLockPrefix(bb,ISCODE(t));
  addBBtoFn(bb,t);
  if(processTarget(bb,t) == false) {
    removeBB(bb);
    invalidPtr(addrs);
    return false;
  }
  if(bb->type() == BBType::MAY_BE_RETURNING && ISCODE(t) == code_type::CODE
     && ISCODE(PointerSource::POSSIBLE_RA) != code_type::CODE) {
    if(bb->fallThrough() != 0) {
#ifdef IGNOREMAYEXIT
      processFallThrough(bb,t);
#else
#ifdef EH_FRAME_DISASM_ROOT
      if(withinFn(bb->fallThrough())) {
        LOG("Ignoring fall through since BB is MAY_BE_RETURNING: "<<
            hex<<bb->start()<<"->"<<hex<<bb->fallThrough());
        newPointer(bb->fallThrough(), PointerType::UNKNOWN,
            PointerSource::POSSIBLE_RA,rootSrc_,bb->end());
      }
      else
        processFallThrough(bb,t);
#else
      LOG("Ignoring fall through since BB is MAY_BE_RETURNING: "<<
          hex<<bb->start()<<"->"<<hex<<bb->fallThrough());
      newPointer(bb->fallThrough(), PointerType::UNKNOWN,
          PointerSource::POSSIBLE_RA,rootSrc_,bb->end());
#endif
#endif
    }
  }
  else
    processFallThrough(bb,t);
  //LOG("Finalizing: "<<hex<<addrs<<" - "<<hex<<bb);
  if(bb->fallThrough() != 0) {
    fall_through_type = getBBType(bb->fallThrough());//bb->fallThroughBB()->type();
  }
  else
    fall_through_type = BBType::NA;
  if(bb->target() != 0)
    tgt_type = getBBType(bb->target());//bb->targetBB()->type();
  else
    tgt_type = BBType::NA;
  if(bb->type() ==  BBType::NA) {
    LOG("Tgt type: "<<(int)tgt_type<<" fall type: "<<(int)fall_through_type);
    if(tgt_type == BBType::NA && fall_through_type == BBType::NA)
      bb->type(BBType::RETURNING);
    else if(tgt_type == BBType::NA)
      bb->type(fall_through_type);
    else if(fall_through_type == BBType::NA)
      bb->type(tgt_type);
    else if(bb->isCall())
      bb->type(fall_through_type);
    else if(fall_through_type != tgt_type)
      bb->type(BBType::MAY_BE_RETURNING);
    else
      bb->type(tgt_type);
  }

  LOG("BB created: "<<hex<<bb->start()<<" target: "<<hex<<bb->target()<<" fall: "
      <<hex<<bb->fallThrough()<<" "<<hex<<bb->targetBB()<<" "
      <<bb->fallThroughBB()<<" type: "<<(int)bb->type());
  return true;
}



void
Cfg::createBB(BasicBlock *bb,vector <Instruction *> &ins_list, uint64_t
    chunk_end, 
    code_type t) {
  /* Input: list of instructions.
   * Traverses the list until a control flow transfer is encountered or end of
   * the list is reached. 
   * Creates a basic block and adds to the map.
   */
  LOG("populating instructions in BB: "<<hex<<bb->start());
  uint64_t end = 0;
  vector <Instruction *> basic_block_ins;

  //bool is_non_returning_bb = false;
  uint64_t fall_through = 0;
  bool isLea = false;
  for(auto & ins:ins_list) {
    if(getBB(ins->location()) != NULL) {
      LOG("BB at "<<hex<<ins->location()<<" already exists. Breaking!!");
      break;
    }
    checkForPtr(ins);
    fall_through = ins->fallThrough();
    if(isLea == false)
      isLea = ins->isLea();
    LOG("instruction location: " <<hex <<ins->location() <<
     " Call value: " <<ins->isCall() <<" jump value: " <<ins->isJump()
     <<" fall: "<<hex<<fall_through);
    if((ins->isJump() != false && ins->isUnconditionalJmp() == false)
    && ins->isCall() == false) {
      //conditional jump 
      basic_block_ins.push_back(ins);
      NEWBB(bb,ins->location(),basic_block_ins,
          fall_through,ins->target(),isLea);
      return;
    }
    else if(ins->isJump() != false || ins->isCall() != false)	{
      //unconditional jump or call 
      basic_block_ins.push_back(ins);
      if(ins->isCall() == false)
        fall_through = 0;

      NEWBB(bb,ins->location(),basic_block_ins,
          fall_through,ins->target(),isLea);
      createFn(ins->isCall(), ins->target(),
        	   ins->location(),t);
      
      //LOG("Function created");
      processIndrctJmp(ins, bb,t);
      //LOG("RIP rltv processing done");
      return;
    }
    else {
      basic_block_ins.push_back(ins);
      end = ins->location();
    }
    if(ins->isHlt()) {
      fall_through = 0;
      break;
    }
  }
  LOG("No jump found");
  //end = ins_list[ins_count - 1].get_location();
  NEWBB(bb, end, basic_block_ins, fall_through, 0,isLea);
  return;
}



void
Cfg::addToDisasmRoots(uint64_t address) {
  disasmRoots_.push(address);
}

void
Cfg::processAllRoots() {
  vector <uint64_t> disasm_later;
  while(true) {
    unsigned int size = disasm_later.size();
    disasm_later.clear();
    while(!disasmRoots_.empty()) {
      uint64_t start = disasmRoots_.top();
      disasmRoots_.pop();
      if(ptr(start) != NULL){
        if(ignoreRoots_.find(ptr(start)->source()) == ignoreRoots_.end()) {
          if(ptr(start)->rootSrc() != PointerSource::NONE)
            rootSrc_ = ptr(start)->rootSrc();
          else
            rootSrc_ = ptr(start)->source();

          addToCfg(start,ptr(start)->source());
        }
        else
          disasm_later.push_back(start);
      }
      else {
        LOG("No pointer for disasm root: "<<hex<<start);
        exit(0);
      }
    }
    if(size == disasm_later.size())
      break;
    else {
      for(auto entry : disasm_later)
        disasmRoots_.push(entry);
    }
  }
  for(auto entry : disasm_later)
    disasmRoots_.push(entry);
}

void
Cfg::randomPointDisasm(int min, int max) {
  uint64_t start = 0;
  uint64_t end = 0;
  auto rx_secs = rxSections();
  for(section & sec : rx_secs) {
    if(sec.sec_type == section_types::RX) {
      if(start == 0)
        start = sec.vma;
      end = sec.vma + sec.size;
    }
  }
  srand(time(0));
  int cnt = rand()%(max - min + 1) + min;

  vector<uint64_t> allAddrs;
  auto ptr_map = pointers();
  while(start < end) {
    if(ptr_map.find(start) == ptr_map.end())
      allAddrs.push_back(start);
    start++;
  }

  unsigned seed =
    std::chrono::system_clock::now().time_since_epoch().count();
  std::shuffle(allAddrs.begin(), allAddrs.end(),
    std::default_random_engine(seed));
  auto fn_map = funcMap();
  for(int i = 0; i < cnt && i < allAddrs.size(); i++) {
    LOG("Random disassm point: "<<hex<<allAddrs[i]);
    newPointer(allAddrs[i],PointerType::UNKNOWN,PointerSource::RANDOMADDRS,0);
    auto fn = is_within(allAddrs[i],fn_map);
    fn->second->addProbableEntry(allAddrs[i]);
    disasmRoots_.push(allAddrs[i]);
  }
  classifyPtrs();
  processAllRoots();
  linkAllBBs();
  analyze();
}

void
Cfg::jmpTblGroundTruth(int type) {
  vector <Reloc> rela_list;
  if(type == 1)
    rela_list = pcrelReloc();
  else
    rela_list = xtraConstReloc();

  string key("/");
  size_t found = exePath_.rfind(key);
  string file_name = exePath_.substr(found + 1);
  ofstream ofile;
  ofile.open("tmp/" + file_name + "_jmp_tbl.dat",ofstream::out | ofstream::app);
  auto ptr_map = pointers();
  auto fn_map = funcMap();
  for (auto & r : rela_list) {
    if((type != 1 && if_exists(r.ptr,ptr_map)) || 
        r.ptr >= codeSegEnd_)
      continue;
    auto bb = withinBB(r.storage);
    if(bb != NULL)
      continue;
    if(ptr_map.find(r.storage) != ptr_map.end()) {
      uint64_t access_pnt = ptr_map[r.storage]->loadPoint();
      if(access_pnt > 0) {
        ofile<<"tbl: "<<dec<<r.storage<<" "<<type<<endl;
        auto fn = is_within(access_pnt,fn_map);
        if(fn != fn_map.end())
          fn->second->hasJmpTbl(true);
      }
    }
    ofile<<"entry address: "<<dec<<r.storage<<" "<<type<<endl;
  }
  ofile.close();
}

void
Cfg::groundTruthDisasm() {

  ignoreRoots_.insert(PointerSource::SYMTABLE);
  ignoreRoots_.insert(PointerSource::DEBUGINFO);
  ignoreRoots_.insert(PointerSource::EXTRA_RELOC_CONST);
  ignoreRoots_.insert(PointerSource::EXTRA_RELOC_PCREL);
  processAllRoots();
  ignoreRoots_.clear();
  ignoreRoots_.insert(PointerSource::SYMTABLE);
  ignoreRoots_.insert(PointerSource::EXTRA_RELOC_PCREL);
  processAllRoots();
  ignoreRoots_.clear();
  ignoreRoots_.insert(PointerSource::EXTRA_RELOC_PCREL);
  processAllRoots();
  ignoreRoots_.clear();
  processAllRoots();
  linkAllBBs();
  //Jump table processing
  jmpTblGroundTruth(1);
  jmpTblGroundTruth(2);
  //Collect extra debug info for possible jump table target

  string key("/");
  size_t found = exePath_.rfind(key);
  string file_name = exePath_.substr(found + 1);
  string ptrfile = "tmp/" + file_name + ".ptrlst";
  ifstream ifile;
  ifile.open(ptrfile);
  char line[500];
  map <uint64_t, Function *> fn_map = funcMap();
  while(ifile.getline(line,500)) {
    string ptrstr(line);
    uint64_t ptr = stoi(ptrstr);
    auto fn = is_within(ptr,fn_map);
    if(withinRoSection(ptr) == false && fn != fn_map.end() && 
       fn->second->withinDefCode(ptr) == false) {
      LOG("Additional pointer for ground truth: "<<ptrstr);
      LOG(ptr);
      disasmRoots_.push(ptr);
      PointerSource s = PointerSource::DEBUGINFO;
      if(fn->second->hasJmpTbl())
        s = PointerSource::JUMPTABLE;
      newPointer(ptr,PointerType::CP,s,0);
    }
  }

  processAllRoots();
  linkAllBBs();
  //analyze();
}

void
Cfg::EHDisasm() {
#ifdef EH_FRAME_DISASM_ROOT
    LOG("Adding EH frame start to roots");
    auto fn_map = funcMap();
    for(auto & fn : fn_map) {
      //First pointer into EH frame body as valid disasm root
      if(fn.second->dummy() == false) {
        disasmRoots_.push(fn.first);
        newPointer(fn.first,PointerType::CP,PointerSource::EHFIRST,100);
      }
    }
    processAllRoots();
    for(auto & fn : fn_map) {
      if(fn.second->dummy() == false) {
        set <uint64_t> indirectPtrs = fn.second->probableEntry();
        auto it = indirectPtrs.begin();
        if(it != indirectPtrs.end())
          if(fn.second->definiteCode(*it) == false) {
            //auto ptr_it = pointerMap_.find(*it);
            auto p = ptr(*it);
            if(p != NULL 
               && p->source() != PointerSource::STOREDCONST
               && p->source() != PointerSource::CONSTOP) {
              disasmRoots_.push(*it);
              newPointer(*it,PointerType::CP,PointerSource::EHFIRST,100);
            }
          }
      }
    }
    processAllRoots();
    //linkAllBBs();
    //analyze();
#endif

}

void
Cfg::possibleCodeDisasm() {
  LOG("Disassembling possible code");
  classifyPtrs();
  LOG("Disassembling possible code");
  disasmRoots(PointerType::UNKNOWN);
  disasmRoots(PointerType::DEF_PTR);
  while(true) {
    unsigned int sz = ptrCnt();
    processAllRoots();
    linkAllBBs();
    analyze();
    if(sz == ptrCnt())
      break;
    disasmRoots(PointerType::UNKNOWN);
    disasmRoots(PointerType::DEF_PTR);
  }
  if(type_ == exe_type::NOPIE) {
    scanPsblPtrs();
//#ifdef EH_FRAME_DISASM_ROOT
//    return;
//#endif
    LOG("Disassembling stored const ptrs");
    while(true) {
      unsigned int sz = ptrCnt();
      processAllRoots();
      linkAllBBs();
      analyze();
      if(sz == ptrCnt())
        break;
      disasmRoots(PointerType::UNKNOWN);
      disasmRoots(PointerType::DEF_PTR);
    }

  }
  LOG("Possible code disassembly complete");
}


void
Cfg::cnsrvtvDisasm() {
  processAllRoots();
  //linkAllBBs();
  //analyze();
  classifyPtrs();
  possibleCodeDisasm();
}

void
Cfg::genCFG() {

#ifdef PURERANDOMDISASM
  randomPointDisasm(500,1000);
#ifdef CFGCONSISTENCYCHECK
  cfgConsistencyAnalysis();
#endif
  classifyPtrs();
  return;
#endif
  
#ifdef DATADISASM
  uint64_t start = 0;
  for(section sec:rxSections_) {
    if(sec.sec_type == section_types::RX) {
      if(start == 0)
        start = sec.vma;
    }
  }
  std::random_device rd;
  std::default_random_engine eng(rd());
  std::uniform_int_distribution<int> distr(start, dataSegmntEnd_);

  for (int n = 0; n < 3000; ++n) {
    uint64_t r = distr(eng);
    newPointer(r, PointerType::DP,PointerSource::NONE,100);
  }
  disasmRoots(PointerType::DP);
  processAllRoots();
  linkAllBBs();
#ifdef CFGCONSISTENCYCHECK
  saveCnsrvtvCode();
  cfgConsistencyAnalysis();
#endif
  return;
#endif
#ifdef STRINGS
  uint64_t start = INT_MAX, end = 0;
  for(auto & sec : rxSections_) {
    if(sec.sec_type == section_types::RX) {
      if(sec.vma < start)
        start = sec.vma;
      if((sec.vma + sec.size) > end)
        end = sec.vma + sec.size;
    }
  }
  std::random_device rd;
  std::default_random_engine eng(rd());
  std::uniform_int_distribution<int> distr(start,end);

  for (int n = 0; n < 5000; ++n) {
    uint64_t r = distr(eng);
    newPointer(r, PointerType::CP,PointerSource::NONE,100);
  }
  disasmRoots(PointerType::CP);
  processAllRoots();
  linkAllBBs();
#ifdef CFGCONSISTENCYCHECK
  saveCnsrvtvCode();
  cfgConsistencyAnalysis();
#endif
  return;
#endif

  disasmRoots(PointerType::CP);

#ifdef GROUND_TRUTH
  groundTruthDisasm();
  classifyPtrs();
  symbolize();
  string key("/");
  size_t found = exePath_.rfind(key);
  string file_name = exePath_.substr(found + 1);
  ofstream ofile;
  ofile.open("tmp/" + file_name + "_symbols.data");
  auto ptr_map = pointers();
  for(auto & ptr : ptr_map) {
    ptr.second->dump(ofile);
  }
  ofile.close();
  return;
#endif

#ifdef KNOWN_CODE_POINTER_ROOT
#ifdef DISASMONLY
  if(utils::file_exists("tmp/cfg.present")) {
    LOG("Cfg already present. Skipping disassembly and reading cfg");
    readCfg();
    linkAllBBs();
    classifyPtrs();
  }
  else {
    LOG("Cfg not present. Starting disassembly");
    cnsrvtvDisasm();
  }
#else
  cnsrvtvDisasm();
#endif
#ifdef CFGCONSISTENCYCHECK
  saveCnsrvtvCode();
  cfgConsistencyAnalysis();
#else
  dump();
#endif
  classifyPtrs();
  symbolize();
  string key("/");
  size_t found = exePath_.rfind(key);
  string file_name = exePath_.substr(found + 1);
  ofstream ofile;
  ofile.open("tmp/" + file_name + "_symbols.data");
  map <uint64_t, Pointer *> ptr_map = pointers();
  for(auto & ptr : ptr_map) {
    ptr.second->dump(ofile);
  }
  ofile.close();
  return;
#endif

#ifdef EH_FRAME_DISASM_ROOT
  processAllRoots();
  EHDisasm();
  classifyPtrs();
  possibleCodeDisasm();
  analyze();
//#ifdef CFGCONSISTENCYCHECK
  saveCnsrvtvCode();
  cfgConsistencyAnalysis();
//#endif
  classifyPtrs();
  symbolize();
  string key("/");
  size_t found = exePath_.rfind(key);
  string file_name = exePath_.substr(found + 1);
  ofstream ofile;
  ofile.open("tmp/" + file_name + "_symbols.data");
  auto ptr_map = pointers();
  for(auto & ptr : ptr_map) {
    ptr.second->dump(ofile);
  }
  ofile.close();
  return;
#endif

}


void
Cfg::disasmRoots(PointerType p_type) {
  classifyPtrs();
  map <uint64_t, Pointer *> ptr_map = pointers();
  for(auto & p : ptr_map) {
    if(p.second->type() == p_type)
      disasmRoots_.push(p.first);
  }
}


void
Cfg::functionRanges() {
  //To be used for debugging purpose
  string key("/");
  size_t found = exePath_.rfind(key);
  string file_name = exePath_.substr(found + 1);
  string input_file_name = "tmp/" + file_name + ".functions";
  map <uint64_t, Function *> fn_map = funcMap();
  ofstream ofile;
  ofile.open(input_file_name);
  for(auto & func:fn_map) {
    vector <BasicBlock *> bbs = func.second->getDefCode();
    if(bbs.size() > 0) {
      auto bb = bbs[bbs.size() - 1];
      Instruction *ins = bb->lastIns();
      uint64_t end = ins->location() + ins->insSize();
      ofile<<hex<<func.first<<"-"<<hex<<end<<endl;
    }
  }
  ofile.close();

}


void
Cfg::randomizer() {

  map <uint64_t, Pointer *> ptr_map = pointers();
  map <uint64_t, Function *> fn_map = funcMap();
  uint64_t data_seg = dataSegmntStart();
  uint64_t blk_end = dataBlkEnd();

#ifdef NO_BASIC_BLOCK_RANDOMIZATION
  randomizer_ = new NoBBRand(ptr_map,fn_map,data_seg,blk_end);
#endif

#ifdef PBR_BASIC_BLOCK_RANDOMIZATION
  randomizer_ = new PbrRand(ptr_map,fn_map,data_seg,blk_end);
#endif

#ifdef LLRK_BASIC_BLOCK_RANDOMIZATION
  randomizer_ = new LlrkRand(ptr_map,fn_map,data_seg,blk_end);
#endif

#ifdef ZJR_BASIC_BLOCK_RANDOMIZATION
  randomizer_ = new ZjrRand(ptr_map,fn_map,data_seg,blk_end);
#endif

#ifdef BBR_BASIC_BLOCK_RANDOMIZATION
  randomizer_ =  new BbrRand(ptr_map,fn_map,data_seg,blk_end);
#endif

#ifdef PHR_BASIC_BLOCK_RANDOMIZATION
  randomizer_ =  new PhrRand(ptr_map,fn_map,data_seg,blk_end);
#endif

}


void
Cfg::printFunc(uint64_t fstart, string file_name) {
  /* Prints ASM for a function
   */
  auto fn_map = funcMap();
  if(if_exists(fstart, fn_map) == false) {
    LOG("Function not present");
    return;
  }
  Function *f = fn_map[fstart];
  vector <BasicBlock *> defbbs = f->getDefCode();
  //vector <BasicBlock *> unknwnbbs = f->getUnknwnCode();

  //map<uint64_t, uint8_t> bytes;
  //for(auto & bb : unknwnbbs) {
  //  auto ins_list = bb->insList();
  //  for(auto & ins : ins_list) {
  //    auto bin = ins->insBinary();
  //    uint64_t loc = ins->location();
  //    for(auto & b : bin) {
  //      bytes[loc] = b;
  //      loc++;
  //    }
  //  }
  //}
  //ofstream ofile;
  //ofile.open(file_name, ofstream::out | ofstream::app);
  //for(auto & b : bytes) {
  //  ofile<<"."<<b.first<<"_unknown_code: .byte "<<(uint32_t)b.second<<endl; 
  //}
  //ofile.close();

#ifdef OPTIMIZED_EH_METADATA 
  if(defbbs.size() > 0) {
    //Intra unwinding block randomization for definite code.
    auto unwind_it = unwinding_info.find(fstart);
    if(unwind_it != unwinding_info.end()) {
      set <uint64_t> all_unwind_blks
        = unwind_it->second.get_all_unwinding_blks(); 
      //bool blk_start = true;
      vector <BasicBlock *> bb_list;
      for(auto bb:defbbs) {
        if(all_unwind_blks.find(bb->start()) != all_unwind_blks.end()) {
          if(bb_list.size()> 0) {
            LOG("Unwinding blk: "<<hex<<bb_list[0]<<" - "<<hex<<bb);
            randomizer_->print(bb_list, file_name, fstart);
          }
          bb_list.clear();
          bb_list.push_back(bb);
        }
        else
          bb_list.push_back(bb);

      }
      if(bb_list.size()> 0)
        randomizer_->print(bb_list, file_name, fstart);
    }
    else
      randomizer_->print(defbbs, file_name, fstart);
    return;
  }
  //if (unknwnbbs.size() > 0)  {
  //  //Since EH metadata for possible code is not optimized at this point, follow
  //  //normal randomization.
  //  randomizer_->print(unknwnbbs, file_name, fstart);
  //  return;
  //}
#endif
  if(defbbs.size() > 0)
    randomizer_->print(defbbs, file_name, fstart);
  //if (unknwnbbs.size() > 0)
  //  randomizer_->print(unknwnbbs, file_name, fstart);
  return;
}

void
Cfg::checkForPtr(Instruction *ins) {

  /* If the instruction is RIP relative, create a pointer with value = RIP
   * relative offset.
   */

  uint64_t ptr_val = ins->ripRltvOfft();
  if(ptr_val != 0 && ptr_val < dataSegmntEnd_) {
    LOG("Adding rltv ptr: "<<hex<<ptr_val<<" location: "<<hex<<ins->location());
    newPointer(ptr_val, PointerType::UNKNOWN,
        PointerSource::RIP_RLTV,rootSrc_,ins->location());
    auto p = ptr(ptr_val);
    if(ins->isLea())
      p->loadPoint(ins->location());
    if(isDataPtr(p))
      p->type(PointerType::DP);
    else if(ins->isLea()) {
      code_type t = code_type::UNKNOWN;
      if(p->type() == PointerType::CP)
        t = code_type::CODE;
      createFn(true, ptr_val,ptr_val,t);
    }
  }
  if(type_ == exe_type::NOPIE) {
    uint64_t ptr_val = ins->constOp();
    LOG("Const op: "<<hex<<ptr_val);
    if(ptr_val != 0 && withinCodeSec(ptr_val)) {
      LOG("Creating ptr: "<<hex<<ptr_val);
      newPointer(ptr_val, PointerType::UNKNOWN,
          PointerSource::CONSTOP,rootSrc_, ins->location());
      auto p = ptr(ptr_val);
      p->loadPoint(ins->location());
      if(isDataPtr(p))
        p->type(PointerType::DP);
      else {
        code_type t = code_type::UNKNOWN;
        if(p->type() == PointerType::CP)
          t = code_type::CODE;
        createFn(true, ptr_val,ptr_val,t);
      }
    }
  }
}

void
Cfg::processIndrctJmp(Instruction *call_ins, BasicBlock *bb,code_type t) {
  //LOG("Call ins addrs: "<<hex<<call_ins->location()<<" is relative"<<call_ins->isRltvAccess());
  if(call_ins->isRltvAccess()) {
    // Special handling for LINUX to add the address of main,
    // __libc_csu_init and __libc_csu_fini.
    //LOG("Jump slot: "<<hex<<call_ins->ripRltvOfft());
    uint64_t jump_slot = call_ins->ripRltvOfft();
    if(call_ins->isCall()  && jump_slot == libcStrtMain_ && t==code_type::CODE) {
      LOG("libc_Start_main call at: "<<hex<<call_ins->location());
      vector <Instruction *> insList = bb->insList();
      if(insList.size() >= 4) {
        int ind = insList.size() - 2;
        uint64_t ptr = PTR_ACCESS(insList[ind]);
        ADD_PTR_TO_MAIN(ptr);
        ind--;
        ptr = PTR_ACCESS(insList[ind]);
        ADD_PTR_TO_MAIN(ptr);
        ind--;
        ptr = PTR_ACCESS(insList[ind]);
        ADD_PTR_TO_MAIN(ptr);
      }
    }
    if(exitCall(jump_slot)) {
      LOG("exit call found. Marking bb: "<<hex<<bb->start()<<" non returning");
      bb->type(BBType::NON_RETURNING);
    }
    else if(mayExitCall(jump_slot)) {
      LOG("may exit call found. Marking bb: "<<hex<<bb->start()<<" may be returning");
      bb->type(BBType::MAY_BE_RETURNING);
    }
  }
}

