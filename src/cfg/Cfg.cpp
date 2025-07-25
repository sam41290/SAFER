#include "Cfg.h"
//#include "constant_ptr.h"
#include "disasm.h"
#include <stack>
#include <stdio.h>
#include <ctype.h>
#include "instrument.h"

using namespace SBI;

//extern map <uint64_t, call_site_info> all_call_sites;
//extern exception_handler eh_frame;
//extern map <uint64_t, cfi_table> unwinding_info;

unordered_set <uint64_t> Cfg::validCFSet_;

Cfg::Cfg(uint64_t memstrt, uint64_t memend,string exepath):
     CFValidity(memstrt,memend,INSVALIDITY),
     PointerAnalysis(memstrt,memend,exepath) {}

void
Cfg:: superset() {
  /* This is the code to execute a superset disassembly of all addresses in the
   * memory of a program
   */
  supersetCfg_ = new Cfg(CFValidity::memSpaceStart_,CFValidity::memSpaceEnd_,exePath_);
  supersetCfg_->codeSegEnd(codeSegEnd_);
  supersetCfg_->libcStartMain(libcStrtMain_);
  supersetCfg_->disassembler(disassembler_);
  supersetCfg_->exePath(exePath_);
  supersetCfg_->type(type_);
  supersetCfg_->dataSegmntStart(dataSegmntStart_);
  supersetCfg_->rxSections(rxSections());
  supersetCfg_->entryPoint(entryPoint_);
  supersetCfg_->roSection(roSections());
  supersetCfg_->rwSections(rwSections());
  //supersetCfg_->functions(funcMap());

  auto rx_sections = supersetCfg_->rxSections();

  for(auto & sec : rx_sections) {
    if(sec.sec_type == section_types::RX) {
      auto start = sec.vma;
      auto end = sec.vma + sec.size;

      //auto p = new Pointer(start,PointerType::UNKNOWN,PointerSource::CONSTOP); 
      supersetCfg_->createFn(true,start,start,code_type::UNKNOWN);

      while(start < end) {
        //DEF_LOG("Superset disassembly: "<<hex<<start);
        if(supersetCfg_->disassembled(start) == false)
          supersetCfg_->addToCfg(start, PointerSource::CONSTOP);
        //else
        //  DEF_LOG("Already disassembled");
        start++;
      }
    }
  }
  supersetCfg_->linkAllBBs();
  for(auto & sec : rx_sections) {
    if(sec.sec_type == section_types::RX) {
      auto start = sec.vma;
      auto end = sec.vma + sec.size;

      while(start < end) {
        supersetCfg_->cfcheck(start);
        start++;
      }
    }
  }


}

void
Cfg::preDisasmConfig() {
  classifyPtrs();
  auto ptr_map = pointers(); 
  for(auto & ptr : ptr_map) {
    //DEF_LOG("Creating function for pointer "<<hex<<ptr.second->address()<<" code type: "<<dec<<(int)ptr.second->type());
    createFuncFrPtr(ptr.second);
  }

  LOG("Functions created for all pointers");

  vector <Reloc> all_const_relocs = picConstReloc();

  LOG("Const reloc count: "<<all_const_relocs.size());

  auto xtra_reloc = xtraConstReloc();

  LOG("Const reloc count: "<<xtra_reloc.size());


  all_const_relocs.insert(all_const_relocs.end(),xtra_reloc.begin(), xtra_reloc.end());
  allConstRelocs(all_const_relocs);
  preDisasmConfig_ = true;
}

void
Cfg::disassemble() {
  if(!preDisasmConfig_) preDisasmConfig();
  genCFG();
  //classifyPtrs();
  populateRltvTgts();
  randomizer();
  prntPtrStats();
}

void
Cfg::guessJumpTable() {
  auto ptr_map = pointers();
  for(auto & p : ptr_map) {
    if(p.second->symbolizable(SymbolizeIf::RLTV) || p.second->symbolizable(SymbolizeIf::CONST)) {
      if(p.second->type() == PointerType::CP || isJmpTblLoc(p.first))
        continue;
      uint64_t end = dataSegmntEnd(p.first);
      DEF_LOG("Guessing jump table locations for: "<<hex<<p.first<<"->"<<hex<<end);
      for(uint64_t i = p.first; i < end; ) {
        int64_t offt64 = 0;
        int64_t offt32 = 0;
        uint64_t file_offt = utils::GET_OFFSET(exePath_,i);
        utils::READ_FROM_FILE(exePath_, (void *) &offt64, file_offt,8);
        utils::READ_FROM_FILE(exePath_, (void *) &offt32, file_offt,4);
        DEF_LOG("8 byte val: "<<hex<<offt64<<" 4 byte val: "<<hex<<offt32);
        if(isValidIns(offt64)) {
          DEF_LOG("Potential target: "<<hex<<offt64);
          newPointer(offt64,PointerType::UNKNOWN,PointerSource::STOREDCONST,offt64);
          i += 8;
        }
        else if(isValidIns((uint32_t)(offt32 + p.first))) {
          uint32_t val = (uint32_t)(offt32 + p.first);
          DEF_LOG("Potential target: "<<hex<<val);
          newPointer(val,PointerType::UNKNOWN,PointerSource::JUMPTABLE,val);
          i += 4;
        }
        else if(isValidIns(offt64 + p.first)) {
          DEF_LOG("Potential target: "<<hex<<offt64 + p.first);
          newPointer(offt64 + p.first,PointerType::UNKNOWN,PointerSource::JUMPTABLE,offt64 + p.first);
          i += 8;
        }
        else if(isValidIns(offt32)) {
          DEF_LOG("Potential target: "<<hex<<offt32);
          newPointer(offt32,PointerType::UNKNOWN,PointerSource::STOREDCONST,offt32);
          i += 4;
        }
        else
          break;
      }
    }
  }
  DEF_LOG("Checking cached jump tables to guess more targets");
  auto jtables = cachedJTables();
  for (auto & j_rec : jtables) {
    auto j_vec = j_rec.second;
    for(auto & j : j_vec) {
      auto start = j.location();
      auto base = j.base();
      if(jmpTblExists(j)) {
        auto j_prev = jmpTbl(start, base);
        if(j_prev.targets().size() > 0)
          continue;
      }
      auto stride = j.entrySize();
      if(CFValidity::validAddrs(j.base()) == false ||
         isMetadata(j.base()))
        continue;
      if(CFValidity::validAddrs(j.location()) == false ||
         isMetadata(j.location()))
        continue;
      if(stride <= 0 || stride > 8)
        continue;
      uint64_t end = dataSegmntEnd(start);
      if(end == 0)
        continue;
      for(uint64_t i = start; i < end; i+=stride) {
        int64_t offt64 = 0;
        uint64_t file_offt = utils::GET_OFFSET(exePath_,i);
        utils::READ_FROM_FILE(exePath_, (void *) &offt64, file_offt,stride);
        if(isValidIns(offt64)) {
          DEF_LOG("Potential target: "<<hex<<offt64);
          newPointer(offt64,PointerType::UNKNOWN,PointerSource::STOREDCONST,offt64);
        }
        else if(isValidIns(offt64 + base)) {
          DEF_LOG("Potential target: "<<hex<<offt64 + base);
          newPointer(offt64 + base,PointerType::UNKNOWN,PointerSource::JUMPTABLE,offt64 + base);
        }
      }
    }
  }
  DEF_LOG("Guessing jump tables complete");
}

void 
Cfg::scanMemForPtrGT (uint64_t start,uint64_t start_addr, uint64_t size) {
  LOG("Scanning memory space for const ptr: "<<hex<<start<<" size: "<<size);
  uint8_t *bytes = (uint8_t *)malloc(size);
  if(bytes != NULL) {
    utils::READ_FROM_FILE(exePath_,bytes,start,size);
    int read_lim = size - sizeof(uint64_t);
    for(int i = 0; i <= read_lim; i++,start++,start_addr++) {
      void *p = bytes + i;
      uint64_t psbl_ptr = *((uint64_t *)p);
      if(withinCodeSec(psbl_ptr)) {
        LOG("Possible stored code ptr: "<<hex<<psbl_ptr<<
            " location: "<<hex<<start<<" size: 8");
        auto bb = withinBB(psbl_ptr);
        if(bb != NULL)
          LOG("Withing bb: "<<hex<<bb->start()<<" code: "<<(int)bb->isCode());
        if(bb == NULL || bb->isCode() == false || bb->isValidIns(psbl_ptr)) {
          newPointer(psbl_ptr, PointerType::UNKNOWN,
            PointerSource::STOREDCONST,PointerSource::STOREDCONST,start_addr);
          ptr(psbl_ptr)->size(8, start_addr);
        }
      }
      if(withinCodeSec(start_addr)) {
        uint32_t psbl_ptr32 = *((uint32_t *)p);
        if(withinCodeSec((uint64_t)psbl_ptr32)) {
          LOG("Possible stored code ptr: "<<hex<<psbl_ptr32<<
              " location: "<<hex<<start<<" size: 4");
          uint64_t addr = psbl_ptr32;
          auto bb = withinBB(addr);
          if(bb != NULL)
            LOG("Withing bb: "<<hex<<bb->start()<<" code: "<<(int)bb->isCode());
          if(bb == NULL || bb->isCode() == false || bb->isValidIns(addr)) {
            newPointer((uint64_t)psbl_ptr32, PointerType::UNKNOWN,
              PointerSource::STOREDCONST,PointerSource::STOREDCONST,start_addr);
            ptr((uint64_t)psbl_ptr32)->size(4, start_addr);
          }
        }
      }

    }
    LOG("Finished reading pointers");
    free(bytes);
  }
}

void
Cfg::scanPsblPtrsGT() {
  auto ro_secs = roSections();
  for (auto & sec : ro_secs) {
    LOG("Scanning section: "<<sec.name);
    scanMemForPtrGT(sec.offset,sec.vma,sec.size);
  }
  auto rx_secs = rxSections();
  for (auto & sec : rx_secs) {
    LOG("Scanning section: "<<sec.name);
    scanMemForPtrGT(sec.offset,sec.vma,sec.size);
  }
  auto rw_secs = rwSections();
  for (auto & sec : rw_secs) {
    LOG("Scanning section: "<<sec.name);
    scanMemForPtrGT(sec.offset,sec.vma,sec.size);
  }
}

void 
Cfg::scanMemForPtr (uint64_t start,uint64_t start_addr, uint64_t size) {
  LOG("Scanning memory space for const ptr: "<<hex<<start<<" size: "<<size);
  uint8_t *bytes = (uint8_t *)malloc(size);
  if(bytes != NULL) {
    utils::READ_FROM_FILE(exePath_,bytes,start,size);
    int read_lim = size - sizeof(uint64_t);
    for(int i = 0; i <= read_lim; i++,start++,start_addr++) {
      void *p = bytes + i;
      uint64_t psbl_ptr = *((uint64_t *)p);
      if(withinCodeSec(psbl_ptr)) {
        LOG("Possible stored code ptr: "<<hex<<psbl_ptr<<
            " location: "<<hex<<start<<" size: 8");
        auto bb = withinBB(psbl_ptr);
        if(bb != NULL)
          LOG("Withing bb: "<<hex<<bb->start()<<" code: "<<(int)bb->isCode());
        if(bb == NULL || bb->isCode() == false || bb->isValidIns(psbl_ptr)) {
          newPointer(psbl_ptr, PointerType::UNKNOWN,
            PointerSource::STOREDCONST,PointerSource::STOREDCONST,start_addr);
          ptr(psbl_ptr)->size(8, start_addr);
          createFn(true, psbl_ptr,psbl_ptr,code_type::UNKNOWN);
          disasmRoots_.push(psbl_ptr);
        }
      }
      if(withinCodeSec(start_addr)) {
        uint32_t psbl_ptr32 = *((uint32_t *)p);
        if(withinCodeSec((uint64_t)psbl_ptr32)) {
          LOG("Possible stored code ptr: "<<hex<<psbl_ptr32<<
              " location: "<<hex<<start<<" size: 4");
          uint64_t addr = psbl_ptr32;
          auto bb = withinBB(addr);
          if(bb != NULL)
            LOG("Withing bb: "<<hex<<bb->start()<<" code: "<<(int)bb->isCode());
          if(bb == NULL || bb->isCode() == false || bb->isValidIns(addr)) {
            newPointer((uint64_t)psbl_ptr32, PointerType::UNKNOWN,
              PointerSource::STOREDCONST,PointerSource::STOREDCONST,start_addr);
            ptr((uint64_t)psbl_ptr32)->size(4, start_addr);
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

bool
Cfg::processFallThrough(BasicBlock *bb, PointerSource t) {
  uint64_t fall = bb->fallThrough();
  //DEF_LOG("Processing fall through: "<<hex<<bb->start()<<"-"<<bb->end()<<"->"<<hex<<fall<<" BB type: "<<dec<<(int)bb->callType());
  if(bb->isCall() && bb->callType() == BBType::MAY_BE_RETURNING && ISCODE(t) == code_type::CODE
     && ISCODE(PointerSource::POSSIBLE_RA) != code_type::CODE) {
    if(fall != 0) {
#ifdef IGNOREMAYEXIT
      LOG("processing fall through: "<<hex<<fall<<" bb "<<hex<<bb->start());
      if(INVALID_CODE_PTR(fall)) {
        return false;
      }
      else if(addToCfg(fall,t) == false) {
        //bb->fallThrough(0);
        return false;
      }
#else
#ifdef EH_FRAME_DISASM_ROOT
      if(withinFn(bb->fallThrough()) == false) {
        LOG("Ignoring fall through since BB is MAY_BE_RETURNING: "<<
            hex<<bb->start()<<"->"<<hex<<bb->fallThrough());
        newPointer(bb->fallThrough(), PointerType::UNKNOWN,
            PointerSource::POSSIBLE_RA,rootSrc_,bb->end());
      }
      else {
        LOG("processing fall through: "<<hex<<fall<<" bb "<<hex<<bb->start());
        if(INVALID_CODE_PTR(fall)) {
          //bb->fallThrough(0);
          return false;
        }
        else if(addToCfg(fall,t) == false) {
          //bb->fallThrough(0);
          return false;
        }
      }
#else
#ifdef GROUND_TRUTH 
      if(withinFn(bb->fallThrough()) == false) {
        LOG("Ignoring fall through since BB is MAY_BE_RETURNING: "<<
            hex<<bb->start()<<"->"<<hex<<bb->fallThrough());
        newPointer(bb->fallThrough(), PointerType::UNKNOWN,
            PointerSource::POSSIBLE_RA,rootSrc_,bb->end());
      }
      else {
        LOG("processing fall through: "<<hex<<fall<<" bb "<<hex<<bb->start());
        if(INVALID_CODE_PTR(fall)) {
          //bb->fallThrough(0);
          return false;
        }
        else if(addToCfg(fall,t) == false) {
          //bb->fallThrough(0);
          return false;
        }
      }
#else
      LOG("Ignoring fall through since BB is MAY_BE_RETURNING: "<<
          hex<<bb->start()<<"->"<<hex<<bb->fallThrough());
      newPointer(bb->fallThrough(), PointerType::UNKNOWN,
          PointerSource::POSSIBLE_RA,rootSrc_,bb->end());
#endif
#endif
#endif
    }
  }
  else if(bb->isCall() && bb->callType() == BBType::MAY_BE_RETURNING 
          && fall != 0 && withinFn(bb->fallThrough()) == false) {
    LOG("Ignoring fall through since BB is MAY_BE_RETURNING: "<<
        hex<<bb->start()<<"->"<<hex<<bb->fallThrough());
    newPointer(bb->fallThrough(), PointerType::UNKNOWN,
        PointerSource::POSSIBLE_RA,rootSrc_,bb->end());
  }
  else if(fall != 0) {
    LOG("processing fall through: "<<hex<<fall<<" bb "<<hex<<bb->start());
    if(INVALID_CODE_PTR(fall)) {
      //bb->fallThrough(0);
      return false;
    }
    else if(addToCfg(fall,t) == false) {
      //bb->fallThrough(0);
      return false;
    }
  }

  return true;

}

bool
Cfg::processTarget(BasicBlock *bb, PointerSource t) {
  uint64_t tgt = bb->target();
  LOG("Processing target: "<<hex<<bb->start()<<"->"<<tgt);
  if(tgt != 0) {
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
    if(fall_through_ins.size() <= 0)
      return;
    if(fall_through_ins[0]->prefix().find("lock") != string::npos) {
      target = 0;
      bb->target(0);
      bb->lockJump(true);
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
  LOG("Processing address: " <<hex <<addrs<<" code type: "<<dec<<(int)t);
  if(disassembler_->invalid(addrs))
    return false;
  if(INVALID_CODE_PTR(addrs))
    return false;
  uint64_t chunk_end = isValidRoot(addrs,ISCODE(t));
  BasicBlock *bb = NULL;
  if(chunk_end == 0)
    return false;
  else if(chunk_end == addrs) {
    LOG("basic block at " <<hex <<addrs <<" already exists!!!");
    //processFallThrough(bb,t);
    bb = getBB(addrs);
    //if(bb == NULL) {
    //  DEF_LOG("Cannot find bb to process fall through: "<<hex<<addrs);
    //  exit(0);
    //}
    if(processFallThrough(bb,t) == false) {
      auto ins = bb->lastIns();
      if(ins->isCall() == false && ins->isJump() == false) {
        removeBB(bb);
        invalidPtr(addrs);
        return false;
      }
    }
  }
  else {
    LOG("Chunk Start: " <<hex <<addrs <<" Chunk end: " <<hex <<chunk_end);
    auto ins_list = disassembler_->getIns(addrs, 1000);
    if(ins_list.size() == 0) {
      LOG("No instruction found");
      invalidPtr(addrs);
      return false;
    }
    bb = new BasicBlock(addrs,t,rootSrc_);
    createBB(bb,ins_list, chunk_end, ISCODE(t));
#ifdef GROUND_TRUTH
    if(t == PointerSource::JUMPTABLE) {
      if(ins_list[0]->asmIns().find(".byte") != string::npos) {
        LOG("invalid instruction at addrs: "<<hex<<addrs);
        return false;
      }
    }
#endif
    bbCache_[bb->start()] = bb;
    checkLockPrefix(bb,ISCODE(t));
    addBBtoFn(bb,t);
    if(t == PointerSource::CALL_TGT_1) {
      ins_list = bb->insList();
      auto first_ins = ins_list[0];
      auto bytes = first_ins->insBinary();
      if(bytes.size() == 0) {
        LOG("invalid instruction at addrs: "<<hex<<addrs);
        removeBB(bb);
        invalidPtr(addrs);
        return false;
      }
      for(auto & ins : ins_list) {
        if(validOpCode(ins) == false) {
          LOG("invalid instruction at addrs: "<<hex<<addrs);
          removeBB(bb);
          invalidPtr(addrs);
          return false;
        }
      }
      //for(auto i = bb->start(); i < bb->boundary(); i++) {
      //  if(bb->isValidIns(i) == false) {
      //    auto cnf_bb = getBB(i);
      //    if(cnf_bb != NULL && 
      //      (cnf_bb->source() == PointerSource::KNOWN_CODE_PTR ||
      //       cnf_bb->source() == PointerSource::CALL_TGT_2)) {
      //      removeBB(bb);
      //      invalidPtr(addrs);
      //      return false;
      //    }
      //  }
      //}
    }
    if(processTarget(bb,t) == false) {
      removeBB(bb);
      invalidPtr(addrs);
      return false;
    }
    if(processFallThrough(bb,t) == false) {
      auto ins = bb->lastIns();
      if(ins->isCall() == false && ins->isJump() == false) {
        removeBB(bb);
        invalidPtr(addrs);
        return false;
      }
    }
  }
  if(bb->target() != 0) {
    auto tgt_bb = getBB(bb->target());
    if(tgt_bb == NULL) {
      LOG("Invalid target..removing BB: "<<hex<<bb->start());
      removeBB(bb);
      invalidPtr(addrs);
      return false;
    }
  }
  if(bb->fallThrough() != 0) {
    auto fall_bb = getBB(bb->fallThrough());
    if(fall_bb == NULL) {
      auto ins = bb->lastIns();
      if(ins->isCall() == false && ins->isJump() == false) {
        LOG("Invalid fall..removing BB: "<<hex<<bb->start());
        removeBB(bb);
        invalidPtr(addrs);
        return false;
      }
    }
  }
  BBType tgt_type;
  BBType fall_through_type;
  LOG("Finalizing: "<<hex<<addrs<<" - "<<hex<<bb);
  if(bb->type() ==  BBType::NA) {


    if(bb->fallThrough() != 0) {
      fall_through_type = getBBType(bb->fallThrough());//bb->fallThroughBB()->type();
    }
    else
      fall_through_type = BBType::NA;
    if(bb->target() != 0)
      tgt_type = getBBType(bb->target());//bb->targetBB()->type();
    else
      tgt_type = BBType::NA;
    LOG("Tgt type: "<<(int)tgt_type<<" fall type: "<<(int)fall_through_type);
    
    if(bb->fallThrough() == 0 && bb->target() == 0)
      bb->type(BBType::RETURNING);
    else if(bb->fallThrough() == 0)
      bb->type(tgt_type);
    else if(bb->target() == 0)
      bb->type(fall_through_type);
    else if(bb->isCall()) {
      bb->callType(tgt_type);
      if(tgt_type == BBType::NON_RETURNING || fall_through_type == BBType::NON_RETURNING)
        bb->type(BBType::NON_RETURNING);
      else if(tgt_type == BBType::MAY_BE_RETURNING || fall_through_type == BBType::MAY_BE_RETURNING)
        bb->type(BBType::MAY_BE_RETURNING);
      else if(tgt_type == BBType::NA)
        bb->type(tgt_type);
      else
        bb->type(fall_through_type);
    }
    else if(fall_through_type != tgt_type)
      bb->type(BBType::MAY_BE_RETURNING);
    else
      bb->type(tgt_type);
    if(bb->isCall() && bb->type() != BBType::NON_RETURNING && fall_through_type == BBType::NON_RETURNING)
      bb->type(BBType::NON_RETURNING);
  }

  LOG("BB created: "<<hex<<bb->start()<<" target: "<<hex<<bb->target()<<" fall: "
      <<hex<<bb->fallThrough()<<" "<<" type: "<<(int)bb->type()<<" call type: "<<(int)bb->callType());

  return true;
}

bool
Cfg::processIns(Instruction *ins, BasicBlock *bb, code_type t) {
  disassembled_.insert(ins->location());
  checkForPtr(ins);
  if(ins->isUnconditionalJmp() || ins->isCall()) {
    processIndrctJmp(ins, bb,t);
    if(ins->target() != 0)
      createFn(ins->isCall(), ins->target(),ins->location(),t);
    return true;
  }
  else if (ins->isJump() || ins->isHlt())
    return true;

  return false;
}

void
Cfg::createBB(BasicBlock *bb,vector <Instruction *> &ins_list, uint64_t chunk_end, code_type t) {
  /* Input: list of instructions.
   * Traverses the list until a control flow transfer is encountered or end of
   * the list is reached. 
   * Creates a basic block and adds to the map.
   */
  //DEF_LOG("populating instructions in BB: "<<hex<<bb->start());
  uint64_t end = 0;
  //vector <Instruction *> basic_block_ins;

  //bool is_non_returning_bb = false;
  uint64_t fall_through = 0;
  bool isLea = false;
  uint64_t target = 0;
  for(auto & ins:ins_list) {
    if(getBB(ins->location()) != NULL) {
      LOG("BB at "<<hex<<ins->location()<<" already exists. Breaking!!");
      if(end == 0) {
        LOG("Creating new bb for a previously existing bb.."<<hex<<bb->start());
        exit(0);
      }
      break;
    }
    fall_through = ins->fallThrough();
    target = ins->target();
    //basic_block_ins.push_back(ins);
    bb->addIns(ins);
    end = ins->location();
    if(isLea == false)
      isLea = ins->isLea();
    if(ins->isHlt() ||
      (ins->isUnconditionalJmp() && ins->isCall() == false)) {
      fall_through = 0;
    }
    LOG("instruction location: " <<hex <<ins->location() <<
     " Call value: " <<ins->isCall() <<" jump value: " <<ins->isJump()
     <<" fall: "<<hex<<fall_through);
    if(processIns(ins, bb, t))
      break;
  }
  //end = ins_list[ins_count - 1].get_location();
  LOG("Creating new bb: "<<hex<<bb->start()<<"-"<<end<<" fall: "<<fall_through<<" target: "<<target);
  NEWBB(bb, end, fall_through, target,isLea);

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
        auto p = ptr(start);
        LOG("Root: "<<hex<<start<<" ptr type: "<<dec<<(int)(p->type()));
        if(p->type() != PointerType::CP && 
           p->source() != PointerSource::GAP_PTR &&
           p->source() != PointerSource::PIC_RELOC &&
           p->source() != PointerSource::RIP_RLTV) {
          auto gap_bb = withinBB(start);
          LOG("Checking if pointer has linear scanned bb: "<<hex<<start);
          if(gap_bb == NULL) {
            for(auto i = start + 1; i < start + 17; i++) {
              gap_bb = getBB(i);
              if(gap_bb != NULL)
                break;
            }
            if(gap_bb == NULL) {
              LOG("Ignoring pointer since linear scan doesn't exist: "<<hex<<start);
              continue;
            }
          }
          LOG("Gap bb found: "<<hex<<gap_bb->start());
        }
        if(ignoreRoots_.find(ptr(start)->source()) == ignoreRoots_.end()) {
          if(ptr(start)->rootSrc() != PointerSource::NONE)
            rootSrc_ = ptr(start)->rootSrc();
          else
            rootSrc_ = ptr(start)->source();
          LOG("Disassembling root: "<<hex<<start);
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
    LOG("Extra reloc ptr: "<<hex<<r.ptr<<" storage: "<<r.storage);
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

  LOG("Starting ground truth disasm");
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
  if(type_ == exe_type::NOPIE)
    scanPsblPtrsGT();
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
    if(withinCodeSec(ptr) && fn != fn_map.end() && 
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

  //ignoreRoots_.insert(PointerSource::DEBUGINFO);
  //analyze();
  //ignoreRoots_.clear();
  processAllRoots();
  linkAllBBs();
  classifyPtrs();
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
        createFn(true, fn.first,fn.first,code_type::CODE);
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
              newPointer(*it,PointerType::UNKNOWN,PointerSource::EHFIRST,100);
            }
          }
      }
    }
    processAllRoots();
    disassembleGaps();
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
Cfg::scanForCalls(int call_cnt) {
  auto rx_secs = rxSections();
  unordered_map <uint64_t, int> target_cnt_map;
  for (auto & sec : rx_secs) {
    if(sec.sec_type == section_types::RX) {
      uint8_t *bytes = (uint8_t *)malloc(sec.size);
      uint64_t start_offt = utils::GET_OFFSET(exePath_,sec.vma);
      utils::READ_FROM_FILE(exePath_,(void *)bytes,start_offt,sec.size);
      for(auto i = 0; i < sec.size; i++) {
        auto bb = withinBB(sec.vma +i);
        if(bb == NULL && *(bytes + i) == 0xe8 && (sec.size - i) >= 5) {
          int32_t offt = *((int32_t *)(bytes + i + 1));
          if(abs(offt) > 128) {
            uint64_t target = (int64_t)sec.vma + i + 5 + offt;
            target_cnt_map[target] += 1;
            DEF_LOG("Scanned call: "<<hex<<sec.vma + i<<"->"<<target);
          }
        }
      }
    }
  }
  for(auto & t : target_cnt_map) {
    if(t.second >= call_cnt && withinCodeSec(t.first)) {
      if(call_cnt == 2)
        DEF_LOG("Call > 2...adding def code ptr: "<<hex<<t.first);
      PointerSource src = PointerSource::CALL_TGT_2;
      code_type ct = code_type::CODE;
      PointerType pt = PointerType::CP;
      if(call_cnt == 1) {
        src = PointerSource::CALL_TGT_1;
        ct = code_type::UNKNOWN;
        pt = PointerType::UNKNOWN;
      }
      newPointer(t.first, pt,src,src,0);
      createFn(true, t.first,t.first,ct);
      disasmRoots_.push(t.first);
    }
  }
}

#include <math.h>

extern bool disasm_only; 

void
Cfg::cnsrvtvDisasm() {
  //scanForCalls(2);
  processAllRoots();
  linkAllBBs();
  //updateBBTypes();
  classifyPtrs();
  DEF_LOG("Disassembling possible code");
  disassembleGaps();
  preCachedJumpTables();
  possibleCodeDisasm();
  if(disasm_only)
    addHintBasedEntries();
#ifdef DISASMONLY
  addHintBasedEntries();
#endif
  //propagateAllRoots();
  //phase1NonReturningCallResolution();
  //analyze();
  linkAllBBs();
  updateBBTypes();



  //markAllCallTgtsAsDefCode();
  //for(auto & ptr : ptr_map) {
  //  if(ptr.second->source() == PointerSource::CALL_TGT_1) {
  //    if(conflicts(ptr.first) == false) {
  //      auto ptr_bb = getBB(ptr.first);
  //      if(ptr_bb != NULL) {
  //        auto bb_list = bbSeq(ptr_bb);
  //        DEF_LOG("Marking single call target as def code: "<<hex<<ptr_bb->start());
  //        for(auto & bb2 : bb_list) {
  //          if(bb2->isCode() == false) {
  //            markAsDefCode(bb2->start());
  //          }
  //        }
  //      }
  //    }
  //  }
  //}
  //DEF_LOG("Disassembling gaps");
  //disassembleGaps();
  //analyze();
}

//void
//Cfg::checkFirstUseDef(vector <uint64_t> &psbl_entries) {
//  if(psbl_entries.size() > 0) {
//    vector <int64_t> all_entries;
//    vector <BasicBlock *> fin_bb_list;
//    for(auto & start : psbl_entries) {
//      auto bb = getBB(start);
//      if(bb != NULL) {
//        auto bb_list = bbSeq(bb);
//        if(validIns(bb_list) && validCF(bb_list)) {
//          all_entries.push_back(start);
//          fin_bb_list.insert(fin_bb_list.end(), bb_list.begin(), bb_list.end());
//        }
//      }
//    }
//    unordered_map<int64_t, vector<int64_t>> ind_tgts;
//    checkIndTgts(ind_tgts,fin_bb_list);
//    string dir = get_current_dir_name();
//    dumpIndrctTgt(/*TOOL_PATH + exeName_*/ dir + "/tmp/" + to_string(psbl_entries[0])
//        + ".ind",ind_tgts);
//    string file_name = /*TOOL_PATH + exeName_*/ dir + "/tmp/" + to_string(psbl_entries[0]) + ".s";
//    genFnFile(file_name,psbl_entries[0],fin_bb_list);
//    unordered_map<int64_t,int64_t> ins_sz = insSizes(fin_bb_list);
//    dumpInsSizes(/*TOOL_PATH + exeName_*/ dir + "/tmp/" + to_string(psbl_entries[0]) + ".sz",ins_sz);
//    bool valid_prog = analysis::load(file_name,ins_sz,ind_tgts,all_entries);
//    if (valid_prog) {
//       /* analyze one function at a time */
//       for (int func_index = 0; ; ++func_index) {
//          bool valid_func = analysis::analyze(func_index);
//          if (valid_func) {
//             auto psbl_entry = analysis::first_used_redef();
//             if(psbl_entry > 0) {
//               newPointer(psbl_entry, PointerType::UNKNOWN, PointerSource::GAP_PTR,PointerSource::GAP_PTR,0);
//               createFn(true, psbl_entry, psbl_entry,code_type::UNKNOWN);
//               addToCfg(psbl_entry, PointerSource::GAP_PTR);
//             }
//          }
//          else
//             break;
//       }
//    }
//  }
//}

void
Cfg::addHintBasedEntries() {
  auto all_ptrs = pointers();
  for(auto & ptr : all_ptrs) {
    if(ptr.second->source() == PointerSource::GAP_PTR) {
    //if(ptr.second->source() != PointerSource::JUMPTABLE) {
      auto ptr_bb = getBB(ptr.first);
      if(ptr_bb != NULL) {
        auto ins_list = ptr_bb->insList();
        //DEF_LOG("Gap start: "<<hex<<ptr.first<<":"<<ins_list[0]->asmIns());
        if(ins_list[0]->asmIns().find("nop") != string::npos ||
           ins_list[0]->asmIns().find("xchg %ax,%ax") != string::npos ||
           ins_list[0]->asmIns().find("xchgw %ax,%ax") != string::npos)
          continue;
        auto parents = ptr_bb->parents();
        bool call_fall = false;
        for(auto & p : parents) {
          if(p->isCall() && p->fallThrough() == ptr_bb->start()) {
            call_fall = true;
            break;
          }
        }
        if(call_fall)
          continue;
        auto last_ins = ptr_bb->lastIns();
        auto gap_end = ptr_bb->boundary();
        DEF_LOG("Finding gap end: "<<hex<<ptr.first<<" - "<<gap_end);
        if((last_ins->isCall() || last_ins->isJump()) && last_ins->insSize() >= 5) {
          DEF_LOG("Call or jump found: "<<last_ins->location()<<": "<<last_ins->asmIns());
          gap_end = last_ins->location();
        }
        else {
          auto bb = ptr_bb;
          while(bb->fallThrough() != 0/* && ctr <= 3*/) {
            bb = getBB(bb->fallThrough());
            if(bb == NULL)
              break;
            auto p = all_ptrs.find(bb->start());
            if(p != all_ptrs.end() && (p->second->source() == PointerSource::JUMPTABLE
               || p->second->source() == PointerSource::GAP_PTR)) {
              DEF_LOG("Jump table target or gap ptr found:"<<hex<<p->first);
              break;
            }
            auto last_ins = bb->lastIns();
            gap_end = last_ins->location() + last_ins->insSize();
            if(last_ins->isUnconditionalJmp() ||
               last_ins->isCall() || last_ins->asmIns().find("ret") != string::npos
               || last_ins->asmIns().find("ud2") != string::npos
               || last_ins->asmIns().find("hlt") != string::npos) {
              gap_end = last_ins->location();
              DEF_LOG("Call or jump found: "<<last_ins->location()<<": "<<last_ins->asmIns());
              break;
            }
            DEF_LOG("Finding gap end: "<<hex<<ptr.first<<" - "<<gap_end);
          }
        }
        checkPsblEntries(ptr.first, gap_end);
      }
    }
  }
}

void
Cfg::checkPsblEntries(uint64_t psbl_fn_start, uint64_t gap_end) {
  //auto new_bb = getBB(psbl_fn_start);
  //vector <Instruction *> ins_list;
  bool sig_found = false;
  DEF_LOG("Checking possible entries: "<<hex<<psbl_fn_start<<" - "<<gap_end);
  //if(new_bb != NULL) {
  //  ins_list = new_bb->insList();
  //  while(new_bb->fallThrough() != 0 && new_bb->fallThrough() < gap_end) {
  //    new_bb = getBB(new_bb->fallThrough());
  //    if(new_bb == NULL)
  //      break;
  //    auto fall_lst = new_bb->insList();
  //    ins_list.insert(ins_list.end(),fall_lst.begin(),fall_lst.end());
  //  }
  //  DEF_LOG("Checking fall through addresses for possible entry: "<<hex<<psbl_fn_start<<" ins count: "<<ins_list.size());
  //  for(auto ins_it = ins_list.begin(); ins_it != ins_list.end(); ins_it++) {
  //    vector <Instruction *> sub_lst;
  //    sub_lst.insert(sub_lst.end(), ins_it, ins_list.end());
  //    auto fn_sig = fnSigScore(sub_lst);
  //    auto loc = (*ins_it)->location();
  //    DEF_LOG("Fn sig score: "<<hex<<loc<<"->"<<dec<<fn_sig);
  //    if(fn_sig > 0) {
  //      newPointer(loc, PointerType::UNKNOWN, PointerSource::GAP_PTR,PointerSource::GAP_PTR,0);
  //      createFn(true, loc, loc,code_type::UNKNOWN);
  //      addToCfg(loc, PointerSource::GAP_PTR);
  //      //sig_found = true;
  //      break;
  //    }
  //  }
  //}
  uint64_t size = gap_end - (psbl_fn_start - 17);
  uint8_t *bytes = (uint8_t *)malloc(size);
  uint64_t start_offt = utils::GET_OFFSET(exePath_,psbl_fn_start - 17);
  utils::READ_FROM_FILE(exePath_,(void *) bytes, start_offt, size);
  int i = 0;
  for(auto start = psbl_fn_start - 17; start < gap_end; start++,i++) {
    if(*(bytes + i) == 0xe9 || *(bytes + i) == 0xe8) {
      start+=4;
      i+=4;
      continue;
    }
    if(*(bytes + i) == 0x41 ||
       *(bytes + i) == 0x55 ||
       *(bytes + i) == 0x53 ||
       *(bytes + i) == 0x54 ||
       (i < (size - 3) && *(bytes + i) == 0x48 &&
        *(bytes + i + 1) == 0x83 && *(bytes + i + 2) == 0xec)) {
      auto ins_lst = disassembler_->getIns(start, 20);
      if(ins_lst.size() > 0) {
        auto fn_sig = fnSigScore(ins_lst);
        DEF_LOG("Fn sig score: "<<hex<<start<<"->"<<dec<<fn_sig);
        if(fn_sig >= powl(2,21)) {
          newPointer(start, PointerType::UNKNOWN, PointerSource::GAP_PTR,PointerSource::GAP_PTR,0);
          createFn(true, start, start,code_type::UNKNOWN);
          addToCfg(start, PointerSource::GAP_PTR);
          sig_found = true;
          break;
        }
      }
    }
    //if(start % 8 == 0) {
    //  DEF_LOG("Adding possible entry: "<<hex<<start);
    //  newPointer(start, PointerType::UNKNOWN, PointerSource::GAP_PTR,PointerSource::GAP_PTR,0);
    //  createFn(true, start, start,code_type::UNKNOWN);
    //  addToCfg(start, PointerSource::GAP_PTR);
    //}
  }
  if(sig_found == false /*&& new_bb != NULL*/) {
    DEF_LOG("Signature not found..adding aligned locations");
    i = 0;
    auto chk_start = psbl_fn_start - 17;
    while(chk_start < gap_end) {
      auto bb = withinBB(chk_start);
      if(bb != NULL) {
        auto parents = bb->parents();
        bool call_fall = false;
        for(auto & p : parents) {
          if(p->isCall() && p->fallThrough() == bb->start()) {
            call_fall = true;
            break;
          }
        }
        if(call_fall) {
          i += (bb->boundary() - chk_start);
          chk_start = bb->boundary();
        }
        else
          break;
      }
      else
        break;
    }
    for(auto start = chk_start; start < gap_end; start++,i++) {
      if(*(bytes + i) == 0xe9 || *(bytes + i) == 0xe8) {
        start+=4;
        i+=4;
        continue;
      }
      DEF_LOG("Checking address: "<<hex<<start);
      if(start % 8 == 0) {
        DEF_LOG("Adding possible entry: "<<hex<<start);
        newPointer(start, PointerType::UNKNOWN, PointerSource::GAP_PTR,PointerSource::GAP_PTR,0);
        createFn(true, start, start,code_type::UNKNOWN);
        addToCfg(start, PointerSource::GAP_PTR);
      }
    }
  }
  free(bytes);
}

void
Cfg::disassembleGaps() {
  auto all_gaps = getGaps();
  for (auto & g : all_gaps) {
    vector <Instruction *> linear_scan;
    DEF_LOG("Disassembling gap: "<<hex<<g.start_<<"-"<<hex<<g.end_);
    for(uint64_t i = g.start_; i < g.end_;) {
      auto ins_list = disassembler_->getIns(i, 200);
      if(ins_list.size() == 0)
        i++;
      else {
        for(auto & ins : ins_list) {
          /*
          if((ins->isCall() || ins->isJump()) &&
              ins->target() != 0 &&
              withinCodeSec(ins->target()) == false) {
            i++;
            break;
          }
          */
          linear_scan.push_back(ins);
          i = ins->location() + ins->insSize();
          if(i >= g.end_)
            break;
        }
        //linear_scan.insert(linear_scan.end(), ins_list.begin(), ins_list.end());
        //i = ins_list[ins_list.size() - 1]->location() + ins_list[ins_list.size() - 1]->insSize();
      }
    }
    DEF_LOG("Linear scan complete. Instruction count: "<<linear_scan.size());
    if(linear_scan.size() > 0) {
      auto last_ins = linear_scan[linear_scan.size() - 1];
      if(last_ins->isUnconditionalJmp() == false && last_ins->asmIns().find("ret") == string::npos) {
        //get instructions untill you reach an unconditional jump or return
        DEF_LOG("Last ins not a CF: "<<last_ins->location()<<": "<<last_ins->asmIns()<<". Continue linear scan till you find CF");
        while(true) {
          auto next_addr = last_ins->location() + last_ins->insSize();
          auto ins_list = disassembler_->getIns(next_addr, 200);
          if(ins_list.size() == 0) break;
          bool cf_found = false;
          for(auto & ins : ins_list) {
            linear_scan.push_back(ins);
            last_ins = ins;
            if((last_ins->isUnconditionalJmp() && last_ins->isCall() == false) ||
               (last_ins->isCall() && last_ins->insSize() >= 5) ||
               last_ins->asmIns().find("ret") != string::npos) {
              cf_found = true;
              DEF_LOG("CF found at: "<<hex<<last_ins->location()<<" breaking");
              break;
            }
          }
          if(cf_found)
            break;
        }
      }
    }

    uint64_t psbl_fn_start = 0;
    uint64_t prev_ins_boundary = 0;
    for(auto & ins : linear_scan) {
      bool valid_ins = CFValidity::validOpCode(ins) && 
                       CFValidity::validMem(ins) && 
                       CFValidity::validPrfx(ins) && 
                       CFValidity::validUsrModeIns(ins);
      auto bin = ins->insBinary();
      if(bin.size() > 1 && bin[0] == 0x00 && bin[1] == 0x00)
        valid_ins = false;
      if(!valid_ins) {
        psbl_fn_start = 0;
        continue;
      }
      if(psbl_fn_start == 0 /*&& valid_ins && ins->asmIns().find("pop") == string::npos*/) {
        psbl_fn_start = ins->location();
        prev_ins_boundary = ins->location() + ins->insSize();
      }
      else {
        if((ins->location() - prev_ins_boundary) > 0) {
          psbl_fn_start = ins->location();
          prev_ins_boundary = ins->location() + ins->insSize();
        }
        else
          prev_ins_boundary = ins->location() + ins->insSize();
      }
      /*
      else if(!valid_ins) {
        psbl_fn_start = 0;
        continue;
      }
      */
      if((ins->isUnconditionalJmp() && ins->isCall() == false) ||
         (ins->isCall() && ins->insSize() >= 5)
         || ins->asmIns().find("ret") != string::npos
         || ins->asmIns().find("hlt") != string::npos
         || ins->asmIns().find("ud2") != string::npos) {
        DEF_LOG("potential function exit: "<<hex<<ins->location()<<": "<<ins->asmIns()<<" psbl fn start: "<<hex<<psbl_fn_start);
        if(ins->location() - psbl_fn_start >= 0) {
          auto bb = getBB(psbl_fn_start);
          if(bb == NULL) {
            DEF_LOG("potential function: "<<hex<<psbl_fn_start<<"->"<<hex<<ins->location());
            newPointer(psbl_fn_start, PointerType::UNKNOWN,
              PointerSource::GAP_PTR,PointerSource::GAP_PTR,psbl_fn_start);
            createFn(true, psbl_fn_start, psbl_fn_start,code_type::UNKNOWN);
            addToCfg(psbl_fn_start, PointerSource::GAP_PTR);
            //checkPsblEntries(psbl_fn_start, ins->location());
          }
          else
            newPointer(psbl_fn_start, PointerType::UNKNOWN,
              PointerSource::GAP_HINT,PointerSource::GAP_HINT,psbl_fn_start);
          bb = getBB(psbl_fn_start);
          if(bb != NULL) {
            auto ins_list = bb->insList();
            if(ins_list[0]->asmIns().find("nop") != string::npos ||
               ins_list[0]->asmIns().find("xchg") != string::npos) {
              auto next_addr = psbl_fn_start + ins_list[0]->insSize();
              newPointer(next_addr, PointerType::UNKNOWN,
                PointerSource::GAP_HINT,PointerSource::GAP_HINT,next_addr);
            }
          }
        }
        psbl_fn_start = 0;//ins->location() + ins->insSize();
      } 
    } 
  }
  linkAllBBs();
}
/*
void
Cfg::disassembleGaps() {
  auto all_gaps = getGaps();
  priority_queue<Gap, vector<Gap>, CompareGap> gapQ;
  for(auto & g : all_gaps) {
    DEF_LOG("Adding gap to priority queue: "<<hex<<g.start_<<" score: "<<dec<<g.score_);
    gapQ.push(g);
  }
  while(!gapQ.empty()) {
    auto g = gapQ.top();
    gapQ.pop();

    DEF_LOG("Disassembling gap: "<<hex<<g.start_);
    //Phase 1 - Disassemble from hints
    unordered_set <uint64_t> invalid_locs;
    while(!g.hintQ_.empty()) {
      auto h = g.hintQ_.top();
      g.hintQ_.pop();
      if(invalid_locs.find(h.addrs_) != invalid_locs.end())
        continue;
      DEF_LOG("Disassembling gap hint: "<<hex<<h.addrs_);
      newPointer(h.addrs_, PointerType::UNKNOWN,
        PointerSource::GAP_HINT,PointerSource::GAP_HINT,0);
      addToCfg(h.addrs_, PointerSource::GAP_HINT);
      auto bb = getBB(h.addrs_);
      if(bb != NULL) {
        linkAllBBs();
        auto bb_lst = bbSeq(bb);
        if(validIns(bb_lst) && validCF(bb_lst)) {
          auto cnf_bb_lst = conflictingBBs(bb->start());
          bool discard = false;
          for(auto & cnf_bb : cnf_bb_lst) {
            if(cnf_bb->isCode() || cnf_bb->hintScore() > h.score_) {
              discard = true;
              break;
            }
          }
          if(discard == false) {
            for(auto & bb2 : bb_lst) {
              bb2->roots(bb);
              bb2->hintScore(h.score_);
              for(auto i = bb2->start(); i < bb2->boundary(); i++)
                if(bb2->isValidIns(i) == false)
                  invalid_locs.insert(i);
            }
          }
          else
            invalid_locs.insert(bb->start());
        }
      }
    }

    //Phase 2: Find function entries
    for(auto i = g.start_; i < g.end_; i++) {
      if(invalid_locs.find(i) != invalid_locs.end())
        continue;
      newPointer(i, PointerType::UNKNOWN,
        PointerSource::GAP_PTR,PointerSource::GAP_PTR,0);
      addToCfg(i, PointerSource::GAP_PTR);
    }
  }
  linkAllBBs();
  auto ptr_map = pointers();
  for(auto & ptr : ptr_map) {
    if(ptr.second->source() == PointerSource::GAP_PTR) {
      auto bb = getBB(ptr.first);
      DEF_LOG("Validating gap address: "<<hex<<ptr.first);
      if(bb != NULL) {
        auto lst = bbSeq(bb);
        if(validIns(lst) && validCF(lst)) {
          bool invalid = false;
          auto cnf_bb_lst = conflictingBBs(bb->start());
          long double score = probScore(ptr.first);
          for(auto & cnf_bb : cnf_bb_lst) {
            if(cnf_bb->isCode() || cnf_bb->hintScore() > score) {
              invalid = true;
              break;
            }
          }
          if(invalid) {
            DEF_LOG("Conflicts high score hint");
            ptr.second->type(PointerType::DP);
          }
        }
        else {
          DEF_LOG("invalid ins");
          ptr.second->type(PointerType::DP);
        }
      }
    }
  }

}
*/
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
  chkJmpTblRewritability();
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

  ofile.open("tmp/" + file_name + "_64bitFP.data");
  for(auto & ptr : ptr_map) {
    auto loc = ptr.second->storages(8);
    if(loc.size() > 0 && ptr.second->type() == PointerType::UNKNOWN)
      ofile<<hex<<ptr.first<<endl;
  }
  ofile.close();

  return;
#endif

#ifdef KNOWN_CODE_POINTER_ROOT
//#ifdef DISASMONLY
//  if(utils::file_exists("tmp/cfg.present")) {
//    LOG("Cfg already present. Skipping disassembly and reading cfg");
//    readCfg();
//    linkAllBBs();
//    classifyPtrs();
//  }
//  else {
//    LOG("Cfg not present. Starting disassembly");
//    cnsrvtvDisasm();
//  }
//#else
  cnsrvtvDisasm();
//#endif
#ifdef CFGCONSISTENCYCHECK
  saveCnsrvtvCode();
  cfgConsistencyAnalysis();
  //dump();
#else
  //dump();
#endif
  classifyPtrs();
  chkJmpTblRewritability();
  guessJumpTable();
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
  guessJumpTable();
//#ifdef CFGCONSISTENCYCHECK
  saveCnsrvtvCode();
  cfgConsistencyAnalysis();
//#endif
  classifyPtrs();
  chkJmpTblRewritability();
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
Cfg::handleLoopIns(vector <BasicBlock *> &bb_list) {
  //vector <BasicBlock *> tramp_bbs;
  for(auto & bb : bb_list) {
    if(bb->lastIns()->isJump() && bb->lastIns()->asmIns().find("loop") != string::npos &&
       bb->targetBB() != NULL && bb->target() != bb->start()) {
      DEF_LOG("Handling loop ins: "<<hex<<bb->start());
      bb->addTrampToTgt();
      //randomizer_->addTrampForBB(bb->targetBB());
      //auto tramp_bb = bb->targetBB()->tramp();
      //bb->mergeBB(tramp_bb);
      //tramp_bbs.push_back(tramp_bb);
      //bb->targetBB(tramp_bb);
    }
  }
  //bb_list.insert(bb_list.end(), tramp_bbs.begin(), tramp_bbs.end());
}

void
Cfg::reAddFallThrough(vector <BasicBlock *> &bb_list) {
  for(auto & bb : bb_list) {
    if(bb->isCall() && bb->fallThroughBB() == NULL) {
      auto fall = bb->lastIns()->fallThrough();
      auto fall_bb = getBB(fall);
      if(fall_bb != NULL) {
        DEF_LOG("Re adding fall through: "<<hex<<bb->start()<<"->"<<fall);
        bb->fallThrough(fall);
        bb->fallThroughBB(fall_bb);
      }
    }
  }
}

void
Cfg::printFunc(uint64_t fstart, string file_name) {
  /* Prints ASM for a function
   */
  DEF_LOG("Printing function: "<<hex<<fstart);
  auto fn_map = funcMap();
  if(if_exists(fstart, fn_map) == false) {
    DEF_LOG("Function not present");
    return;
  }
  Function *f = fn_map[fstart];
  vector <BasicBlock *> defbbs = f->getDefCode();
  handleLoopIns(defbbs);
  reAddFallThrough(defbbs);
  vector <BasicBlock *> unknwnbbs = f->getUnknwnCode();
  reAddFallThrough(unknwnbbs);
  vector <BasicBlock *> psbl_code;
  for(auto & bb : unknwnbbs) {
    if(dataByProperty(bb) == false) {
      DEF_LOG("Adding psbl bb: "<<hex<<bb->start());
      psbl_code.push_back(bb);
    }
  }
  handleLoopIns(psbl_code);
  //DEF_LOG("Handling loops done");
#ifdef OPTIMIZED_EH_METADATA 
  if(defbbs.size() > 0) {
    //Intra unwinding block randomization for definite code.
    auto unwind_it = unwinding_info.find(fstart);
    if(unwind_it != unwinding_info.end()) {
      set <uint64_t> all_unwind_blks
        = unwind_it->second.get_all_unwinding_blks(); 
      //bool blk_start = true;
      vector <BasicBlock *> bb_list;
      for(auto & bb : defbbs) {
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
  }
  if (psbl_code.size() > 0)  {
    //Since EH metadata for possible code is not optimized at this point, follow
    //normal randomization.
    randomizer_->print(psbl_code, file_name, fstart);
  }
#else
  //DEF_LOG("Printing def code bbs");
  if(defbbs.size() > 0)
    randomizer_->print(defbbs, file_name, fstart);
  //DEF_LOG("Printing psbl code bbs");
  if (psbl_code.size() > 0) {
    DEF_LOG("First bb: "<<hex<<psbl_code[0]->start());
    randomizer_->print(psbl_code, file_name, fstart);
  }
#endif
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
    uint64_t const_mem = ins->constPtr();
    if(const_mem != 0) {
      LOG("Creating data ptr: "<<hex<<ptr_val);
      newPointer(const_mem, PointerType::DP,
          PointerSource::CONSTMEM,rootSrc_, ins->location());
    }
  }
}

void
Cfg::processIndrctJmp(Instruction *call_ins, BasicBlock *bb,code_type t) {
  //LOG("Call ins addrs: "<<hex<<call_ins->location()<<" is relative"<<call_ins->isRltvAccess());
  if(call_ins->isRltvAccess()) {
    // Special handling for LINUX to add the address of main,
    // __libc_csu_init and __libc_csu_fini.
    DEF_LOG("Jump slot: "<<hex<<call_ins->ripRltvOfft());
    uint64_t jump_slot = call_ins->ripRltvOfft();
    if(call_ins->isCall()  && jump_slot == libcStrtMain_ && t==code_type::CODE) {
      DEF_LOG("libc_Start_main call at: "<<hex<<call_ins->location());
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
      DEF_LOG("exit call found. Marking bb: "<<hex<<bb->start()<<" non returning");
      bb->type(BBType::NON_RETURNING);
    }
    else if(mayExitCall(jump_slot)) {
      DEF_LOG("may exit call found. Marking bb: "<<hex<<bb->start()<<" may be returning");
      bb->type(BBType::MAY_BE_RETURNING);
    }
    if(isPlt(jump_slot))
      call_ins->isPltJmp(true);
    //  call_ins->atRequired(false);
  }
}

