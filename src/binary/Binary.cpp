#include "Binary.h"
#include "Pointer.h"
#include "disasm.h"
#include <stack>
#include <time.h>

using namespace SBI;

bool disasm_only = false; 
bool dump_cfg = false;

extern map <uint64_t, call_site_info> all_call_sites;	//contains info
//regarding try-catch blocks and landing pads.

extern map <uint64_t, cfi_table> unwinding_info;

exception_handler eh_frame;	//kept global so that every module can access it.

void
section_ends(vector <uint64_t> & ends,vector <section> &secs, section_types t) {
  for(auto & s : secs) {
    if(s.sec_type == t) {
      LOG("Section: "<<s.name<<" end: "<<hex<<s.vma + s.size);
      ends.push_back(s.vma + s.size);
    }
  }
}

Binary::Binary(string Binary_path) {
  
  exePath_ = Binary_path;
  manager_ = new binary_class(exePath_);
  rxSections_ = manager_->sections(section_types::RorX);
  roSections_ = manager_->sections(section_types::RONLY);
  rwSections_ = manager_->sections(section_types::RW);

  //get trampoline addresses for exit function calls.

  exitCallPlt_ = manager_->exitPlts();
  mayExitPlt_ = manager_->mayExitPlts();
  allPltSlots_ = manager_->allJmpSlots();
  //get trampoline address for __libc_Start_main function.

  libcStartMain_ = manager_->jmpSlot("__libc_start_main");
  for(section & sec:rxSections_) {
    if(sec.sec_type == section_types::RX) {
      uint64_t sec_end = sec.vma + sec.size;
      if(sec_end > codeSegmentEnd_)
        codeSegmentEnd_ = sec.vma + sec.size;

      if(sec.vma < codeSegmentStart_)
        codeSegmentStart_ = sec.vma;
    }
  }
  vector <uint64_t> sec_ends;
  section_ends(sec_ends,rxSections_,section_types::RX);
#ifdef DATA_DISASM
  section_ends(sec_ends,rwSections_, section_types::RW);
  section_ends(sec_ends,rxSections_,section_types::RONLY);
#endif
  disassembler_ = new DisasmEngn(exePath_,sec_ends);
  picConstReloc_ = manager_->relocatedPtrs(rel::CONSTPTR_PIC);
  auto range = manager_->progMemRange();
  codeCFG_ = new Cfg(range.first, range.second,exePath_);
#ifdef KNOWN_CODE_POINTER_ROOT
#ifdef DISASMONLY
  if(utils::file_exists("tmp/cfg.present") == false) {
    init();
  }
#else
  LOG("Performing initialization tasks!!!");
  init();
#endif
#else
  init();
#endif
  set_codeCFG_params();
}

void
Binary::init() {
  //exception_handler eh;
  //eh_frame = eh;
  all_call_sites.clear();
  unwinding_info.clear();
  eh_frame.read_eh_frame_hdr(exePath_);
  eh_frame.read_eh_frame(exePath_);
  populate_functions();
  populate_pointers();
  map_functions_to_section();
  //disassembler_->createInsCache(codeSegmentStart_,codeSegmentEnd_);
#ifdef GROUND_TRUTH
  if(manager_->type() == exe_type::NOPIE) {
    xtraConstReloc_ = manager_->relocatedPtrs(rel::CONSTPTR_NOPIC);
    for(auto & r : xtraConstReloc_) {
      //if(if_exists(r.ptr,pointerMap_) &&
      //    pointerMap_[r.ptr]->type() == PointerType::CP) {
        LOG("Extra reloc const ptr: "<<hex<<r.ptr<<" at "<<hex<<r.storage);
        ADDPOINTER(r.ptr, PointerType::UNKNOWN,
            PointerSource::EXTRA_RELOC_CONST,r.storage);
      //}
    }
  }
  pcrelReloc_ = manager_->relocatedPtrs(rel::PCREL);
#endif
}

Binary::~Binary() {
  for(auto it = pointerMap_.begin(); it != pointerMap_.end(); it++)
    delete(it->second);

  for(auto it = funcMap_.begin(); it != funcMap_.end(); it++)
    delete(it->second);
}

void
Binary::set_codeCFG_params() {
  /* Initialize parameters needed by CFG object.
   */
  codeCFG_->codeSegEnd(codeSegmentEnd_);
  codeCFG_->libcStartMain(libcStartMain_);
  codeCFG_->disassembler(disassembler_);
  codeCFG_->exePath(exePath_);
  codeCFG_->pointers(pointerMap_);
  codeCFG_->functions(funcMap_);
  codeCFG_->exitCall(exitCallPlt_);
  codeCFG_->mayExitPlt(mayExitPlt_);
  codeCFG_->allPltSlots(allPltSlots_);
  codeCFG_->type(manager_->type());
  codeCFG_->dataSegmntStart(rwSections_[0].vma);
  codeCFG_->rxSections(rxSections_);
  codeCFG_->entryPoint(entryPoint_);
  codeCFG_->roSection(roSections_);
  codeCFG_->rwSections(rwSections_);
  codeCFG_->pcrelReloc(pcrelReloc_);
  codeCFG_->xtraConstReloc(xtraConstReloc_);
  codeCFG_->picConstReloc(picConstReloc_);
}

void
Binary::disassemble() {
  //string key("/");
  //size_t found = exePath_.rfind(key);
  //string exeName = exePath_.substr(found + 1);

  codeCFG_->disassemble();
  pointerMap_ = codeCFG_->pointers();
  funcMap_ = codeCFG_->funcMap();
  //ofstream ofile("tramp.s");


  /*
  auto all_ras = codeCFG_->allReturnAddresses();
  for(auto & r : all_ras) {
    if(added.find(r) == added.end()) {
      added.insert(r);
      string sym = codeCFG_->getSymbol(r);
      if(sym != "") {
        manager_->addAttEntry(r,".8byte " + sym + "- .elf_header_start",
            ".8byte " + sym + " - " + ".elf_header_start",1);
      }
      ctr++;
    }
  }
  */

#ifdef OPTIMIZED_EH_METADATA
  mark_leaf_functions();
  reduce_eh_metadata();
#endif
  //DEF_LOG("Disassembly complete..printing assembly");
  codeCFG_->printOriginalAsm();
  codeCFG_->printDeadCode();
  if(dump_cfg)
    codeCFG_->dump();
}

void
Binary::hookPoints() {
  //for(auto & p : pointerMap_) {
  //  if((p.second->type() == PointerType::UNKNOWN ||
  //      p.second->type() == PointerType::CP ||
  //      p.second->type() == PointerType::DEF_PTR) &&
  //      codeCFG_->withinCodeSec(p.first) &&
  //      (p.second->symbolizable(SymbolizeIf::CONST) ||
  //       p.second->symbolizable(SymbolizeIf::IMMOPERAND) ||
  //       p.second->symbolizable(SymbolizeIf::RLTV) ||
  //       p.second->symbolizable(SymbolizeIf::JMP_TBL_TGT))) {
  //    hookPoints_.push_back(p.first);
  //  }
  //}
  unordered_set <uint64_t> added;
  for(auto & p : pointerMap_) {
    DEF_LOG("pointer: "<<hex<<p.first<<" source: "<<(int)p.second->source());
    if(codeCFG_->withinCodeSec(p.first) && 
       (p.second->symbolizable(SymbolizeIf::CONST) ||
        p.second->symbolizable(SymbolizeIf::IMMOPERAND) ||
        p.second->symbolizable(SymbolizeIf::RLTV) ||
        p.second->symbolizable(SymbolizeIf::JMP_TBL_TGT))) {
      DEF_LOG("Adding hook point: "<<hex<<p.first);
      added.insert(p.first);
      hookPoints_.push_back(p.first);
    }
    else
      DEF_LOG("Ignoring pointer for hooking: "<<hex<<p.first);
  }
  for(auto & f : funcMap_) {
    auto entries = f.second->allEntries();
    for(auto & e : entries) {
      if(added.find(e) == added.end() && codeCFG_->definiteCode(e)) {
        DEF_LOG("Adding hook point: "<<hex<<e);
        hookPoints_.push_back(e);
      }
    }
  }
  hookPoints_.push_back(codeSegmentEnd_); //Pushing code segment end to ease space calculation.
  sort(hookPoints_.begin(), hookPoints_.end());
}

uint64_t
Binary::nextHookPoint(uint64_t addr) {
  for(auto & h : hookPoints_) {
    if (h <= addr)
      continue;
    return h;
  }
  return codeSegmentEnd_;
}

uint64_t
Binary::findSecondHookSpace(uint64_t addrs) {
  //for(auto & h : hookPoints_) {
  //  if(h < addrs && (addrs - h) > 255)
  //    continue;
  //  if(addrs < h && ( h - addrs ) > 255)
  //    return 0;
  //  uint64_t next_hook = nextHookPoint(h);
  //  if((h + 10) < next_hook)
  //    return (h + 5);
  //}

  auto start = addrs + 2 - 127;
  auto end = addrs + 2 + 127;

  while (start < end) {
    auto cur_block = is_within(start, trampData_);
    auto next_block = next_iterator(start, trampData_);
    auto blk_end = codeSegmentEnd_;
    if(next_block != trampData_.end())
      blk_end = next_block->first;
    if(blk_end >= end)
      blk_end = end;
    auto space_start = start;
    if(cur_block != trampData_.end() && 
       space_start < (cur_block->first + cur_block->second.size()))
      space_start = cur_block->second.size() + cur_block->first;
    if(space_start < codeSegmentStart_)
      space_start = codeSegmentStart_;
    auto space = blk_end - space_start;
    if(space >= 5)
      return space_start;
    start = blk_end;
  }

  return 0;
}

void
Binary::calcTrampData() {
  hookPoints();
  vector <pair<uint64_t,int>> phase2;
  //Phase 1: check 5 byte space
  unsigned int sz = (unsigned int)hookPoints_.size();
  for(unsigned int i = 0; i < (sz - 1); i++) {
    DEF_LOG("Checking hook point: "<<hex<<hookPoints_[i]);
    auto next_pos = i + 1;
    uint64_t next_ptr = 0;
    if(next_pos < sz) {
      next_ptr = hookPoints_[next_pos];
    }
    uint64_t space = next_ptr - hookPoints_[i];
    auto p = pointerMap_.find(hookPoints_[i]);
    if(p == pointerMap_.end()) {
      DEF_LOG("No pointer for hook point: "<<hex<<hookPoints_[i]);
      continue;
    }
    if(p->second->type() == PointerType::CP) {
      if(space >= 5) {
        DEF_LOG("Phase 1 Space found for hook: "<<hex<<hookPoints_[i]<<": "<<5);
        //hookTgts_.push_back(make_pair(hookPoints_[i],manager_->newSymVal(hookPoints_[i])));
        auto opcode = utils::hook(hookPoints_[i], manager_->newSymVal(hookPoints_[i]));
        trampData_[hookPoints_[i]] = opcode;
      }
      else {
        DEF_LOG("Pushing to phase 2: "<<hex<<hookPoints_[i]);
        phase2.push_back(make_pair(hookPoints_[i],space));
      }
    }
    else {
      DEF_LOG("Hook point is data: "<<hex<<hookPoints_[i]);
      uint8_t *data = (uint8_t *) malloc(space);
      uint64_t offset = utils::GET_OFFSET(exePath_,hookPoints_[i]);
      utils::READ_FROM_FILE(exePath_,(void *)data,offset,space);
      vector <uint8_t> bytes;
      for(int i = 0; i < space; i ++)
        bytes.push_back(data[i]);
      trampData_[hookPoints_[i]] = bytes;
    }
  }

  //Phase 2 -- finding short jump locations
  vector <uint64_t> phase3;
  for(auto & p : phase2) {
    if(p.second >= 2) {
      uint64_t short_tgt = findSecondHookSpace(p.first);
      if(short_tgt != 0) {
        DEF_LOG("Phase 2 found short target: "<<hex<<p.first<<"->"<<hex<<short_tgt);
        //hookTgts_.push_back(make_pair(p.first,short_tgt));
        auto short_jmp =  utils::hook(p.first,short_tgt);
        trampData_[p.first] = short_jmp;
        uint64_t new_addr = manager_->newSymVal(p.first);
        DEF_LOG("New address: "<<hex<<new_addr);
        //hookTgts_.push_back(make_pair(short_tgt,new_addr));
        auto long_jmp = utils::hook(short_tgt,new_addr);
        trampData_[short_tgt] = long_jmp;
      }
      else {
        DEF_LOG("Pushing to phase 3: "<<hex<<p.first);
        phase3.push_back(p.first);
      }
    }
    else {
      LOG("Pushing to phase 3: "<<hex<<p.first);
      phase3.push_back(p.first);
    }
  }

  //Phase 3 -- left over pointers are those
  //    1) Do not have space > 2 bytes
  //    2) Couldn't find nearest location with 5 bytes.
  //
  // For now, Just putting the bytes as it is.
  //    1) May have jumps whose target may need hooking. Ignoring this case for
  //       now.

  for(auto & p : phase3) {
    DEF_LOG("Phase 3: Putting hlt bytes for: "<<hex<<p);
    //auto bb = codeCFG_->withinBB(p);
    vector <uint8_t> opcodes;
    uint64_t next_hook = nextHookPoint(p);
    int size = next_hook - p;
    for(int i = 0; i < size; i++)
      opcodes.push_back(0xf4);
    trampData_[p] = opcodes;
  }

  //for(unsigned int i = 0; i < (sz - 1); i++) {
  //  auto next_pos = i + 1;
  //  uint64_t next_ptr = 0;
  //  if(next_pos < sz) {
  //    next_ptr = hookPoints_[next_pos];
  //  }
  //  auto p = hookPoints_[i];
  //  uint64_t space = next_ptr - p;
  //  auto data_sz = trampData_[p].size();
  //  for(auto i = data_sz; i < space; i++)
  //     trampData_[p].push_back(0xf4);
  //}

  //generate hooks for Phase 1 and phase 2 candidates

  //for(auto & h : hookTgts_) {
  //  vector <uint8_t> opcode = utils::hook(h.first,h.second);
  //  trampData_[h.first] = opcode;
  //}
  //uint64_t header_sz = manager_->exeHdrSz() + manager_->newPHdrSz(); 
  //for(auto & sec : roSections_) {
  //  if(sec.offset > header_sz) {
  //    uint8_t *data = (uint8_t *) malloc(sec.size);
  //    utils::READ_FROM_FILE(exePath_,(void *)data,sec.offset,sec.size);
  //    vector <uint8_t> bytes;
  //    for(int i = 0; i < sec.size; i ++)
  //      bytes.push_back(data[i]);
  //    trampData_[sec.vma] = bytes;
  //    free(data);
  //  }
  //}

}

void
Binary::rewrite() {
  disassemble();

#ifdef DISASMONLY
  exit(0);
#endif
  if(disasm_only)
    exit(0);
  //install_segfault_handler();
  //check_segfault_handler();
  instrument();

  for(auto & ptr : pointerMap_) {
    string sym = "";
    auto bb = codeCFG_->getBB(ptr.first);
    if(bb != NULL && bb->alreadyInstrumented(InstPoint::SHSTK_FUNCTION_ENTRY)) {
      sym = bb->shStkTrampSym();
    }
    else
      sym = codeCFG_->getSymbol(ptr.first);
    if(ptr.second->type() == PointerType::CP /*&& it->second->encodable() == true*/) {
      manager_->addAttEntry(ptr.first,".8byte " + to_string(ptr.first),
                            ".8byte " + sym + " - " + ".elf_header_start",
                            sym, 0);
      if(FULL_ADDR_TRANS == false)
        manager_->ptrsToEncode(ptr.first);
    }
    else if(ptr.second->type() != PointerType::DP){
      if(sym != "") {
        manager_->addAttEntry(ptr.first,".8byte " + to_string(ptr.first),
                              ".8byte " + sym + " - " + ".elf_header_start",
                              sym, 0);
      }
    }
  }

  unordered_set<uint64_t> added;
  for(auto & x : all_call_sites) {
    auto ptr = x.second.landing_pad;
    if(added.find(ptr) == added.end()) {
      added.insert(ptr);
      string sym = codeCFG_->getSymbol(ptr);
      if(sym != "") {
        manager_->addAttEntry(ptr,".8byte " + sym + " - .elf_header_start",
                              ".8byte " + sym + " - " + ".elf_header_start",
                              sym, 1);
        //if(RA_OPT == false)
        //  manager_->addAttEntry(ptr,".8byte " + to_string(ptr),
        //                      ".8byte " + sym + " - " + ".elf_header_start",
        //                      sym, 0);
      }
    }
  }
  genInstAsm();
  string file_name = print_assembly();
  manager_->rewrite(file_name);
#ifdef STATIC_TRANS
  //if(manager_->type() == exe_type::NOPIE) {
    calcTrampData();
    manager_->placeHooks(trampData_);
  //}
#endif
}

void
Binary::populate_functions() {
  //One function created for every EH frame body.

  map <uint64_t, uint64_t> eh_frames = eh_frame.get_all_frame_address();
  auto it = eh_frames.begin();
  //uint64_t prev_frame_end = 0;
  while(it != eh_frames.end()) {
    LOG("Creating function from eh frame: " <<hex <<it->first <<" - " <<
     it->second);

    Function *new_func = new Function(it->first,it->second,false);
    funcMap_[it->first] = new_func;
    //prev_frame_end = it->second;
    it++;
  }
}

void
Binary::populate_ptr_eh_frame() {
  //Extracts and populates pointers from EH frame
  //Initial type is UNKNOWN
  //The flag will be changed later.

  auto it = funcMap_.begin();
  while(it != funcMap_.end()) {
    ADDPOINTER(it->first,PointerType::UNKNOWN, PointerSource::EH,0);
    it++;
  }
}

void
Binary::populate_ptr_reloc_ptr() {
  //Obtain definite code pointer: dynamic symbol table, init_array and
  //fini_array.

  vector <Reloc> code_pointers = manager_->codePtrs();
  for(auto & r : code_pointers) {
    /* This vector contains constants that are definitely code pointers.
     * Dynamic symbols.
     * Intialization function pointers and closing function pointers.
     */
    LOG("code pointer: " <<hex <<r.ptr);
    ADDPOINTER(r.ptr, PointerType::CP, PointerSource::KNOWN_CODE_PTR,r.storage);
    //Passing storage location = 100 for all known code pointers
  }

  //Entry point marked as definite code

  entryPoint_ = manager_->entryPoint();
  LOG("entry point: " <<hex << entryPoint_);
  ADDPOINTER(entryPoint_, PointerType::CP,PointerSource::KNOWN_CODE_PTR,100);
  //Passing storage location = 100 for all known code pointers
  //call sites and landing pads from exception handling marked as definite
  //code.

  map <uint64_t, call_site_info>::iterator call_site_it;
  call_site_it = all_call_sites.begin();
  while(call_site_it != all_call_sites.end()) {
    /* All call sites and landing pads obtained from exception handling
     * metadata marked as definite code pointers.
     */

    uint64_t ptr = call_site_it->first;
    LOG("EH call site: " <<hex <<ptr);
    ADDPOINTER(ptr, PointerType::CP, PointerSource::KNOWN_CODE_PTR,100);
    //Passing storage location = 100 for all known code pointers
    ptr = call_site_it->second.landing_pad;
    if(ptr != 0) {
      LOG("landing pad: " <<ptr);
      ADDPOINTER(ptr, PointerType::CP,PointerSource::KNOWN_CODE_PTR,100);
      //Passing storage location = 100 for all known code pointers
    }
    call_site_it++;
  }

  //Finally relocation pointers are obtained and populated with type = UNKNOWN
  //Their type will be classified later.

  //picConstReloc_ = manager_->relocatedPtrs(rel::CONSTPTR_PIC);
  for(auto r : picConstReloc_) {
    /* A Pointer object created for every relocated pointer. Initial status
     * of the Pointer is unknown.
     * Will be later marked as code or data pointer.
     */
     ADDPOINTER(r.ptr, PointerType::UNKNOWN, PointerSource::PIC_RELOC,r.storage);
  }
}

void
Binary::populate_ptr_sym_table() {

  //This function is used only when we want to use symbol table for
  //disassembly.

  vector <uint64_t> symVals = manager_->allSyms();
  for(uint64_t symVal:symVals) {
    for (auto & sec : rxSections_) { 
      if(sec.vma <= symVal && (sec.vma + sec.size) >= symVal
         && sec.sec_type == section_types::RX) {
        if(symVal == 0)
          DEF_LOG("Symbol: "<<hex<<symVal);
        ADDPOINTER(symVal, PointerType::CP,PointerSource::SYMTABLE,0);
      }
    }
  }
}

void
Binary::populate_pointers() {
#ifdef EH_FRAME_DISASM_ROOT
  populate_ptr_eh_frame();
#endif
#ifdef GROUND_TRUTH
  populate_ptr_sym_table();
#endif
  populate_ptr_reloc_ptr();
#ifdef DATADISASM
  vector <uint64_t> data_ptrs = manager_->dataSyms();
  for (auto & ptr : data_ptrs)
    ADDPOINTER(ptr, PointerType::DP,PointerSource::NONE,100);
#endif
}

void
Binary::map_functions_to_section() {
  /* Maps exception handling frames to the corresponding code section.
   */

  LOG("mapping functions to sections");
  for(section sec:rxSections_) {
    if(sec.sec_type == section_types::RX) {
      /* A Pointer object with type as code Pointer is created for every
       * code section.
       */
      //DEF_LOG("Exec section: "<<hex<<sec.vma);
      ADDPOINTER(sec.vma, PointerType::CP,PointerSource::KNOWN_CODE_PTR,100);
      auto frame_it = funcMap_.find(sec.vma);
      if(frame_it == funcMap_.end()) {
        /* If no frame exists for the section, create a frame.
         * Done for the ease of re-assembly.
         */

        Function *f = new Function(sec.vma, 0,true);
        f->addEntryPoint(sec.vma);
        funcMap_[sec.vma] = f;
      }
      else
        frame_it->second->addEntryPoint(sec.vma);
    }
    else
      ADDPOINTER(sec.vma, PointerType::DP,PointerSource::NONE,100);
  }

}

void
Binary::print_data_segment(string file_name) {
  //Prints out the assembly file for data section using assembler directives
  //and labels.

  map <uint64_t, vector <string>> section_map;
  map <uint64_t, string> section_range_map;
  uint64_t segment_size = 0;

  //In some cases, section regions might overlap. To assign correct labels to
  //section ends, we create the below map.
  
  for(section & sec : rwSections_) {
    section new_sec = sec;
    new_sec.start_sym = sec.name + "_dup";
    new_sec.end_sym = sec.name + "_dup_end";
    manager_->newSection(new_sec);
    section_map[sec.vma].push_back(sec.name);
    section_range_map[sec.vma + sec.size] = sec.name;
    if((sec.vma + sec.size) > segment_size)
      segment_size = sec.vma + sec.size;
  }

  uint64_t data_seg_start = rwSections_[0].offset;
  int last_sec_ind = rxSections_.size() - 1;
  uint64_t code_seg_end = rxSections_[last_sec_ind].offset
    + rxSections_[last_sec_ind].size;

  if(manager_->type() != exe_type::NOPIE) {
    utils::printAlgn(manager_->segAlign(),file_name);
    uint64_t mod =  rwSections_[0].vma % manager_->segAlign();
    utils::printAsm(".skip " + to_string(mod) + "\n", 0,"", SymBind::NOBIND,file_name);
  }
  else {
    utils::printAsm(".skip " + to_string(data_seg_start - code_seg_end) + "\n",
        code_seg_end,"." + to_string(code_seg_end), SymBind::BIND,file_name);
  }
  utils::printLbl(".datasegment_start",file_name);
  uint64_t byte_count = 0;
  uint64_t i = rwSections_[0].vma;

  //Below, we do not put the actual data. Rather we just use .skip <bytes>
  //directive. This is done for faster re-assembly.
  //.skip <bytes> reserves the adequete space. The datasegment is injected
  //into that space later.

  for(; i < segment_size; i++) {
    if(if_exists(i, section_range_map)) {
      utils::printAsm("\t.skip " + to_string(byte_count)
          + "\n",0,"",SymBind::NOBIND,file_name);
      utils::printAsm("\n",i,"." + to_string(i),SymBind::FORCEBIND,file_name); 
      utils::printLbl(section_range_map[i] + "_dup_end",file_name);
      byte_count = 0;
    }
    if(if_exists(i, section_map)) {
      for(string & sec_name:section_map[i]) {
        if(byte_count> 0)
          utils::printAsm("\t.skip " + to_string(byte_count)
              + "\n",0,"",SymBind::NOBIND,file_name);
        utils::printAsm("\n",i,"." + to_string(i),SymBind::FORCEBIND,file_name); 
        utils::printLbl(sec_name + "_dup",file_name);
        byte_count = 0;
      }
    }
    byte_count++;
  }
  if(byte_count > 0)
    utils::printAsm("\t.skip " + to_string(byte_count)
        + "\n",0,"",SymBind::NOBIND,file_name);

  if(if_exists(i, section_range_map)) {
    utils::printLbl(section_range_map[i] + "_dup_end",file_name);
  }
  utils::printLbl(".datasegment_end",file_name);
  utils::printAsm("\n",i,"." + to_string(i),SymBind::FORCEBIND,file_name); 

}

extern void sort_pheaders(vector <pheader> &vec_of_pheader);

void
Binary::printOldCodeAndData(string file_name) {
  map <uint64_t, vector <section>> section_map;
  map <uint64_t, vector <section>> section_range_map;

  //In some cases, section regions might overlap. To assign correct labels to
  //section ends, we create the below map.
  //auto all_secs = rxSections_;
  //all_secs.insert(all_secs.end(), rwSections_.begin(), rwSections_.end());
  for(section & sec : rxSections_) {
    section new_sec = sec;
#ifdef STATIC_TRANS
    //if(manager_->type() == exe_type::NOPIE) 
      new_sec.sec_type = section_types::RX;
    //else
      //new_sec.sec_type = section_types::RONLY;
#else
    new_sec.sec_type = section_types::RONLY;
#endif
    if((RA_OPT == false || manager_->isEhSection(sec.vma) == false) && sec.sec_type != section_types::RX) { 
      if(sec.name.rfind(".") == 0) {
        new_sec.start_sym = sec.name + "_dup";
        new_sec.end_sym = sec.name + "_dup_end";
      }
      else {
        new_sec.start_sym = "." + to_string(sec.vma) + "_dup";
        new_sec.end_sym = "." + to_string(sec.vma + sec.size) + "_dup_end";
      }
      sec.printed = true;
    }
    else {
      new_sec.additional = true;
      new_sec.name = ".old_" + new_sec.name;
      new_sec.start_sym = ".old_" + to_string(sec.vma) + "_dup";
      new_sec.end_sym = ".old_" + to_string(sec.vma + sec.size) + "_dup_end";
    }
    //manager_->newSection(new_sec);
    section_map[sec.vma].push_back(new_sec);
    section_range_map[sec.vma + sec.size].push_back(new_sec);
  }
  for(section & sec : rwSections_) {
    if(manager_->isEhSection(sec.vma) == false) { 
      section new_sec = sec;
      if(sec.name.rfind(".") == 0) {
        new_sec.start_sym = sec.name + "_dup";
        new_sec.end_sym = sec.name + "_dup_end";
      }
      else {
        new_sec.start_sym = "." + to_string(sec.vma) + "_dup";
        new_sec.end_sym = "." + to_string(sec.vma + sec.size) + "_dup_end";
      }
      //manager_->newSection(new_sec);
      section_map[sec.vma].push_back(new_sec);
      section_range_map[sec.vma + sec.size].push_back(new_sec);
      sec.printed = true;
    }
    else
      LOG("Ignoring section: "<<sec.name);
  }

  //ofstream ofile;
  //ofile.open(file_name, ofstream::out | ofstream::app);

  //ofile <<".old_top:\n";
  utils::printLbl(".old_top",file_name);
  vector <pheader> ronly_segs
    = manager_->prgrmHeader(pheader_types::LOAD,pheader_flags::RONLY);
  vector <pheader> rx_segs
    = manager_->prgrmHeader(pheader_types::LOAD,pheader_flags::RX);
  vector <pheader> rw_segs
    = manager_->prgrmHeader(pheader_types::LOAD,pheader_flags::RW);

  vector <pheader> all_segs;
  
  all_segs.insert(all_segs.end(),ronly_segs.begin(),ronly_segs.end());
  all_segs.insert(all_segs.end(),rx_segs.begin(),rx_segs.end());
  all_segs.insert(all_segs.end(),rw_segs.begin(),rw_segs.end());
  sort_pheaders(all_segs);
  int ctr = 0;
  uint64_t prev_end = 0;
  for (auto & p : all_segs) {
    section new_sec(".old" + to_string(ctr),p.offset,p.file_sz,p.address,64);
    new_sec.load = false;
    new_sec.start_sym = ".old" + to_string(ctr);
    new_sec.end_sym = ".old" + to_string(ctr) + "_end";
    if(p.p_flag == pheader_flags::RW)
      new_sec.sec_type = section_types::RW;
    else {
#ifdef STATIC_TRANS
      //if(manager_->type() == exe_type::NOPIE) 
        new_sec.sec_type = section_types::RX;
      //else
        //new_sec.sec_type = section_types::RONLY;
#else
      new_sec.sec_type = section_types::RONLY;
#endif
    }
    new_sec.additional = true;
    if(prev_end != 0) {
      uint64_t align_point = 0;
      for(auto i = prev_end; i < p.address; i++) {
        if(i % manager_->segAlign() == 0) {
          section new_sec("." + to_string(i),p.offset - (p.address -i),p.address - i,i,64);
          new_sec.start_sym = "." + to_string(i) + "_start";
          new_sec.end_sym = "." + to_string(i) + "_end";
          if(p.p_flag == pheader_flags::RW)
            new_sec.sec_type = section_types::RW;
          else
            new_sec.sec_type = section_types::RONLY;
          new_sec.additional = true;
          manager_->newSection(new_sec);
          utils::printAsm(".skip " + to_string(i - prev_end) + "\n",0,"",SymBind::NOBIND,file_name);
          utils::printLbl("." + to_string(i) + "_start",file_name);
          prev_end = i;
          align_point = i;
          break;
        }
      }
      uint64_t pad = p.address - prev_end;
      if(pad > 0) {
        utils::printAsm(".skip " + to_string(pad) + "\n",0,"",SymBind::NOBIND,file_name);
        if(align_point != 0)
          utils::printLbl("." + to_string(align_point) + "_end",file_name);
      }
    }
    utils::printLbl(".old" + to_string(ctr),file_name);
    if(p.p_flag == pheader_flags::RW)
      utils::printLbl(".datasegment_start",file_name);
    //ofile<<".old"<<ctr<<":\n";
    auto data_sz = p.mem_sz;
    auto file_offt = p.offset;
    auto vma = p.address;
    if(p.offset == 0) {
      data_sz -= (manager_->exeHdrSz()/* + manager_->newPHdrSz()*/);
      file_offt += manager_->exeHdrSz()/* + manager_->newPHdrSz()*/;
      vma += manager_->exeHdrSz();
    }
    uint8_t *data = (uint8_t *)malloc(data_sz);
    utils::READ_FROM_FILE (exePath_, data, file_offt, data_sz);
    for(uint64_t i = 0; i < data_sz; ) {
      auto addr = vma + i;
      bool rw_sec = false;
      bool interp_sec = false;
      uint64_t sec_size = 0;
      if(section_range_map.find(addr) != section_range_map.end()) {
        for(auto & sec : section_range_map[addr])
          utils::printLbl(sec.end_sym,file_name);
      }
      if(section_map.find(addr) != section_map.end()) {
        for(auto & sec : section_map[addr]) {
          utils::printLbl(sec.start_sym,file_name);
          manager_->newSection(sec);
          if(sec.sec_type == section_types::RW) {
            rw_sec = true;
            if(sec_size > sec.size || sec_size == 0)
              sec_size = sec.size;
          }
          else if(sec.name == ".interp") {
            interp_sec = true;
            sec_size = sec.size;
          }
        }
      }
      SymBind b = SymBind::BIND;
      string label = "." + to_string(addr);
      if(codeCFG_->rewritableJmpTblLoc(addr)) {
        label = "";
        b = SymBind::NOBIND;
      }
      if(rw_sec) {
        uint64_t byte_cnt;
        uint64_t skipped = 0;
        for(byte_cnt = 1; byte_cnt < sec_size; byte_cnt++) {
          if(section_range_map.find(addr + byte_cnt) != section_range_map.end()) {
            if((byte_cnt - skipped) > 0) {
              utils::printAsm("\t.skip " + to_string(byte_cnt - skipped) + "\n",addr + skipped,
                              "." + to_string(addr + skipped),b,file_name);
              skipped = byte_cnt;
            }
            for(auto & sec : section_range_map[addr + byte_cnt])
              utils::printLbl(sec.end_sym,file_name);
          }
        }
        if((byte_cnt - skipped) > 0) {
          utils::printAsm("\t.skip " + to_string(byte_cnt - skipped) + "\n",addr + skipped,
                           "." + to_string(addr + skipped),b,file_name);
        }
        if(sec_size == 0)
          i++;
        else
          i += sec_size;
      }
      else if(interp_sec) {
#ifdef STATIC_TRANS
        utils::printAsm(".byte " + to_string((uint32_t)data[i]) + "\n",addr, label, b, file_name);
        i++;
#else
        string interp((char *)(data + i));
        interp.replace(interp.find("x86-64"),6,"xsafer");
        auto len = interp.length();
        const char *interp_char = interp.c_str();
        uint64_t j = 0;
        for(j = 0; j < len; j++) {
          label = "." + to_string(addr + j);
          utils::printAsm(".byte " + to_string((uint32_t)interp_char[j]) + "\n",addr + j, label, b, file_name);
        }
        label = "." + to_string(addr + j);
        utils::printAsm(".byte " + to_string((uint32_t)0) + "\n",addr + j, label, b, file_name);
        i += sec_size;
#endif
      }
      else {
        utils::printAsm(".byte " + to_string((uint32_t)data[i]) + "\n",addr, label, b, file_name);
        i++;
      }
    }
    //ofile<<".old"<<ctr<<"_end:\n";
    utils::printLbl(".old" + to_string(ctr) + "_end",file_name);
    if(p.p_flag == pheader_flags::RW)
      utils::printLbl(".datasegment_end",file_name);
    manager_->newSection(new_sec);
    prev_end = p.address + p.mem_sz;
    if(section_range_map.find(prev_end) != section_range_map.end()) {
      for(auto & sec : section_range_map[prev_end])
        utils::printLbl(sec.end_sym,file_name);
    }
    ctr++;
  }
  utils::printLbl(".old_end",file_name);
}

bool
compare_jmp_tbl(JumpTable & A, JumpTable & B) {
  return A.location() < B.location();
}

void
sort_jmp_tbl(vector <JumpTable> &vec_of_jmp_tbls) {
  sort(vec_of_jmp_tbls.begin(), vec_of_jmp_tbls.end(), compare_jmp_tbl);
}
/*
void
Binary::print_old_code_and_data(string file_name) {

  //Prints the assembly file for old code and data.
  //For old code, only 0s are put rather than actual code.
  //It can be changed to put the actual code instead.

  ofstream ofile;
  ofile.open(file_name, ofstream::out | ofstream::app);

  ofile <<".old_top:\n";
  vector <pheader> ronly_segs
    = manager_->prgrmHeader(pheader_types::LOAD,pheader_flags::RONLY);
  vector <pheader> rx_segs
    = manager_->prgrmHeader(pheader_types::LOAD,pheader_flags::RX);

  vector <pheader> rorx_segs;
  
  rorx_segs.insert(rorx_segs.end(),ronly_segs.begin(),ronly_segs.end());
  rorx_segs.insert(rorx_segs.end(),rx_segs.begin(),rx_segs.end());
  sort_pheaders(rorx_segs);
  int ctr = 0;
  uint64_t prev_end = 0;
  for (auto & p : rorx_segs) {
    section new_sec(".old" + to_string(ctr),p.offset,p.file_sz,p.address,64);
    new_sec.start_sym = ".old" + to_string(ctr);
    new_sec.end_sym = ".old" + to_string(ctr) + "_end";
    new_sec.sec_type = PFLAG_TO_SECTYPE(p.p_flag);
    new_sec.additional = true;
    if(prev_end != 0) {
      uint64_t pad = p.offset - prev_end;
      if(pad > 0)
        ofile<<".skip "<<pad<<endl;
    }
    ofile<<".old"<<ctr<<":\n";
    if(p.offset == 0) {
      ofile<<".skip "<<p.mem_sz - hdr_sz<<endl;
    }
    else
      ofile<<".skip "<<p.mem_sz<<endl;
    ofile<<".old"<<ctr<<"_end:\n";
    manager_->newSection(new_sec);
    prev_end = p.offset + p.mem_sz;
    ctr++;
  }
  ofile<<".old_end:\n";
  //ofile<<".align "<<manager_->segAlign()<<endl;
  ofile.close();

  print_data_segment(file_name);
}
*/



void
Binary::rewrite_jmp_tbls(string file_name) {
  //Generates assembly to re-create jump tables.
  section new_sec("jmp_table",0,0,0,8);
  new_sec.start_sym=".jmp_tbl_start";
  new_sec.end_sym=".jmp_tbl_end";
  new_sec.sec_type = section_types::RONLY;
  new_sec.additional = true;
  manager_->newSection(new_sec);
  utils::printAlgn(8,file_name);
  utils::printLbl(".jmp_tbl_start",file_name);
  set <uint64_t> processed_jmp_tbl;
  vector <JumpTable> jmp_tbls = codeCFG_->jumpTables();
  sort_jmp_tbl(jmp_tbls);
  for(auto & j : jmp_tbls) {
    if(processed_jmp_tbl.find(j.location()) == processed_jmp_tbl.end() &&
       j.targets().size() > 0 &&
       codeCFG_->isMetadata(j.location()) == false &&
       j.rewritable()) {
      DEF_LOG("Writing jump table: "<<hex<<j.location());
      string tbl = j.rewriteTgts();
      utils::printAsm(tbl,j.location(),"."
          + to_string(j.location()),SymBind::FORCEBIND,file_name); 
      processed_jmp_tbl.insert(j.location());
    }
  }
  utils::printLbl(".jmp_tbl_end",file_name);
}

void
Binary::get_section_asm(string sec_name, string sec_file) {
  /* Print asm for a given function
   */
  for(section sec:rxSections_) {
    if(sec.name == sec_name) {
      if(sec.sec_type == section_types::RX) {
        print_executable_section(sec.vma,
  	    		sec.vma + sec.size,
  	    		sec_file);
      }
      else {
        /* If the section type is not RX, then just print out the bytes.
         * Exclude .eh_frame, .gcc_except_table and .eh_frame_hdr sections.
         * Assembly for these sections will be generated separately.
         */

        print_ro_section(sec.offset,
  	    	sec.vma,
  	    	sec.size, sec_file);
      }

    }
  }
}

/*
void
Binary::assignLabeltoFn(string label, string func_name) {

  off_t func_addrs = manager_->symbolVal(func_name);

  if(func_addrs == -1) {
    LOG("Symbol info for function " <<func_name <<" doesn't exist");
    return;
  }

  if(!(codeCFG_->assignLabeltoFn(label, func_addrs)))
    //if(!(unknownCFG_.assignLabeltoFn(label, func_addrs)))
      LOG("Error adding label: basic block doesn't exist for" <<func_name);

}
*/
void
Binary::check_segfault_handler() {
  /* Add instrumentatio to check if any handler registered for SIGSEGV.
   * Instruments main to make a call to sigaction system call.
   */
  string label = "segfault_checker";
  string inst_code = generate_hook(label);
  off_t hook_point = manager_->symbolVal("main");
  if(hook_point == -1)
    return;
  LOG("Hooking signal handler check at entry point" <<hex <<hook_point);
  codeCFG_->instrument(hook_point, inst_code);

}

void
Binary::install_segfault_handler() {
  /* Instruments __libc_start_main in GLIBC to make a call to sigaction and
   * register a user-defined SIGSEGV handler.
   */

  //string key("/");
  //size_t found = exePath_.rfind(key);
  //string exeName = exePath_.substr(found + 1);
  //off_t hook_point;
  //if(exeName == "ld-2.27.so")
  //  hook_point = entryPoint_;
  //else
  off_t  hook_point = manager_->symbolVal("__libc_start_main");

  if(hook_point <= 0) {
    LOG("__libc_start_main not present, returning without adding segfault handlier");
    return;
  }

  string label = "fill_sigaction";
  uint64_t sigaction_addrs = manager_->symbolVal("sigaction");	//get address of sigaction in GLIBC
  string inst_code = generate_hook(label,"","",HookType::SEGFAULT, "",sigaction_addrs);

  LOG("Installing signal handler at libcStartMain_" <<hex <<hook_point);

  codeCFG_->instrument(hook_point,inst_code);
}

void
Binary::genInstAsm() {

  /* Parses the instrumentation code Binary
   *(SBI/run/instrumentation_code_here/tutorial)
   * and generates asm to be re-assembled along with the target Binary.
   */

  string inst_Binary_path(INST_CODE_PATH "tutorial");
  /*
   * One way to add instrumentation code is to disassembly the instrumentation
   * Binary and add asm.
   * However, diasassembly is not feasible because of one global
   * exception_handler which is used by the target Binary.
   *
   * Will fix this soon.
   *
   Binary inst_Binary(inst_Binary_path);
   inst_Binary.populate_ptr_sym_table();
   inst_Binary.disassemble();
   inst_Binary.assignLabeltoFn(label,instrumentation_func_name);
   inst_Binary.get_section_asm(".text","inst_text.s");
   inst_Binary.get_section_asm(".rodata","inst_rodata.s");
   */

  /*
   * Another approach is to just obtain the hex bytes and put it in target
   * Binary asm.
   * Need to keep the offsets same so that the code works fine.
   */

  string key("/");
  size_t found = exePath_.rfind(key);
  string exeName = exePath_.substr(found + 1);

  ofstream ofile;
  ofile.open("inst_text.s", ofstream::out | ofstream::app);
  ofile<<exeNameLabel()<<":\n";
  for(unsigned int i = 0; i < exeName.length(); i++)
    ofile<<".byte "<<(uint32_t)exeName[i]<<"\n";
  ofile<<".byte 0\n";
  ExeManager *inst_exe = new binary_class(inst_Binary_path);

  vector<string> instFuncs = instFunctions();
  instFuncs.push_back("atf");
  map<uint64_t,string> instLabels;
  for(string & s : instFuncs) {
    off_t addrs = inst_exe->symbolVal(s);
    if(addrs > 0) 
      instLabels[addrs] = "." + s;
  }


  uint64_t sig_installer_address = inst_exe->symbolVal("install_signal");
  uint64_t sig_checker_address = inst_exe->symbolVal("check_handler");
  uint64_t fill_sigaction_address = inst_exe->symbolVal("fill_sigaction");
  uint64_t segfault_handler_address = inst_exe->symbolVal("segfault_handler");
  vector <section> inst_code_section =
    inst_exe->sections(section_types::RorX);;

  //ofstream ofile;
  //ofile.open("inst_text.s", ofstream::out | ofstream::app);
  uint64_t prev_sec = 0;
  for(section & sec:inst_code_section) {
    int byte_count = sec.size;

    uint8_t *section_data =(uint8_t *) malloc(byte_count);
    utils::READ_FROM_FILE(inst_Binary_path, section_data,sec.offset,
        byte_count);

    uint64_t sec_start = sec.vma;
    if(prev_sec != 0 && (sec_start - prev_sec) > 0)
      ofile<<".skip "<<sec_start - prev_sec<<endl;
   
    for(int j = 0; j <byte_count; j++) {
      auto it = instLabels.find(sec_start);
      if(it != instLabels.end())
        ofile <<it->second <<":\n";
      if(sec_start == sig_installer_address)
        ofile <<".segfault_installer:\n";
      if(sec_start == sig_checker_address)
        ofile <<".segfault_checker:\n";
      if(sec_start == fill_sigaction_address)
        ofile <<".fill_sigaction:\n";
      if(sec_start == segfault_handler_address)
        ofile<<".segfault_handler:\n";
      ofile <<".byte " <<(uint32_t) section_data[j] <<"\n";
      sec_start++;
    }

    prev_sec = sec_start;
    free(section_data);
  }
  ofile<<".align 16\n";
  ofile<<".GTF_stack:\n";
  //ofile<<"jmp *.dispatcher_stack(%rip)\n";
#ifdef ONE_LEVEL_HASH
  string ra_atf_file(TOOL_PATH"src/instrument/one_level_atf_ra.s");
#else
  string ra_atf_file(TOOL_PATH"src/instrument/two_level_atf_ra.s");
#endif
  ifstream ifile;
  ifile.open(ra_atf_file);
  string ra_atf_line;
  while(getline(ifile,ra_atf_line)) {
    ofile<<ra_atf_line<<endl;
  }
  ifile.close();
  ofile<<".align 16\n";
  ofile<<".GTF_reg:\n";
#ifdef ONE_LEVEL_HASH
  string atf_file(TOOL_PATH"src/instrument/one_level_atf.s");
#else
  string atf_file(TOOL_PATH"src/instrument/two_level_atf.s");
#endif
  ifile.open(atf_file);
  string atf_line;
  while(getline(ifile,atf_line)) {
    ofile<<atf_line<<endl;
  }
  ifile.close();
  ofile<<".align 16\n";
  ofile<<".GTF_decode_rax:\n";
  ofile<<decodeRAX();
  ofile<<".GTF_translate:\n";
#ifdef ONE_LEVEL_HASH
  string atf_file_tt(TOOL_PATH"src/instrument/one_level_atf_translate_ptr.s");
#else
  string atf_file_tt(TOOL_PATH"src/instrument/two_level_atf_translate_ptr.s");
#endif
  ifile.open(atf_file_tt);
  string atf_line_tt;
  while(getline(ifile,atf_line_tt)) {
    ofile<<atf_line_tt<<endl;
  }
  ifile.close();
  //string shstk_code = directCallShstkTramp();
  //ofile<<shadowTramp(shstk_code);

  //ofile<<"jmp *.gtt(%rip)\n";
  string shstk_init_file(TOOL_PATH"src/instrument/init_shstk.s");
  ifile.open(shstk_init_file);
  string shstk_line;
  while (getline(ifile, shstk_line)) {
    ofile << shstk_line << endl;
  }
  ifile.close();
  //if(alreadyInstrumented(InstPoint::LEGACY_SHADOW_STACK) ||
  //   alreadyInstrumented(InstPoint::SHADOW_STACK)) {
  //  ofile<<codeCFG_->shStkTramps();
  //}
  ofile<<".SYSCHK:\n";
  ofile<<"jmp *.syscall_checker(%rip)\n";

  ofile.close();
}

void
Binary::instrument() {
  DEF_LOG("Adding instrumentation");
  vector<string> instFuncs = instFunctions();
  if(instFuncs.size() <= 0) {
    DEF_LOG("No registered instrumentation....returning");
    return;
  }
  vector<pair<InstPoint,string>> targetPos = targetPositions();
  for(auto & p : targetPos) {
    DEF_LOG("Adding instrumentation to binary: "<<(int)p.first);
    codeCFG_->registerInstrumentation(p.first,p.second,instArgs()[p.second]);
  }
  //codeCFG_->instrument();
  vector<pair<string,string>> targetFuncs = targetFunctions();
  for(auto & f : targetFuncs) {
    uint64_t address = manager_->symbolVal(f.first);
    codeCFG_->registerInstrumentation(address,f.second,instArgs()[f.second]);
  }
  codeCFG_->instrument();
}

uint64_t xtraJmp = 0;

int unwndBlkSz = 0;


void
Binary::print_executable_section(uint64_t section_start, uint64_t
				  section_end, string sec_file) {
  /* Generates ASM for a given executable section.
   * Executable section is present between section_start and section_end.
   */

  ofstream ofile;

  //Obtain functions from both definite code and possible code.

  set <uint64_t> function_list;
  codeCFG_->functions(function_list, section_start, section_end);
  //unknownCFG_.functions(function_list, section_start, section_end);

  vector <uint64_t> function_vec;
  function_vec.assign(function_list.begin(), function_list.end());
#ifdef FUNCTION_RANDOMIZATION
  unsigned seed =
    std::chrono::system_clock::now().time_since_epoch().count();
  std::shuffle(function_vec.begin(), function_vec.end(),
		std::default_random_engine(seed));

#endif

  for(uint64_t func_addrs:function_vec) {
    LOG("Printing function: " <<hex <<func_addrs);
    ofile.open(sec_file, ofstream::out | ofstream::app);
    ofile <<".frame_" <<func_addrs <<":\n";	//Tag representing start of
                                            //an EH frame
    ofile.close();
    xtraJmp = 0;
    unwndBlkSz = 0;
    LOG("Printing definite code\n");
    eh_frame.print_bst(func_addrs);	//Print a record for the function in
                                    //EH's Binary search table.
    codeCFG_->printFunc(func_addrs, sec_file);
    //LOG("printing uncertain code\n");
    //unknownCFG_.printFunc(func_addrs, sec_file);
    ofile.open(sec_file, ofstream::out | ofstream::app);
    ofile <<".frame_" <<func_addrs <<"_end:\n";	//Tag for end of an EH frame.
    ofile.close();
  }

}
/*
string
Binary::printPsblData() {
  string filename="psbl_data.s";
  for(auto & p : pointerMap_) {
    if((p.second->type() == PointerType::UNKNOWN || 
        p.second->type() == PointerType::DP ||
        p.second->type() == PointerType::DEF_PTR) &&
        codeCFG_->withinCodeSec(p.first) &&
        (p.second->symbolizable(SymbolizeIf::CONST) ||
         p.second->symbolizable(SymbolizeIf::IMMOPERAND) ||
         p.second->symbolizable(SymbolizeIf::RLTV))) {
      //uint64_t next_ptr = codeCFG_->nextPtr(p.first);
      LOG("Creating data blk: "<<hex<<p.first);
      uint64_t next_ptr = 0;
      auto it = pointerMap_.find(p.first);
      it++;
      if(it == pointerMap_.end())
        next_ptr = codeSegmentEnd_;
      else
        next_ptr = it->first;
      uint64_t size = next_ptr - p.first;
      uint8_t *data = (uint8_t *)malloc(size);
      uint64_t offset = utils::GET_OFFSET(exePath_,p.first);
      utils::READ_FROM_FILE(exePath_,data,offset,size);
      uint64_t addr = p.first;
      for(uint64_t i = 0; i < size; i++,addr++)
        utils::printAsm(".byte " + to_string((uint32_t)data[i]) + "\n",addr,
            "." + to_string(addr),SymBind::FORCEBIND,filename); 
    }
  }
  return filename;
}

*/
void
Binary::print_ro_section(uint64_t start_offset, uint64_t section_start,
			  uint64_t byte_count, string sec_file) {
  /* Prints ASM for a read-only data section.
   */

  uint8_t *section_data =(uint8_t *) malloc(byte_count);
  utils::READ_FROM_FILE(exePath_, section_data, start_offset,
			 byte_count);
  for(unsigned int i = 0; i <byte_count; i++) {
    string line;

    /* If the address represents a jump table start, then do not add labels.
     * Because jump tables will be re-created at a separate location with
     * these labels.
     */
    SymBind b = SymBind::FORCEBIND;
    if(codeCFG_->isJmpTblLoc(section_start)) {
      line = "";
      b = SymBind::NOBIND;
    }
    else
      line = "." + to_string(section_start);

    utils::printAsm(".byte " + to_string((uint32_t)section_data[i])
        + "\n",section_start,line,b,sec_file); 
    section_start++;

  }

}

void
Binary::printSections() {
  for(section & sec : rxSections_) {
    LOG("Printing section: " <<sec.name);
    string sec_file = sec.name;
    if(sec_file.find(".") == 0)
      sec_file = sec_file.replace(0, 1, "");
    sec_file += ".s";
    LOG("section file: " <<sec_file);

    /* Iterate over all the sections.
     * If the section type is RX(read and execute), obtain the functions.
     * Call printFunc for both codeCFG_(definite code) and unknownCFG_
     *(possible code) to generate the assembly for the function.
     * This iteration generates separate assembly file for each section.
     */
    if(sec.sec_type == section_types::RX) {
      print_executable_section(sec.vma,sec.vma + sec.size, sec_file);
      if(sec.name == ".text") {
        utils::append_files("inst_text.s", sec_file);
        //utils::append_files(printPsblData(),sec_file);
      }
    }
    //else {
    //  /* If the section type is not RX, then just print out the bytes.
    //   * Exclude .eh_frame, .gcc_except_table and .eh_frame_hdr sections.
    //   * Assembly for these sections will be generated separately.
    //   */
    //  if(sec.name != ".eh_frame" &&
    //    sec.name != ".gcc_except_table" &&
    //    sec.name != ".eh_frame_hdr")
    //    print_ro_section(sec.offset, sec.vma, sec.size, sec_file);
    //}
    sec.asm_file = sec_file;
    if(sec.name.rfind(".") == 0) {
      sec.start_sym = sec.name + "_dup";
      sec.end_sym = sec.name + "_dup_end";
    }
    else {
      sec.start_sym = "." + to_string(sec.vma) + "_dup";
      sec.end_sym = "." + to_string(sec.vma + sec.size) + "_dup_end";
    }
    utils::bind(sec.vma, sec.start_sym, SymBind::FORCEBIND);

  }

  //Assembly files for EH sections generated here.
  if(RA_OPT) {
    eh_frame.printAllCallSiteTbls();
    eh_frame.print_eh_frame(rwSections_[0].vma);
    eh_frame.print_lsda(rwSections_[0].vma);
    eh_frame.print_eh_frame_hdr();
  }

}

void
Binary::stitchSections(section_types t,string file_name, bool align) {
  ofstream ofile;
  if(align) {
    utils::printAlgn(manager_->segAlign(), file_name);
  }
  for(auto & sec : rxSections_) {
    if(sec.sec_type == t && sec.printed == false) {
      utils::printAlgn(sec.align,file_name);
      utils::printLbl(sec.start_sym,file_name);
      string
        sec_file = sec.asm_file;

      utils::append_files(sec_file, file_name);
      utils::printLbl(sec.end_sym,file_name);
      section new_sec = sec;
      manager_->newSection(new_sec);
      sec.printed = true;
    }
  }
}

string Binary::print_assembly() {

  //Prints the complete assembly that contains instrumented code, old code and
  //data.
  string key("/");
  size_t found = exePath_.rfind(key);
  string file_name = exePath_.substr(found + 1) + "_new.s";
  string file_tmp = exePath_.substr(found + 1) + "_tmp.s";
  //if(manager_->type() == exe_type::NOPIE)
  //print_old_code_and_data("old_code_and_data.s");
  //utils::append_files("old_code_and_data.s", file_name);
  printOldCodeAndData("old_code_and_data.s");
  printSections();

  //Separate assembly files generated for each section are appended here.
  //if(manager_->type() != exe_type::NOPIE) {
  //  print_data_segment(file_name);
  //}

  section phdr_sec("phdr",0,0,0,8);
  phdr_sec.start_sym=".pheader_start";
  phdr_sec.end_sym=".pheader_end";
  phdr_sec.sec_type = section_types::RX;
  phdr_sec.additional = true;
  manager_->newSection(phdr_sec);
  stitchSections(section_types::RX,"new_code.s",true);
#ifdef STATIC_TRANS
  DEF_LOG("Skipping translation table addition");
#else
  //if(RA_OPT) {
    int ctr = 0;
    auto all_ras = codeCFG_->allReturnSyms();
    for(auto & s : all_ras) {
      manager_->addAttEntry(ctr,".8byte " + s + "- .elf_header_start",
                            ".8byte " + s + " - " + ".elf_header_start",
                            s, 1);
      ctr++;
    }
 // }
  if(RA_OPT == false) {
    pointerMap_ = codeCFG_->pointers();
    auto all_ras = codeCFG_->allReturnAddresses();
    for(auto & r : all_ras) {
      DEF_LOG("Adding old RA to hash: "<<hex<<r.first<<"->"<<r.second);
      if(pointerMap_.find(r.first) == pointerMap_.end()) { //Else already added
        //string sym = codeCFG_->getSymbol(r);
        manager_->addAttEntry(r.first,".8byte " + to_string(r.first),
                              ".8byte " + r.second + " - " + ".elf_header_start",
                              r.second, 0);
      }
    }
  }
  //{

    //ADD ATT
    section att_sec("att_table",0,0,0,8);
    att_sec.start_sym=".att_tbl_start";
    att_sec.end_sym=".att_tbl_end";
    att_sec.sec_type = section_types::RX;
    att_sec.additional = true;
    att_sec.is_att = true;
    manager_->newSection(att_sec);
    string att_asm = manager_->attTableAsm();
    utils::printAsm(att_asm,0,att_sec.start_sym,SymBind::NOBIND,"att.s"); 
    utils::printLbl(att_sec.end_sym,"att.s");
    utils::printAlgn(8, "new_code.s");
  utils::append_files("att.s", "new_code.s");
#endif
  //}
    //ADD ATT TRAMPS

    //string tramp_asm = manager_->trampAsm();
    //section tramp_sec("tramp_table",0,0,0,8);
    //tramp_sec.start_sym=".tramp_tbl_start";
    //tramp_sec.end_sym=".tramp_tbl_end";
    //tramp_sec.sec_type = section_types::RX;
    //tramp_sec.additional = true;
    //manager_->newSection(tramp_sec);
    //utils::printLbl(tramp_sec.start_sym,"tramp.s");
    //utils::printAsm(tramp_asm,0,tramp_sec.start_sym,SymBind::NOBIND,"tramp.s"); 
    //utils::printLbl(tramp_sec.end_sym,"tramp.s");
    //utils::append_files("tramp.s", "new_code.s");
  stitchSections(section_types::RONLY,"new_code.s", true);

  rewrite_jmp_tbls("jmp_tbl.s");
  utils::append_files("jmp_tbl.s", "new_code.s");

#ifdef ONE_LEVEL_HASH
  manager_->printNonLoadSecs("nonloadsecs.s");
  manager_->printExeHdr("exe_hdr.s");
  manager_->printPHdrs("pheaders.s");

  utils::append_files("exe_hdr.s", file_name);
  utils::append_files("old_code_and_data.s", file_name);
  utils::printAlgn(manager_->segAlign(), file_name);
  utils::printLbl(".new_codesegment_start",file_name);
  utils::printLbl(".pheader_start",file_name);
  utils::append_files("pheaders.s", file_name);
  utils::printLbl(".pheader_end",file_name);
  utils::append_files("new_code.s", file_name);

  utils::printLbl(".new_codesegment_end",file_name);
  utils::append_files("nonloadsecs.s", file_name);
  return file_name;
#else
#ifdef STATIC_TRANS
  DEF_LOG("Skipping translation table addition");
#else
  //{
    //New section for hash table
    section hash_tbl_sec("hash_tbl",0,0,0,8);
    hash_tbl_sec.start_sym=".hash_tbl_start";
    hash_tbl_sec.end_sym=".hash_tbl_end";
    hash_tbl_sec.sec_type = section_types::RONLY;
    hash_tbl_sec.additional = true;
    manager_->newSection(hash_tbl_sec);
  //}
#endif

  manager_->printNonLoadSecs("nonloadsecs.s");

  manager_->printExeHdr("exe_hdr.s");
  manager_->printPHdrs("pheaders.s");

  utils::append_files("exe_hdr.s", file_tmp);
  utils::append_files("old_code_and_data.s", file_tmp);
  utils::printAlgn(manager_->segAlign(), file_tmp);
  utils::printLbl(".new_codesegment_start",file_tmp);
  utils::printLbl(".pheader_start",file_tmp);
  utils::append_files("pheaders.s", file_tmp);
  utils::printLbl(".pheader_end",file_tmp);
  utils::append_files("new_code.s", file_tmp);
  utils::printLbl(".new_codesegment_end",file_tmp);

#ifdef STATIC_TRANS
  DEF_LOG("Skipping translation table addition");
#else
  uint64_t hash_entry_cnt = manager_->generateHashTbl(file_tmp,att_sec); 
  uint64_t hash_tbl_sz = hash_entry_cnt * sizeof(void *);
#endif
  utils::append_files("exe_hdr.s", file_name);
  utils::append_files("old_code_and_data.s", file_name);
  utils::printAlgn(manager_->segAlign(), file_name);
  utils::printLbl(".new_codesegment_start",file_name);
  utils::printLbl(".pheader_start",file_name);
  utils::append_files("pheaders.s", file_name);
  utils::printLbl(".pheader_end",file_name);
  utils::append_files("new_code.s", file_name);
  //
#ifdef STATIC_TRANS
  DEF_LOG("Skipping translation table addition");
#else
  string hash_asm = manager_->hashTblAsm();
  utils::printAsm(hash_asm,0,hash_tbl_sec.start_sym,SymBind::NOBIND,file_name);
  utils::printLbl(hash_tbl_sec.end_sym,file_name);
#endif
  utils::printLbl(".new_codesegment_end",file_name);
  utils::append_files("nonloadsecs.s", file_name);
  //utils::append_files(TOOL_PATH"/src/instrument/atf.s",file_name);
  return file_name;
#endif
}


void
Binary::reduce_eh_metadata() {
  auto f_it = funcMap_.begin();
  while(f_it != funcMap_.end()) {
    if(f_it->second->isLeaf()) {
      //If function is leaf, remove entire EH metadata.
      unwinding_info.erase(f_it->first);
      eh_frame.add_fde_to_remove(f_it->first);
    }
    else {
      //else merge non-call containing unwinding blocks.
      //Blocks with call to leaf functions are also considered non-call
      //containing.
      auto cfi_it = unwinding_info.find(f_it->first);
      if(cfi_it != unwinding_info.end()) {

        vector <BasicBlock *> bbs = f_it->second->getDefCode();
        uint64_t blk_start = f_it->first;
        uint64_t effective_blk = blk_start;
        uint64_t blk_end = 0;
        for(auto bb:bbs) {
  	      Instruction *ins = bb->lastIns();
  	      blk_end = ins->location();
  	      bool first_blk = true;
  	      if(ins->isCall()) {
  	        uint64_t target = ins->target();
  	        if(target != 0) {
  	          auto f_it2 = is_within(target, funcMap_);
  	          if(f_it2->second->isLeaf() == false) {
  	            if(first_blk)
  	      	      /* If it is first call block, then continue without
  	      	       * marking it as end. So that, if the function has just
  	      	       * one call, whole function may be merged into one
  	      	       * unwinding block.
  	      	       */
  	      	      first_blk = false;
  	            else {
  	      	      /* Else end and merge the current unwinding block and
  	      	       * start a new unwinding block.
  	      	       */
  	      	      cfi_it->second.
  	      	        merge_unwinding_blocks(blk_start, blk_end,
  	      	        		    effective_blk);
  	      	      blk_start = bb->start();
  	      	    }
  	            effective_blk = ins->location();
  	          }
  	        }
  	      }
  	    }
        //Merge the last blocks
        cfi_it->second.merge_unwinding_blocks(blk_start, blk_end,
  					     effective_blk);
      }
    }
    f_it++;
  }
}


void
Binary::mark_leaf_functions() {
  set <uint64_t> all_plt_slots = manager_->allJmpSlots();
  bool repeat = true;
  while(repeat) {
    /* Recursively mark function as leaf functions.
     * A function with no further calls is leaf.
     * A function calling only leaf functions is also marked as leaf(for EH
     * metadata removal.
     */
    repeat = false;
    auto it = funcMap_.begin();
    while(it != funcMap_.end()) {
      //If a function has possible code, mark it as non-leaf to be
      //conservative.
      //Will deal with possible code later.
      if(it->second->hasUnknwnCode())
        it->second->isLeaf(false);
      else if(it->second->isLeaf() == false) {
        bool is_leaf = true;
        vector <BasicBlock *> bbs = it->second->getDefCode();
        for(BasicBlock *bb : bbs) {

    	  Instruction *ins = bb->lastIns();
    	  if(ins->isIndirectCf()) {
    	    uint64_t access_location = ins->ripRltvOfft();
    	    if(access_location != 0 && 
                all_plt_slots.find(access_location) != all_plt_slots.end()) {
    	      //Mark all plt trampolines as non-leaf functions.
    	      //So that any function that contains standard library
    	      //function calls will not be marked as leaf.
    	      is_leaf = false;
    	      break;
    	    }
    	  }
          else if(bb->isCall() && bb->target() != 0) {
            auto f_it = is_within(bb->target(),funcMap_);
    	    if(f_it->second->isLeaf() == false) {
    	      is_leaf = false;
    	      break;
    	    }

    	  }

    	}
        if(is_leaf) {
    	  repeat = true;
    	  it->second->isLeaf(true);
    	}
      }
      it++;
    }
  }
}
