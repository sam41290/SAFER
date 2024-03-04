#include "disasm.h"
#include "globals.h"
#include <dis-asm.h>
#include <stddef.h>
#include <stdarg.h>

void
DisasmEngn::createInsCache(uint64_t code_start, uint64_t code_end) {
  //Performs linear disassembly of a code block between two code pointers and
  //stores the result instruction cache.
  //This cache will be used by cfg object when it recursively verifies the
  //disassembly and creates basic blocks.

  //End bytes may be misaligned. Add extra 4 bytes and reject the last
  //instruction.
  DEF_LOG("Creating ins cache: "<<hex<<code_start<<" - "<<hex<<code_end);
  vector <Instruction *> ins_list = readIns(code_start,code_end);

  uint64_t ins_cnt = ins_list.size();
  if(ins_cnt > 0)
    DEF_LOG("Last ins: "<<hex<<ins_list[ins_cnt - 1]->location());
  

  uint64_t ctr = 0;
  Instruction *prev_ins = NULL;
  for(auto & ins : ins_list) {
    uint64_t loc = ins->location();
    if(ctr == (ins_cnt - 2)) { //Ignore the last two instructions
      DEF_LOG("Last ins reached: "<<hex<<loc);
      break;
    }
    insCache_[loc] = ins;
    if(prev_ins != NULL && prev_ins->fallThrough() == ins->location())
      prev_ins->fallIns(ins);
    ctr++;
    prev_ins = ins;
  }
  //DEF_LOG("Instructions created: "<<insCache_.size());

}


vector <Instruction *>
DisasmEngn::getIns(uint64_t start, int limit) {
  DEF_LOG("Getting instructions for address: "<<hex<<start);
  vector <Instruction *> ins_list;
  if(invalid_.find(start) != invalid_.end()) {
    DEF_LOG("Invalid address");
    return ins_list;
  }

  uint64_t ins_start = start;
  auto it = insCache_.find(ins_start); 
  if(it == insCache_.end() || gaps_.find(start) != gaps_.end()) {

    uint64_t end = start;
    //auto cache_start = start;
    for(auto & e : sectionEnds_)
      if(e > end) {
        //cache_start = 
        end = e;
        break;
      }
    //createInsCache(start,end);
    superSetCache(start,end);
  }

  int ctr = 0;
  it = insCache_.find(start);
  Instruction *ins = NULL;
  if(it != insCache_.end())
    ins = it->second;
  while (ins != NULL && ctr < limit) {
    ins_list.push_back(ins);
    auto fall_ins = ins->fallIns();
    if(fall_ins == NULL) {
      uint64_t fall = it->second->fallThrough();
      it = insCache_.find(fall);
      if(it != insCache_.end())
        fall_ins = it->second;
    }
    ins = fall_ins;
    ctr++;
  }

  int  ins_count = ins_list.size();
  if(ins_count == 0) {
    DEF_LOG("Adding invalid address: "<<hex<<start);
    invalid_.insert(start);
    return ins_list;
  }
  //if(ins_count < limit) {
  //  vector <Instruction *> rest_ins = 
  //    getIns(ins_list[ins_count - 1]->fallThrough(),limit - ins_count);
  //  if(rest_ins.size() > 0)
  //    ins_list.insert(ins_list.end(),rest_ins.begin(),rest_ins.end());
  //}

  //insSeq_[start] = ins_list;
  return ins_list;
}


void
DisasmEngn::handle_gaps (uint8_t * bytes, uint64_t addrs, int index, uint64_t size,
	     vector <Instruction *> &ins_list) {
  //Generates instruction objects with .byte directive.
  //Needed to put raw bytes in case of a disassembly gap.
  //DEF_LOG("Handling gap: "<<hex<<addrs<<" size: "<<size);
  for (unsigned int i = 0; i < size; i++) {
    if(insCache_.find(addrs) != insCache_.end()) {
      //DEF_LOG("Addrs present in cache: "<<hex<<addrs<<" index "<<i);
      auto ins = insCache_[addrs];
      //ins_list.push_back(ins);
      uint64_t fall = ins->fallThrough();
      if(fall != 0) {
        index = index + (fall - addrs);
        i = i + (fall - addrs) - 1;
        addrs = fall;
      }
      else {
        index++;
        addrs++;
      }
      //DEF_LOG("Next address: "<<hex<<addrs<<" index "<<i<<" size "<<size);
      //exit(0);
    }
    else {
      //if(addrs == 0x405d86)
        //DEF_LOG("Adding gap byte: "<<hex<<addrs<< " index "<<i);
      Instruction *ins = new Instruction();		//=new ins_struct();
      ins->location(addrs);
      ins->insBinary(&bytes[index], 1);
      ins->label("." + to_string (addrs));
      ins->asmIns(".byte " + to_string(bytes[index]));
      addrs++;
      index++;
      ins->fallThrough(addrs);
      ins_list.push_back(ins);
      gaps_.insert(addrs);
    }
  }

}

uint64_t
DisasmEngn::disasmEnd(uint64_t start, uint64_t size) {
  uint64_t end = start + size;
  if(insCache_.size() == 0)
    return end;
  auto i = start;
  for(; insCache_.find(i) == insCache_.end() && i < end; i++);
  bool jump = false;
  int ctr = 0;
  if(i < end) {
    auto it = insCache_.find(i);
    DEF_LOG("Iterating till unconditional jump: "<<hex<<i);
    while(it != insCache_.end() && gaps_.find(it->first) != gaps_.end() && i < end) {
      i = it->second->fallThrough();
      if(it->second->isUnconditionalJmp()) {
        jump = true;
        DEF_LOG("Jump at: "<<hex<<i);
      }
      if(jump) {
        if(ctr >= 50)
          return i;
        ctr++;
      }
      it = insCache_.find(i);
    }
  }

  if(i < end) {
    auto it = insCache_.find(i);
    for(auto ctr = 0; ctr < 2000 && it != insCache_.end() && i < end; ctr++) {
      i = it->second->fallThrough();
      it = insCache_.find(i);
    }
  }

  auto it = insCache_.find(i);
  while(it != insCache_.end() && gaps_.find(it->first) != gaps_.end()) {
    i = it->second->fallThrough();
    it = insCache_.find(i);
  }
  end = i;
  //DEF_LOG("Linear scan: "<<hex<<start<<" - "<<hex<<end);
  return end;
}

typedef struct {
  //char *mne = NULL;
  //char *opcode = NULL;
  char *insn_buffer;
  bool reenter;
} stream_state;

/* This approach isn't very memory efficient or clear,
 * but it avoids external size/buffer tracking in this
 * example.
 */
static int dis_fprintf(void *stream, const char *fmt, ...) {
  stream_state *ss = (stream_state *)stream;

  va_list arg;
  va_start(arg, fmt);
  if (!ss->reenter) {
    vasprintf(&ss->insn_buffer, fmt, arg);
    ss->reenter = true;
  } else {
    char *tmp;
    vasprintf(&tmp, fmt, arg);

    char *tmp2;
    asprintf(&tmp2, "%s%s", ss->insn_buffer, tmp);
    free(ss->insn_buffer);
    free(tmp);
    ss->insn_buffer = tmp2;
  }
  va_end(arg);

  return 0;
}

void
DisasmEngn::disassembleLibOpcodes(uint8_t *buffer, size_t buff_size, 
                                  uint64_t start_addr, 
                                  vector <Instruction *> &ins_list) {

  //char *disassembled = NULL;
  stream_state ss = {};

  disassemble_info disasm_info = {};
  init_disassemble_info(&disasm_info, &ss, dis_fprintf);
  disasm_info.arch = bfd_arch_i386;
  disasm_info.mach = bfd_mach_x86_64;
  disasm_info.read_memory_func = buffer_read_memory;
  disasm_info.buffer = buffer;
  disasm_info.buffer_vma = 0;
  disasm_info.buffer_length = buff_size;
  disassemble_init_for_target(&disasm_info);

  disassembler_ftype disasm;
  disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);

  size_t pc = 0;
  while (pc < buff_size) {
    if(insCache_.find(start_addr) != insCache_.end() || invalid_.find(start_addr) != invalid_.end())
      return;
    //DEF_LOG("Disassembling addr: "<<hex<<start_addr);
    size_t insn_size = disasm(pc, &disasm_info);
    //if(ss.opcode == NULL) ss.opcode = "";
    //DEF_LOG("Disassembled: "<<ss.insn_buffer<<" "<<insn_size); 
    if(insn_size == 0) {
      free(ss.insn_buffer);
      ss.reenter = false;
      return;
    }

    string ins_str = ss.insn_buffer;

    if(ins_str.find("(bad)") != string::npos ||
       ins_str.find(".byte") != string::npos) {
      free(ss.insn_buffer);
      ss.reenter = false;
      return;
    }

    auto words = utils::split_string(ins_str.c_str());
    string mne = "";
    int i = 0;
    int word_cnt = words.size();
    for(auto & w : words) {
      if(utils::is_prefix(w) == false) break;
      mne += w + " ";
      i++;
    }
    if(i >= word_cnt) {
      free(ss.insn_buffer);
      ss.reenter = false;
      return;
    }

    mne += words[i];
    i++;
    string operand = "";
    while(i < word_cnt) {
      if(words[i] == "#") break;
      operand += words[i];
      i++;
    }

    //DEF_LOG("Mnemonic: "<<mne<<" "<<operand);
    Instruction *x = new Instruction(start_addr, (char *)mne.c_str(), (char *)operand.c_str(),
                                     buffer + pc,insn_size);
    ins_list.push_back (x);
    pc += insn_size;
    start_addr += insn_size;

    //if (disassembled == NULL) {
    //  asprintf(&disassembled, "%s", ss.insn_buffer);
    //} else {
    //  char *tmp;
    //  asprintf(&tmp, "%s\n%s", disassembled, ss.insn_buffer);
    //  free(disassembled);
    //  disassembled = tmp;
    //}

    /* Reset the stream state after each instruction decode.
     */
    free(ss.insn_buffer);
    ss.reenter = false;
  }

}

void
DisasmEngn::superSetCache(uint64_t start, uint64_t end) {
  DEF_LOG("Creating superset cache: "<<hex<<start<<"-"<<hex<<end);

  uint8_t *buffer = getBytes(start, end);
  while (buffer == NULL && start < end) {
    start++;
    buffer = getBytes(start, end);
  }
  if(buffer == NULL) return;
  size_t buff_size = end - start;
  auto start_addr = start;
  stream_state ss = {};

  disassemble_info disasm_info = {};
  init_disassemble_info(&disasm_info, &ss, dis_fprintf);
  disasm_info.arch = bfd_arch_i386;
  disasm_info.mach = bfd_mach_x86_64;
  disasm_info.read_memory_func = buffer_read_memory;
  disasm_info.buffer = buffer;
  disasm_info.buffer_vma = 0;
  disasm_info.buffer_length = buff_size;
  disassemble_init_for_target(&disasm_info);

  disassembler_ftype disasm;
  disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);

  size_t pc = 0;
  while (pc < buff_size) {
    if(insCache_.find(start_addr) != insCache_.end() || invalid_.find(start_addr) != invalid_.end())
      return;
    //DEF_LOG("Disassembling addr: "<<hex<<start_addr);
    size_t insn_size = disasm(pc, &disasm_info);
    //if(ss.opcode == NULL) ss.opcode = "";
    //DEF_LOG("Disassembled: "<<ss.insn_buffer<<" "<<insn_size); 
    if(insn_size == 0) {
      invalid_.insert(start_addr);
      pc++;
      start_addr++;
      free(ss.insn_buffer);
      ss.reenter = false;
      continue;
    }
    string ins_str = ss.insn_buffer;

    if(ins_str.find("(bad)") != string::npos ||
       ins_str.find(".byte") != string::npos) {
      invalid_.insert(start_addr);
    }
    else {
      auto words = utils::split_string(ins_str.c_str());
      string mne = "";
      int i = 0;
      int word_cnt = words.size();
      for(auto & w : words) {
        if(utils::is_prefix(w) == false) break;
        mne += w + " ";
        i++;
      }
      if(i >= word_cnt) {
        invalid_.insert(start_addr);
      }
      else {
        mne += words[i];
        i++;
        string operand = "";
        while(i < word_cnt) {
          if(words[i] == "#") break;
          operand += words[i];
          i++;
        }

        //DEF_LOG("Mnemonic: "<<mne<<" "<<operand);
        Instruction *x = new Instruction(start_addr, (char *)mne.c_str(), (char *)operand.c_str(),
                                         buffer + pc,insn_size);
        insCache_[start_addr] = x;
      }
    }
    //pc += insn_size;
    //start_addr += insn_size;
    pc++;
    start_addr++;

    /* Reset the stream state after each instruction decode.
     */
    free(ss.insn_buffer);
    ss.reenter = false;
  }

  for(uint64_t i = start; i < end; i++) {
    auto ins_it = insCache_.find(i);
    if(ins_it != insCache_.end()) {
      auto fall = ins_it->second->fallThrough();
      auto fall_it = insCache_.find(fall);
      if(fall_it != insCache_.end()) {
        ins_it->second->fallIns(fall_it->second);
      }
    }
  }
}

void
DisasmEngn::disassembleCaps(uint8_t *bytes, int size, uint64_t start,
		  vector <Instruction *> &ins_list) {
  //For disassembly using capstone disassembler.
  //Capstone takes a stream of bytes as input and returns a linear disassembly
  //output.
  //Capstone returns output in its pre-defined data structures. Usage shown
  //below.

  LOG ("machine code byte count " << dec << size);
  csh handle_;
  if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle_) != CS_ERR_OK) {
    LOG("Error opening capstone handle");
    exit(0);
  }
  cs_option (handle_, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
  cs_insn *ins;
  size_t count;
  uint64_t prev_loc = start;
  uint64_t end = start + size;//disasmEnd(start, size);
  if(start == 0x41c10)       
    DEF_LOG("Disassembling: "<<hex<<start<<"-"<<hex<<end);
  count = cs_disasm (handle_, bytes, end - start, start, 0, &ins);
  if (count > 0) {
    LOG ("fetched " << count << " instructions");
    size_t j;
    for (j = 0; j < count; j++) {
      if (prev_loc < ins[j].address) {
        //A gap could be because of disassembly error because of
        //presence of data.
        //When encountered, handle_gaps function puts out raw bytes
        //previously present in that gap.
        DEF_LOG ("Gap found at: " << hex<<prev_loc<<" - "<<hex<<ins[j].address);
        //disassembleObj(bytes + (prev_loc - start),
        //               ins[j].address - prev_loc,prev_loc,ins_list);
      }
      //if(ins[j].address == 0x405d86)
      //  DEF_LOG(hex<<ins[j].address<<":"<<ins[j].mnemonic<<" "<<ins[j].op_str);
      if(insCache_.find(ins[j].address) != insCache_.end()) {
        if(gaps_.find(ins[j].address) == gaps_.end()) {
          DEF_LOG("Ins present in cache...returning:"<<hex<<ins[j].address);
          cs_free(ins,count);
          cs_close(&handle_);
          return;
        }
        else
          gaps_.erase(ins[j].address);
      }
      Instruction *x = new Instruction(ins[j].address, ins[j].mnemonic,
          ins[j].op_str, ins[j].bytes,ins[j].size);
      ins_list.push_back (x);
      prev_loc = ins[j].address + ins[j].size;
    }
    cs_free(ins, count);
  }
  if(prev_loc < end) {
  //else {
    DEF_LOG ("Gap found at: " << hex<<prev_loc<<" - "<<hex<<(start + size));
    //disassembleObj(bytes + (prev_loc - start),
    //                 end - prev_loc,prev_loc,ins_list);
  }
  cs_close(&handle_);
  return;
}

void
DisasmEngn::disassembleObj (uint8_t *bytes, int size, uint64_t start,
		 vector <Instruction *> &ins_list) {


  //For disassembly using objdump
  //Takes a stream of bytes as input.
  //Puts out the bytes in an assembly file, assembles it and then calls
  //objdump on resulted object file.
  //It then parses every line of the objdump output to obtain details
  //regarding every instruction.

  uint64_t end = start + size;//disasmEnd(start, size);
  

  //string temp_asm = "log/" + to_string (start) + "_" + to_string (end) + ".s";
  string obj_name = "log/" + to_string (start) + "_" + to_string (end) + ".o";
  string dump_name = "log/tmp.dump";//obj_name + "_dump";

  //ofstream ofile;
  //ofile.open (temp_asm);
  //for (int i = 0; i < size; i++)
  //  ofile << ".byte " << (uint32_t) bytes[i] << endl;
  //string cmd = "gcc -c " + temp_asm + " -o " + obj_name;
  //if(system (cmd.c_str ()) < 0)
  //  LOG("System command failed");
  //DEF_LOG("objdumping: "<<hex<<start<<" - "<<hex<<end);
  string cmd = "objdump -d -w -M att-mnemonic -M suffix --start-address=" + to_string(start) + " --stop-address=" + to_string(end) + " " + bname_ + " | cut -d\"#\" -f1 | cut -d\"<\" -f1 > " + dump_name;
  if(system (cmd.c_str ()) < 0)
    LOG("System command failed");

  ifstream ifile;
  ifile.open (dump_name);
  int file_ctr = -1;
  //char line[1000];
  string line;
  uint64_t prev_loc = start;
  vector < string > results;
  regex bin ("[0-9a-f][0-9a-f]");
  while (getline (ifile,line)) {
    //DEF_LOG(line);
    results.clear ();
    if (file_ctr < 0) {
      if (strncmp (line.c_str(), "Disassembly", 11) == 0) {
        //Beginning of the dump file. Save the file name.
        file_ctr++;
      }
      else
        LOG("File ctr not found yet");
      continue;
    }
    if (file_ctr >= 0) {
      uint64_t loc;
      unsigned int l = 1;

      //int bin_count = 0;
      results = util.split_string (line.c_str());
      if (results.size () <= 2)
        continue;
      //LOG("Size > 2 "<<results[0]<<":"<<results[1]);
      //while(l < results.size() && results[l].size() <= 0) {
      //  DEF_LOG(results[l]);
      //  l++;
      //}
      //if(l >= results.size())
      //  continue;
      int colon_pos = results[0].find (":");
      if (colon_pos == string::npos)
        continue;
      //LOG("colon found");
      loc = stoi (results[0].replace (colon_pos, 1, ""), 0, 16);// + start;
      if (prev_loc < loc) {
        LOG ("Objdump Gap found at: " <<hex<< prev_loc<<"-"<<hex<<loc);
        handle_gaps(bytes, prev_loc, prev_loc - start, loc - prev_loc,
      	   ins_list);
      }
      if(insCache_.find(loc) != insCache_.end()) {
        if(gaps_.find(loc) == gaps_.end())
          return;
        else
          gaps_.erase(loc);
      }
      uint8_t opcodes[50];
      int ins_size = 0;
      while (l < results.size() && regex_match (results[l], bin)) {
        opcodes[ins_size] = stoi (results[l], 0, 16);
        //LOG("opcode "<<hex<<(uint32_t)opcodes[ins_size]);
        l++;
        ins_size++;
      }

      prev_loc = loc + ins_size;
      char *mnemonic = NULL;
      string mne = "";
      if ( l < results.size()) {
        if( results[l] == "jmpq" )
           results[l] = "jmp";
        if(results[l].find("ret") == 0 && (l+1) < results.size()) {
          LOG("Found ret with operand");
          handle_gaps(bytes, loc, loc - start, ins_size,ins_list);
        }
        INVALIDINS(results[l],bytes, loc, loc - start, ins_size,
             ins_list);
        while(l < results.size() && utils::is_prefix(results[l])) {
          mne += results[l] + " ";
          l++;
        }
        if(l < results.size()) {
          mne += results[l];
          l++;
        }
        INVALIDINS(mne,bytes, loc, loc - start, ins_size,
           ins_list);
      }
      else {
        LOG("Ins without mnemonic at: "<<hex<<loc);
        handle_gaps(bytes, loc, loc - start, ins_size,ins_list);
        continue;
      }
      char *operand = "";
      //if(loc == 0x405d86)
        //DEF_LOG(hex<<loc<<":  mne: "<<mne);
      mnemonic = (char *) mne.c_str ();
      if (l < results.size ()) {
        INVALIDINS(results[l],bytes, loc, loc - start, ins_size,
             ins_list);
        operand = (char *)(results[l].c_str());
      }
      Instruction *x = new Instruction(loc, mnemonic, operand, opcodes,
          ins_size);
      ins_list.push_back (x);
    }
  }
  if(prev_loc < end) {
    LOG ("Objdump Gap found at: " <<hex<< prev_loc<<"-"<<hex<<end);
    handle_gaps(bytes,prev_loc,prev_loc - start,
        end - prev_loc,ins_list);
  }
}

uint8_t *
DisasmEngn::getBytes(uint64_t start, uint64_t end) {
  for(auto & b : byteCache_) {
    if(b.first <= start && b.second.first >= end && b.second.first > start) {
      return (uint8_t *)(b.second.second + (start - b.first));
    }
  }
  size_t size = end - start;
  uint8_t *bytes =(uint8_t *) malloc(size);
  uint64_t start_offt = utils::GET_OFFSET(bname_,start);
  if(start_offt == 0) {
    LOG("Invalid address: "<<hex<<start);
    free(bytes);
    return NULL;
  }
  utils::READ_FROM_FILE(bname_,(void *) bytes, start_offt, size);
  byteCache_[start] = make_pair(end, bytes);
  return bytes;
}

vector <Instruction *> 
DisasmEngn::readIns(uint64_t start, uint64_t end) {
  vector <Instruction *> ins_list;
  bool cache_found = false;

  int size = end - start;
  uint8_t *bytes = NULL;
  for(auto & b : byteCache_) {
    if(b.first <= start && b.second.first >= end && b.second.first > start) {
      bytes = b.second.second + (start - b.first);
      //memcpy((void *)bytes, (void *)(b.second.second + (start - b.first)), size);
      cache_found = true;
    }
  }

  if(cache_found == false) {
    //LOG("byte cache not present!!!");
    bytes =(uint8_t *) malloc(size);
    uint64_t start_offt = utils::GET_OFFSET(bname_,start);
    if(start_offt == 0) {
      LOG("Invalid address: "<<hex<<start);
      free(bytes);
      return ins_list;
    }
    //DEF_LOG("reading file from: " <<hex<<start_offt <<" size " <<dec<<size);
    utils::READ_FROM_FILE(bname_,(void *) bytes, start_offt, size);
    byteCache_[start] = make_pair(end, bytes);
  }
  DISASENGN(bytes, size, start, ins_list);
  //if(cache_found)
    //free(bytes);
  return ins_list;

}

