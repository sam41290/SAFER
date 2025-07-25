#include "exe_manager.h"
#include "libutils.h"
#include "config.h"

//vector < pheader > utils::all_ph;
//string utils::cur_file = "";
//int utils::initialized = 0;

map<string, ExeManager *> utils::exeMap;

ExeManager::ExeManager (string p_filename, exe_format fmt)
{
  origBname_ = p_filename,
  bname_ = p_filename;
  fmt_ = fmt;
}

bool
ExeManager::is_ELF64 ()
{
  /*if(!strncmp((char*)(elf_header->e_ident), "\177ELF", 4)) {
     printf("ELFMAGIC \t= ELF\n");
     IS a ELF file 
     return 1;
     } else {
     printf("ELFMAGIC mismatch!\n");
     Not ELF file 
     return 0;
     } */

  return true;
}

uint64_t
ExeManager::encode (uint64_t ptr, uint64_t orig_ptr, uint64_t tramp_ptr)
{
  if (ENCODE == 1) {
    if(encode_.find (orig_ptr) != encode_.end ()) {
      ptr = encodePtr(orig_ptr,ptr,tramp_ptr);
      return ptr;
    }
    else
      return orig_ptr;
  }
  return ptr;
}

void
ExeManager::placeHooks(map <uint64_t, vector <uint8_t>> &hooks) {
  for (auto & h : hooks) {
    uint64_t offt = utils::GET_OFFSET(instBname_,h.first);
    int ctr = 0;
    for(auto & d : h.second) {
      char c = (char)d;
      utils::WRITE_TO_FILE(instBname_,&c,offt + ctr,1);
      ctr++;
    }
  }
}

vector <string> 
ExeManager::additionSecs() {
  vector <string> additional_secs;
  for(auto & sec : newSections_) {
    if(sec.additional)
      additional_secs.push_back(sec.name);
  }
  return additional_secs;
}

pair <uint64_t, uint64_t> 
ExeManager::progMemRange() {
  uint64_t start = INT_MAX, end = 0;
  vector <pheader> phdrs = ptLoadHeaderes ();
  for(auto & p : phdrs) {
    DEF_LOG("Pheader: "<<hex<<p.address<<"->"<<p.address + p.mem_sz);
    if(p.address < start)
      start = p.address;
    if((p.address + p.mem_sz) > end)
      end = p.address + p.mem_sz;
  }
  DEF_LOG("Program mem range: "<<hex<<start<<"->"<<end);
  return make_pair(start,end);
}

