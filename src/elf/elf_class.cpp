/*-----------------------------------------------------------------------

Author: Soumyakant Priyadarshan
		PhD student, Stony Brook University

Description:
	Member function definitions for the class "ElfClass".
	Creates necessary data structures to store "sections, segments and symbols" information.
	
Reference:
	1. https://github.com/TheCodeArtist/elf-parser

-------------------------------------------------------------------------*/



#include "elf64.h"
#include <iostream>
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include<stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iterator>
#include <vector>
#include <regex>
#include <map>
#include "elf_class.h"

#include "libutils.h"

using namespace std;

bool
compare_sections (section & A, section & B) {
  return A.vma < B.vma;
}

void
sort_sections (vector < section > &vec_of_sections) {
  sort (vec_of_sections.begin (), vec_of_sections.end (), compare_sections);
}

bool
compare_pheaders (pheader & A, pheader & B) {
  return A.offset < B.offset;
}

void
sort_pheaders (vector <pheader> &vec_of_pheader) {
  sort (vec_of_pheader.begin (), vec_of_pheader.end (), compare_pheaders);
}

bool
compare_reloc(Reloc & A, Reloc & B) {
  return A.storage < B.storage;
}

void sort_reloc (vector <Reloc> & rela_list) {
  sort(rela_list.begin(),rela_list.end(),compare_reloc);
}

void *section_data(uint64_t offt,uint64_t sz,string file) {
  //LOG("Getting section data at: "<<hex<<offt);
  void *data = (void *)malloc(sz);
  utils::READ_FROM_FILE (file, data, offt, sz);
  return data;
}

void symtbl_to_ptr(Elf64_Shdr *sym_sec, Elf64_Phdr *code_ph,
                   vector <uint64_t> &sym_values,string file, int type) {
  Elf64_Sym *sym_tbl = 
    (Elf64_Sym *)section_data((uint64_t)sym_sec->sh_offset,(uint64_t)sym_sec->sh_size,file);
  uint32_t sym_count = (sym_sec->sh_size) / sizeof (Elf64_Sym);

  for (uint32_t j = 0; j < sym_count; j++) {
    if (sym_tbl[j].st_value == 0 || (sym_tbl[j].st_info & 0xf) ==
    STT_TLS || (sym_tbl[j].st_info & 0xf) != type)
      continue;

    if (sym_tbl[j].st_value >= code_ph->p_vaddr &&
    sym_tbl[j].st_value <= (code_ph->p_vaddr + code_ph->p_memsz))
      sym_values.push_back (sym_tbl[j].st_value);

  }
}

void 
ElfClass::ptrArray(vector <Reloc> &lst, string secname) {

  vector < section > code_sections = sections (section_types::RX);
  uint64_t code_segment_end =
    code_sections[code_sections.size () - 1].vma +
    code_sections[code_sections.size () - 1].size;
  elf_section
    array_section = elfSectionHdr (secname);
  Elf64_Shdr *
    sh = array_section.sh;
  if (sh == NULL)
    return;
  if (sh->sh_offset == 0)
    return;
  ////LOG("Reading section: "<<secname);
  uint64_t *array = (uint64_t *)section_data(sh->sh_offset,sh->sh_size,binaryName());
  int entry_cnt = sh->sh_size/sizeof(uint64_t);
  uint64_t loc = sh->sh_addr;
  for(int i = 0; i < entry_cnt; i++) {
    uint64_t addr = array[i];
    if (addr != 0 && addr < code_segment_end) {
      LOG("section "<<secname<<" ptr: "<<hex<<addr);
      Reloc r;
      r.ptr = addr;
      r.storage = loc;
      lst.push_back (r);
    }
    loc += 8;
  }

}

ElfClass::ElfClass (string name):ExeManager (name,exe_format::ELF) {
  ElfClass::parse (name.c_str ());
}

void
ElfClass::parse (const char *file_name) {
  elfHeader_ = new Elf64_Ehdr ();
  fd = open (file_name, O_RDONLY);
  if (fd < 0) {
      LOG ("Error " << fd << " Unable to open file_name");
    }
  bname(file_name);
  ElfClass::readElfHeader64 ();
  ElfClass::readPHdrTbl64 ();
  ElfClass::readSectionHdrTbl64 ();
  ElfClass::readSymbols64 ();
  ElfClass::readJmpSlots ();
  ElfClass::readRelocs();
}

ElfClass::ElfClass ():ExeManager () {
  //binary_type = type;
}

ElfClass::~ElfClass () {
  close (fd);
  free (elfHeader_);
  for(auto sh : shTable_)
    free (sh);
  for(auto p : phTable_)
    free (p);
}

void
ElfClass::readElfHeader64 () {
  assert (lseek (fd, (off_t) 0, SEEK_SET) == (off_t) 0);
  assert (read (fd, (void *) (elfHeader_), sizeof (Elf64_Ehdr)) ==
	  sizeof (Elf64_Ehdr));
}

Elf64_Ehdr
ElfClass::elfHeader () {
  Elf64_Ehdr ehdr;
  memcpy (&ehdr, (void *) (elfHeader_), sizeof (Elf64_Ehdr));

  return ehdr;
}

uint64_t
ElfClass::entryPoint () {
  Elf64_Ehdr eh = elfHeader ();
  return eh.e_entry;
}

char *
ElfClass::readSection64 (Elf64_Shdr * sh) {
  LOG("Reading section at: "<<hex<<sh->sh_offset);
  char *buff = (char *) malloc (sh->sh_size);

  if (!buff) {
      LOG (__func__ << ":Failed to allocate " << sh->sh_size << " bytes");
  }

  assert (buff != NULL);
  assert (lseek (fd, (off_t) sh->sh_offset, SEEK_SET) == (off_t) sh->sh_offset);
  assert (read (fd, (void *) (buff), sh->sh_size) == sh->sh_size);

  return buff;
}

void
ElfClass::readPHdrTbl64 () {
  uint32_t i;

  assert (lseek (fd, (off_t) elfHeader_->e_phoff, SEEK_SET) ==
	  (off_t) elfHeader_->e_phoff);

  for (i = 0; i < elfHeader_->e_phnum; i++) {
    Elf64_Phdr *ph = new Elf64_Phdr ();
    assert (read (fd, (void *) ph, elfHeader_->e_phentsize)
        == elfHeader_->e_phentsize);
    phTable_.push_back (ph);

  }
  LOG("Program header read complete!!\n");
}


int
ElfClass::pHdrIndx (unsigned int type, int flag) {
  for(size_t i = 0; i < phTable_.size (); i++) {
    if (flag == -1 && phTable_[i]->p_type == type)
      return i;
    else if (phTable_[i]->p_type == type && phTable_[i]->p_flags == flag)
      return i;
  }
  return -1;
}

vector <Elf64_Phdr *>
ElfClass::elfPhdr (elf_pheader_types type, elf_pheader_flags flag) {
  //int index = pHdrIndx ((int) type, (int) flag);
  vector <Elf64_Phdr *> p_lst;
  for(size_t i = 0; i < phTable_.size (); i++) {
    if (((int)flag == -1 || flag == elf_pheader_flags::DONTCARE) &&
        phTable_[i]->p_type == (unsigned int)type)
      p_lst.push_back(phTable_[i]);
    else if (phTable_[i]->p_type == (unsigned int)type && phTable_[i]->p_flags == (int)flag)
      p_lst.push_back(phTable_[i]);
  }
  return p_lst;
}

vector <pheader>
ElfClass::prgrmHeader (pheader_types p_type, pheader_flags p_flag) {
  vector <Elf64_Phdr *> ph_lst = elfPhdr (p_type, p_flag);
  vector <pheader> phdr_lst;
  for(auto & ph : ph_lst) {
    pheader p(ph->p_offset,ph->p_vaddr,ph->p_filesz,ph->p_memsz);
    p.p_flag = REVERSE_PFLAG(ph->p_flags);
    phdr_lst.push_back(p);
  }
  return phdr_lst;
}

vector < pheader > ElfClass::ptLoadHeaderes () {
  vector < pheader > all_ph;
  for(size_t i = 0; i < phTable_.size (); i++) {
    if (phTable_[i]->p_type == PT_LOAD) {
      pheader p(phTable_[i]->p_offset,phTable_[i]->p_vaddr,phTable_[i]->p_filesz,phTable_[i]->p_memsz);
      p.p_flag = REVERSE_PFLAG(phTable_[i]->p_flags);
      all_ph.push_back (p);
    }
  }
  return all_ph;
}

void
ElfClass::readSectionHdrTbl64 () {
  uint32_t i;
  LOG("Reading section header table at: "<<hex<<elfHeader_->e_shoff<<" cnt: "<<elfHeader_->e_shnum<<" str tbl index: "<<elfHeader_->e_shstrndx);
  assert (lseek (fd, (off_t) elfHeader_->e_shoff, SEEK_SET) ==
	  (off_t) elfHeader_->e_shoff);
  for (i = 0; i < elfHeader_->e_shnum; i++) {
    Elf64_Shdr *sh = new Elf64_Shdr ();
    assert (read (fd, (void *) sh, elfHeader_->e_shentsize)
        == elfHeader_->e_shentsize);
    LOG("Section :"<<i<<" offset: "<<hex<<sh->sh_offset<<" name index "<<sh->sh_name);
    shTable_.push_back (sh);

  }
  char *sh_str = readSection64 (shTable_[elfHeader_->e_shstrndx]);
  for (i = 0; i < elfHeader_->e_shnum; i++) {
    char *sec_name = sh_str + shTable_[i]->sh_name;
    assert (sec_name != NULL);
    string name (sec_name);

    if (name.length () == 0)
      continue;
    LOG("Reading section: "<<sec_name<<" index: "<<i);
    elf_section sec;
    sec.name = name;
    sec.sh = shTable_[i];
    sec.hdr_indx = i;
    sec.header_offset =
      (elfHeader_->e_shentsize * i) + elfHeader_->e_shoff;
    allSections_[name] = sec;
  }
  free (sh_str);
}

void
ElfClass::readSymTbl64 (int32_t symbol_table) {
  LOG("Reading symbol table: "<<symbol_table);
  char *str_tbl;
  Elf64_Sym *sym_tbl;
  uint32_t i, symbol_count;

  sym_tbl = (Elf64_Sym *) readSection64 (shTable_[symbol_table]);

  /* Read linked string-table
   * Section containing the string table having names of
   * symbols of this section
   */
  uint32_t str_tbl_ndx = shTable_[symbol_table]->sh_link;
  str_tbl = readSection64 (shTable_[str_tbl_ndx]);

  symbol_count = (shTable_[symbol_table]->sh_size / sizeof (Elf64_Sym));
  LOG("Symbol count: "<<symbol_count);
  for (i = 0; i < symbol_count; i++) {
    LOG("Symbol string index: "<<sym_tbl[i].st_name<<" val: "<<hex<<sym_tbl[i].st_value);
    string name ((str_tbl + sym_tbl[i].st_name));
    allSyms_[name] = (off_t) sym_tbl[i].st_value;
  }

  free (sym_tbl);
  free (str_tbl);
}
vector <Object>
ElfClass::noTypeObjects () {
  vector <Object> data_objects;
  for (auto i = 0; i < elfHeader_->e_shnum; i++) {
    if ((shTable_[i]->sh_type == SHT_SYMTAB)
    || (shTable_[i]->sh_type == SHT_DYNSYM)) {
      char *str_tbl;
      Elf64_Sym *sym_tbl;
      uint32_t symbol_count;

      sym_tbl = (Elf64_Sym *) readSection64 (shTable_[i]);

      /* Read linked string-table
       * Section containing the string table having names of
       * symbols of this section
       */
      uint32_t str_tbl_ndx = shTable_[i]->sh_link;
      str_tbl = readSection64 (shTable_[str_tbl_ndx]);

      symbol_count = (shTable_[i]->sh_size / sizeof (Elf64_Sym));
      for (auto j = 0; j < symbol_count; j++) {

        string nm ((str_tbl + sym_tbl[j].st_name));
        uint64_t addr = (off_t) sym_tbl[j].st_value;
        if((sym_tbl[j].st_info & 0xf) == STT_NOTYPE) {
          Object o;
          o.name = nm;
          o.addr = addr;
          o.size = sym_tbl[j].st_size;
          data_objects.push_back(o);
        }
      }

      free (sym_tbl);
      free (str_tbl);
    }
  }
  return data_objects;
}

vector <Object>
ElfClass::dataObjects () {
  vector <Object> data_objects;
  for (auto i = 0; i < elfHeader_->e_shnum; i++) {
    if ((shTable_[i]->sh_type == SHT_SYMTAB)
    || (shTable_[i]->sh_type == SHT_DYNSYM)) {
      char *str_tbl;
      Elf64_Sym *sym_tbl;
      uint32_t symbol_count;

      sym_tbl = (Elf64_Sym *) readSection64 (shTable_[i]);

      /* Read linked string-table
       * Section containing the string table having names of
       * symbols of this section
       */
      uint32_t str_tbl_ndx = shTable_[i]->sh_link;
      str_tbl = readSection64 (shTable_[str_tbl_ndx]);

      symbol_count = (shTable_[i]->sh_size / sizeof (Elf64_Sym));
      for (auto j = 0; j < symbol_count; j++) {

        string nm ((str_tbl + sym_tbl[j].st_name));
        uint64_t addr = (off_t) sym_tbl[j].st_value;
        if((sym_tbl[j].st_info & 0xf) == STT_OBJECT) {
          Object o;
          o.name = nm;
          o.addr = addr;
          o.size = sym_tbl[j].st_size;
          data_objects.push_back(o);
        }
      }

      free (sym_tbl);
      free (str_tbl);
    }
  }
  return data_objects;
}
vector <Object>
ElfClass::codeObjects () {
  vector <Object> code_objects;
  for (auto i = 0; i < elfHeader_->e_shnum; i++) {
    if ((shTable_[i]->sh_type == SHT_SYMTAB)
    || (shTable_[i]->sh_type == SHT_DYNSYM)) {
      char *str_tbl;
      Elf64_Sym *sym_tbl;
      uint32_t symbol_count;

      sym_tbl = (Elf64_Sym *) readSection64 (shTable_[i]);

      /* Read linked string-table
       * Section containing the string table having names of
       * symbols of this section
       */
      uint32_t str_tbl_ndx = shTable_[i]->sh_link;
      str_tbl = readSection64 (shTable_[str_tbl_ndx]);

      symbol_count = (shTable_[i]->sh_size / sizeof (Elf64_Sym));
      for (auto j = 0; j < symbol_count; j++) {

        string nm ((str_tbl + sym_tbl[j].st_name));
        uint64_t addr = (off_t) sym_tbl[j].st_value;
        if((sym_tbl[j].st_info & 0xf) == STT_FUNC && addr != 0) {
          Object o;
          o.name = nm;
          o.addr = addr;
          o.size = sym_tbl[j].st_size;
          code_objects.push_back(o);
        }
      }

      free (sym_tbl);
      free (str_tbl);
    }
  }
  return code_objects;
}

void
ElfClass::readSymbols64 () {
  LOG("-----Reading symbols-------");
  uint32_t i;

  for (i = 0; i < elfHeader_->e_shnum; i++) {
    if ((shTable_[i]->sh_type == SHT_SYMTAB)
    || (shTable_[i]->sh_type == SHT_DYNSYM)) {
      readSymTbl64 (i);
    }
  }
}

vector < uint64_t > ElfClass::allSyms () {

  /* Returns all symbol values (dynamic + debugging symbols if available)
   */

  int
    code_segment_index = pHdrIndx (PT_LOAD, 5);
  Elf64_Phdr *
    code_ph = phTable_[code_segment_index];

  vector < uint64_t > sym_values;
  vector<elf_section> sym_sections;
  SECTIONS(SHT_DYNSYM,sym_sections);
  SECTIONS(SHT_SYMTAB,sym_sections);
  for (auto & sec :  sym_sections) {
    symtbl_to_ptr(sec.sh,code_ph,sym_values,binaryName(),STT_FUNC);
    //symtbl_to_ptr(sec.sh,code_ph,sym_values,binaryName(),STT_NOTYPE);
  }
  return sym_values;
}


vector < uint64_t > ElfClass::dataSyms () {

  /* Returns all symbol values (dynamic + debugging symbols if available)
   */

  int
    code_segment_index = pHdrIndx (PT_LOAD, 5);
  Elf64_Phdr *
    code_ph = phTable_[code_segment_index];

  vector < uint64_t > sym_values;
  vector<elf_section> sym_sections;
  SECTIONS(SHT_SYMTAB,sym_sections);
  for (auto & sec :  sym_sections) {
    symtbl_to_ptr(sec.sh,code_ph,sym_values,binaryName(),STT_OBJECT);
  }
  return sym_values;
}

vector < elf_section > ElfClass::symSections () {
  /* Returns sections that contain symbols
   */
  vector < elf_section > sym_secs;
  SECTIONS(SHT_SYMTAB,sym_secs);
  SECTIONS(SHT_DYNSYM,sym_secs);
  return sym_secs;
}



bool
ElfClass::is64Bit () {
  if (elfHeader_->e_ident[EI_CLASS] == ELFCLASS64)
    return true;
  else
    return false;
}

off_t
ElfClass::symbolVal (string func_name) {

  /* Given a symbol or function name, returns its memory offset.
   */
  map < string, off_t >::iterator it;
  it = allSyms_.find (func_name);
  if (it == allSyms_.end ())
    return -1;
  return it->second;
}

elf_section
ElfClass::elfSectionHdr (string sec_name) {
  elf_section sec;
  auto it = allSections_.find (sec_name);
  if (it != allSections_.end ())
    return it->second;
  else
  {
    LOG("Section "<<sec_name<<" not found");
    //exit(0);
    sec.sh = NULL;
  }
  return sec;
}

section
ElfClass::secHeader (string sec_name) {
  elf_section sec = elfSectionHdr (sec_name);

  if (sec.sh != NULL) {
    section
      s(sec.name,sec.sh->sh_offset,sec.sh->sh_size,sec.sh->sh_addr,sec.sh->sh_addralign);
    return s;
  }
  else {
    LOG("Section "<<sec_name<<" not found");
    //exit(0);
    section s("dummy",0,0,0,0);
    return s;
  }

}

vector < elf_section > ElfClass::relaSections () {
  vector < elf_section > rela_sections;
  SECTIONS(SHT_RELA,rela_sections);
  return rela_sections;
}

bool 
ElfClass::isEhSection(uint64_t addrs) {
  for(auto & s : allSections_) {
    if(s.second.sh->sh_addr != 0 && addrs >= s.second.sh->sh_addr &&
       addrs < (s.second.sh->sh_addr + s.second.sh->sh_size)) {
      if(ehSections_.find(s.first) != ehSections_.end()) {
        LOG("Section: "<<s.first<<" at "<<hex<<addrs<<"|"<<hex<<s.second.sh->sh_addr<<" is EH");
        return true;
      }
      else
        return false;
    }
  }
  return false;
}

bool 
ElfClass::isMetaData(uint64_t addrs) {
  for(auto & s : allSections_) {
    if(s.second.sh->sh_addr != 0 && addrs >= s.second.sh->sh_addr &&
       addrs < (s.second.sh->sh_addr + s.second.sh->sh_size)) {
      if(metaSections_.find(s.first) != metaSections_.end())
        return true;
      else
        return false;
    }
  }
  return true;
}

vector < elf_section > 
ElfClass::elfSections (elf_section_types sec_type) {
  vector < elf_section > sec_lst;
  switch (sec_type) {
  case elf_section_types::RW:
    return rwSections ();
  case elf_section_types::RX:
    return rxSections ();
  case elf_section_types::RONLY:
    return ronlySections ();
  case elf_section_types::RELRO:
    return relroSections ();
  case elf_section_types::SYM:
    return symSections ();
  case elf_section_types::RELA:
    return relaSections ();
  case elf_section_types::RorX:
    return rorxSections ();
  case elf_section_types::ALL:
    for (auto & sec : allSections_)
      sec_lst.push_back (sec.second);
    break;
  case elf_section_types::NONLOAD:
    for (auto & sec : allSections_)
      if(sec.second.sh->sh_addr == 0)
        sec_lst.push_back (sec.second);
    break;
  }
  return sec_lst;
}

vector < section > ElfClass::sections (section_types p_type) {
  vector < elf_section > elf_section_vec = elfSections (p_type);
  vector < section > section_vec;
  for (elf_section sec:elf_section_vec) {
    section
      s(sec.name,sec.sh->sh_offset,sec.sh->sh_size,sec.sh->sh_addr,sec.sh->sh_addralign);
    switch (sec.sh->sh_flags & 0xf) {
    case 2:
      s.sec_type = section_types::RONLY;
      break;
    case 6:
      s.sec_type = section_types::RX;
      break;
    case 3:
      s.sec_type = section_types::RW;
      break;
    default:
      s.sec_type = p_type;
      break;
    }
    if(metaSections_.find(sec.name) != metaSections_.end())
      s.is_metadata = true;
    section_vec.push_back (s);
  }
  sort_sections (section_vec);
  return section_vec;

}

vector < elf_section > ElfClass::rwSections () {
  int index =
    pHdrIndx ((int) elf_pheader_types::LOAD,
		       (int) elf_pheader_flags::RW);
  Elf64_Phdr *
    ph = phTable_[index];
  vector < elf_section > data_sections;
  for (auto & sec : allSections_) {
    Elf64_Shdr *sh = sec.second.sh;
    if (sh->sh_addr != 0
        && sh->sh_offset >= ph->p_offset
        && sh->sh_offset < (ph->p_offset + ph->p_memsz)) {
      data_sections.push_back (sec.second);
    }
  }
  return data_sections;
}

vector < elf_section > ElfClass::rxSections () {
  /* Returns sections with read and execute permissions.
   */
  int index =
    pHdrIndx ((int) elf_pheader_types::LOAD,
		       (int) elf_pheader_flags::RX);
  Elf64_Phdr * ph = phTable_[index];

  vector < elf_section > code_sections;
  for (auto & sec : allSections_) {
    Elf64_Shdr *sh = sec.second.sh;
    if (sh->sh_offset >= ph->p_offset
    && sh->sh_offset < (ph->p_offset + ph->p_memsz)
    && sh->sh_flags == 6) {
      code_sections.push_back (sec.second);
    }
  }
  return code_sections;
}

vector < elf_section > ElfClass::ronlySections () {
  /* Returns sections with read only permissions,
   */
  uint64_t
    min_addrs = INT_MAX;
  uint64_t
    max_addrs = 0;
  for(unsigned int i = 0; i < phTable_.size (); i++) {
    if (phTable_[i]->p_type == PT_LOAD && (phTable_[i]->p_flags == 4 ||
  				     phTable_[i]->p_flags == 5)) {
      if (phTable_[i]->p_vaddr < min_addrs)
        min_addrs = phTable_[i]->p_vaddr;
      if ((phTable_[i]->p_vaddr + phTable_[i]->p_memsz) > max_addrs)
        max_addrs = phTable_[i]->p_vaddr + phTable_[i]->p_memsz;
    }
  }
  vector < elf_section > code_sections;
  for (auto & sec : allSections_) {
    Elf64_Shdr *sh = sec.second.sh;
    if (sh->sh_addr != 0 && sh->sh_addr >= min_addrs 
        && sh->sh_addr < max_addrs 
        && (sh->sh_flags & 0xf) == 0x2) {
      code_sections.push_back (sec.second);
    }
  }
  return code_sections;
}

vector < elf_section > ElfClass::rorxSections () {
  /* Returns section with read-only/read-execute permissions.
   */
  uint64_t
    min_addrs = INT_MAX;
  uint64_t
    max_addrs = 0;
  for(unsigned int i = 0; i < phTable_.size (); i++) {
    if (phTable_[i]->p_type == PT_LOAD && (phTable_[i]->p_flags == 4 ||
  				     phTable_[i]->p_flags == 5)) {
      if (phTable_[i]->p_vaddr < min_addrs)
        min_addrs = phTable_[i]->p_vaddr;
      if ((phTable_[i]->p_vaddr + phTable_[i]->p_memsz) > max_addrs)
        max_addrs = phTable_[i]->p_vaddr + phTable_[i]->p_memsz;
    }
  }
  LOG("RorX sections:");
  vector < elf_section > code_sections;
  for (auto & sec : allSections_) {
    auto sh = sec.second.sh;
    if (sh->sh_addr != 0 
        && sh->sh_addr >= min_addrs 
        && sh->sh_addr < max_addrs) {
      LOG(sec.first);
      code_sections.push_back (sec.second);
    }
  }
  return code_sections;
}


vector < elf_section > ElfClass::relroSections () {
  /* Returns all sections that contain relocated pointers.
   */

  int
    index = pHdrIndx (PT_GNU_RELRO, -1);
  Elf64_Phdr *
    ph = phTable_[index];


  vector < elf_section > code_sections;
  for (auto & sec : allSections_) {
    auto sh = sec.second.sh;
    if (sh->sh_offset >= ph->p_offset
        && sh->sh_offset < (ph->p_offset + ph->p_memsz)
        && (sh->sh_type == SHT_INIT_ARRAY
        || sh->sh_type == SHT_FINI_ARRAY
        || sh->sh_type == SHT_PREINIT_ARRAY
        || sec.first == ".data.rel.ro")) {
      code_sections.push_back (sec.second);
    }
  }
  return code_sections;
}

bool
ElfClass::usedAtRunTime(uint64_t addrs) {
  for(auto sec: allSections_) {
    if(sec.second.sh->sh_addr != 0 &&
       addrs >= sec.second.sh->sh_addr &&
       addrs < (sec.second.sh->sh_addr + sec.second.sh->sh_size)) {
      if(sec.second.sh->sh_flags < 2 || sec.second.sh->sh_flags > 6)
        return false;
      if(sec.first == ".eh_frame_hdr" ||
         sec.first == ".eh_frame" ||
         sec.first == ".dynamic" ||
         sec.first == ".dynsym")
        return false;

      return true;

    }
  }
  return false;
}

void
ElfClass::readRelocs() {
  LOG("-------------Reading relocs----------------"); 
  vector <elf_section> rela_sections = relaSections ();
  for(auto & sec : rela_sections) {
    LOG("Reading section "<<sec.name);
    Elf64_Rela *rl
      = (Elf64_Rela *)section_data(sec.sh->sh_offset,sec.sh->sh_size,binaryName());
    int entry_count = sec.sh->sh_size / sizeof (Elf64_Rela);
    for(int j = 0; j < entry_count; j++) {
      /*
         for entries of type R_X86_64_IRELATIVE and R_X86_64_RELATIVE,
         addend needs to be updated to point to location in new codesegment
       */

      if (rl[j].r_info == R_X86_64_IRELATIVE || 
          rl[j].r_info == R_X86_64_RELATIVE) {
        if(rl[j].r_addend > 0) {
          Reloc r;
          r.storage = rl[j].r_offset;
          r.ptr = rl[j].r_addend;
          allRelocs_[rel::CONSTPTR_PIC].push_back(r);
        }
      }

    }
    free (rl);
  }

//READING EXTRA RELOCS NECESSARY FOR GROUND TRUTH

  string bname = binaryName ();
  /*

  vector <elf_section> sym_secs;
  SECTIONS(SHT_SYMTAB,sym_secs);

  if(sym_secs.size() <= 0) {
    LOG("No sym table available. No point in reading extra relocs");
    return;
  }
  else
    sym_sh = sym_secs[0].sh; //Must be only one symbol table.

  if(sym_sh == NULL) {
    LOG("Error: No symbol section in the executable");
    exit(1);
  }
  */
  //uint64_t string_tbl_idx = sym_sh->sh_link;
  //uint64_t string_tbl_offset = shTable_[string_tbl_idx]->sh_offset;
  //uint64_t string_tbl_size = shTable_[string_tbl_idx]->sh_size;

  //char *all_strings = (char *)section_data(string_tbl_offset,
  //    string_tbl_size,bname);



  for(auto & sec : rela_sections) {
    LOG("Reading section "<<sec.name);
    if(sec.name != ".rela.eh_frame" &&
       sec.name != ".rela.debug_aranges" &&
       sec.name != ".rela.debug_info" &&
       sec.name != ".rela.debug_line" &&
       sec.name != ".rela.debug_loc" &&
       sec.name != ".rela.debug_ranges") {
      Elf64_Rela *rl
        = (Elf64_Rela *)section_data(sec.sh->sh_offset,sec.sh->sh_size,binaryName());
      int entry_count = sec.sh->sh_size / sizeof (Elf64_Rela);
      Elf64_Shdr *sym_sh = shTable_[sec.sh->sh_link];
      Elf64_Sym *sym_tbl = (Elf64_Sym *)section_data(sym_sh->sh_offset,
      sym_sh->sh_size,bname);
      for(int j = 0; j < entry_count; j++) {
        //if(usedAtRunTime(rl[j].r_offset)) { 
          uint32_t type = (uint32_t) rl[j].r_info;
          if (type == R_X86_64_PLT32) {
            ADDRELOC(true,rel::CFTARGET,rl[j].r_addend,rl[j].r_offset,
                sym_tbl,rl[j].r_info);
          }
          else if (type == R_X86_64_PC32 || type == R_X86_64_PC16
                   || type == R_X86_64_PC8) {
            ADDRELOC(true,rel::PCREL,rl[j].r_addend,rl[j].r_offset,
                sym_tbl,rl[j].r_info);
          }
          else if (type == R_X86_64_64 || type == R_X86_64_32
                   || type == R_X86_64_32S || type == R_X86_64_16
                   || type == R_X86_64_8) {
            ADDRELOC(false,rel::CONSTPTR_NOPIC,rl[j].r_addend,rl[j].r_offset,
                sym_tbl,rl[j].r_info);
          }
        //}
      }

      free (rl);
    }
  }

}
vector <Reloc> 
ElfClass::relocatedPtrs (rel type) {
  /* returns all relocated pointers.
   */
  vector <Reloc> rela_list = allRelocs_[type];
  sort_reloc(rela_list);
  return rela_list;
}

vector <Reloc> ElfClass::pltGotTramps () {

  /* Obtains pointers stored in .got and .got.plt sections.
   * These are valid code pointers.
   */
   
  vector <Reloc> pointers;
  ptrArray(pointers,".got");
  ptrArray(pointers,".got.plt");
  return pointers;
}

vector <Reloc> ElfClass::initArray () {
  /* Extracts pointers from .init_array section.
   */

  vector <Reloc> init_ptrs;
  ptrArray(init_ptrs,".init_array");
  return init_ptrs;
}

vector <Reloc> ElfClass::finiArray () {
  /* Extracts pointers from .fini_array section.
   */

  vector <Reloc> fini_ptrs;
  ptrArray(fini_ptrs,".fini_array");
  return fini_ptrs;
}


vector <uint64_t> ElfClass::dynSyms () {
  /* Returns all dynamic symbols.
   */

  int code_segment_index = pHdrIndx (PT_LOAD, 5);
  Elf64_Phdr *code_ph = phTable_[code_segment_index];

  vector < uint64_t > sym_values;
  vector <elf_section> dyn_sym_sections;
  SECTIONS(SHT_DYNSYM,dyn_sym_sections);

  for (auto & sec : dyn_sym_sections) {
    symtbl_to_ptr(sec.sh,code_ph,sym_values,binaryName(),STT_FUNC);
    symtbl_to_ptr(sec.sh,code_ph,sym_values,binaryName(),STT_GNU_IFUNC);
  }

  return sym_values;
}


vector <Reloc> ElfClass::codePtrs () {
  /* Returns all known code pointers.
   */
  vector <Reloc> code_pointers;
  vector <Reloc> trampolines = pltGotTramps ();
  code_pointers.insert (code_pointers.end (), trampolines.begin (),
			trampolines.end ());
  vector <Reloc> init_array = initArray ();
  code_pointers.insert (code_pointers.end (), init_array.begin (),
			init_array.end ());
  vector <Reloc> fini_array = finiArray ();
  code_pointers.insert (code_pointers.end (), fini_array.begin (),
			fini_array.end ());
  vector <uint64_t> dyn_syms = dynSyms ();
  for(auto & s : dyn_syms) {
    Reloc r;
    r.ptr = s;
    r.storage = 0;
    code_pointers.push_back(r);
  }


  section sec = secHeader (".dynamic");
  uint64_t dyn_offset = sec.offset;

  uint64_t size = sec.size;

  int dyn_count = size / sizeof (Elf64_Dyn);
  //LOG("Reading section "<<sec.name);
  Elf64_Dyn *dyn = (Elf64_Dyn *)section_data(dyn_offset,size,binaryName ());

  for(int i = 0; i < dyn_count; i++) {
    if (dyn[i].d_tag == DT_INIT) {
      Reloc r;
      r.ptr = dyn[i].d_un.d_ptr;
      r.storage = 0;
      code_pointers.push_back(r);
    }
  }
  free(dyn);
  return code_pointers;

}

void
ElfClass::populateNewSymOffts (string obj_file) {

  /* Populates memory offsets of symbols after re-assembly.
   */

  LOG ("-----------------populating new symbol offsets---------------");

  uint64_t code_segment_offset = codeSegOffset();

  LOG ("new code segment offset: " << hex << code_segment_offset);

  Elf64_Ehdr *elfHeader_ = new Elf64_Ehdr ();
  int fd = open (obj_file.c_str (), O_RDONLY);
  if (fd < 0) {
    LOG ("Error " << fd << " Unable to open " << obj_file);
  }
  assert (lseek (fd, (off_t) 0, SEEK_SET) == (off_t) 0);
  assert (read (fd, (void *) (elfHeader_), sizeof (Elf64_Ehdr)) ==
	  sizeof (Elf64_Ehdr));

  LOG ("section table offset of obj file: " << hex << elfHeader_->e_shoff);

  assert (lseek (fd, (off_t) elfHeader_->e_shoff, SEEK_SET) ==
	  (off_t) elfHeader_->e_shoff);

  vector < Elf64_Shdr * >sh_tbl;
  for(unsigned int i = 0; i < elfHeader_->e_shnum; i++) {
    Elf64_Shdr *sh = new Elf64_Shdr ();
    assert (read (fd, (void *) sh, elfHeader_->e_shentsize)
        == elfHeader_->e_shentsize);
    sh_tbl.push_back (sh);

  }

  for(unsigned int i = 0; i < elfHeader_->e_shnum; i++) {
    if ((sh_tbl[i]->sh_type == SHT_SYMTAB)
    || (sh_tbl[i]->sh_type == SHT_DYNSYM)) {
      char *str_tbl;
      uint32_t symbol_count;
      LOG ("Symbol table offset: " << hex << sh_tbl[i]->
           sh_offset << " size: " << sh_tbl[i]->sh_size);
      Elf64_Sym *sym_tbl = (Elf64_Sym *) malloc (sh_tbl[i]->sh_size);
      utils::READ_FROM_FILE (obj_file, (void
    				    *) sym_tbl, sh_tbl[i]->sh_offset,
    			 sh_tbl[i]->sh_size);


      /* Read linked string-table
       * Section containing the string table having names of
       * symbols of this section
       */
      uint32_t str_tbl_ndx = sh_tbl[i]->sh_link;
      LOG ("String section index: " << str_tbl_ndx << " offset: " <<
           sh_tbl[str_tbl_ndx]->sh_offset);
      str_tbl = (char *) malloc (sh_tbl[str_tbl_ndx]->sh_size);
      utils::READ_FROM_FILE (obj_file, (void
    				    *) str_tbl,
    			 sh_tbl[str_tbl_ndx]->sh_offset,
    			 sh_tbl[str_tbl_ndx]->sh_size);

      symbol_count = (sh_tbl[i]->sh_size / sizeof (Elf64_Sym));
      for(unsigned int j = 0; j < symbol_count; j++) {
        string name ((str_tbl + sym_tbl[j].st_name));
        newSymOfft_[name] = (off_t) sym_tbl[j].st_value + code_segment_offset;
        LOG(name<<" - "<<hex<<newSymOfft_[name]);
      }

      free (sym_tbl);
      free (str_tbl);

    }
  }

}

string
ElfClass::xtrctSection (string bname, string section_name) {
    /*------------------------------------------------------*
    Extracts a given section from the elf file.
    Funciton Not being used currently
    *-------------------------------------------------------*/

  ElfClass elf_obj (bname.c_str ());

  section sec = elf_obj.secHeader (section_name);
  uint64_t offset = sec.offset;

  uint64_t size = sec.size;

  string dump_name (section_name.replace (0, 1, ""));

  FILE *tgt = fopen (dump_name.c_str (), "w");

  FILE *src = fopen (bname.c_str (), "r");
  if (src == NULL) {
    cout << "function xtrctSection: can not open file: " << bname << endl;
    exit (0);
  }
  fseek (src, offset, SEEK_SET);
  for(unsigned int i = 0; i < size; i++) {
    char data = fgetc (src);
    fputc (data, tgt);
  }
  fclose (tgt);
  fclose (src);

  return dump_name;

}

uint64_t
ElfClass::segAlign() {
  for (auto & p : phTable_) {
    if(p->p_type == PT_LOAD)
      return p->p_align;
  }
  return 0;
}

void
ElfClass::printExeHdr(string fname) {
  vector <section> new_secs = newSections();
  ofstream ofile;
  ofile.open(fname);
  ofile<<".align "<<segAlign()<<endl;
  ofile<<".elf_header_start:\n";
  int i = 0; 
  for(; i < EI_NIDENT; i++) {
    ofile<<"."<<i<<": .byte "<<(uint32_t)(elfHeader_->e_ident[i])<<endl;
  }
  ofile<<"."<<i<<": .2byte "<<elfHeader_->e_type<<endl;
  i+=2;
  ofile<<"."<<i<<": .2byte "<<elfHeader_->e_machine<<endl;
  i+=2;
  ofile<<"."<<i<<": .4byte "<<elfHeader_->e_version<<endl;
  i+=4;
  ofile<<"."<<i<<": .8byte "<<elfHeader_->e_entry<<endl;
  i+=8;
  ofile<<"."<<i<<": .8byte .pheader_loc - .elf_header_start"<<endl;
  i+=8;
  ofile<<"."<<i<<": .8byte .section_header_loc - .elf_header_start"<<endl;
  i+=8;
  ofile<<"."<<i<<": .4byte "<<elfHeader_->e_flags<<endl;
  i+=4;
  ofile<<"."<<i<<": .2byte "<<elfHeader_->e_ehsize<<endl;
  i+=2;
  ofile<<"."<<i<<": .2byte "<<elfHeader_->e_phentsize<<endl;
  i+=2;
  ofile<<"."<<i<<": .2byte "<<elfHeader_->e_phnum + 3<<endl;
  i+=2;
  ofile<<"."<<i<<": .2byte "<<elfHeader_->e_shentsize<<endl;
  i+=2;
  ofile<<"."<<i<<": .2byte "<<new_secs.size() + 1<<endl;
  i+=2;
  ofile<<"."<<i<<": .2byte "<<elfHeader_->e_shstrndx<<endl;
  ofile.close();
}

void
ElfClass::printNewSectionHdrs(string fname) {
  ofstream ofile;
  ofile.open(fname);
  ofile<<".section_header_loc:\n";
  vector <section> new_secs = newSections();
  vector <section> secs_in_old_order;
  int idx = 0;
  for(auto & sh : shTable_) {
    string sec = secIdxToNm(idx);
    for(auto & new_sec : new_secs) {
      if(sec == new_sec.name) {
        new_sec.header_asm += ".4byte " + to_string(sh->sh_name) + "\n";
        new_sec.header_asm += ".4byte " + to_string(sh->sh_type) + "\n";
        new_sec.header_asm += ".8byte " + to_string(sh->sh_flags) + "\n";
        if(sh->sh_addr == 0)
          new_sec.header_asm += ".8byte 0\n";
        else
          new_sec.header_asm += ".8byte " + new_sec.start_sym + " - .elf_header_start\n";
        new_sec.header_asm += ".8byte " + new_sec.start_sym + " - .elf_header_start\n";
        new_sec.header_asm += ".8byte " + new_sec.end_sym + " - " + new_sec.start_sym + "\n";
        new_sec.header_asm += ".4byte " + to_string(sh->sh_link) + "\n";
        new_sec.header_asm += ".4byte " + to_string(sh->sh_info) + "\n";
        new_sec.header_asm += ".8byte " + to_string(sh->sh_addralign) + "\n";
        new_sec.header_asm += ".8byte " + to_string(sh->sh_entsize) + "\n";
        secs_in_old_order.push_back(new_sec);
      }
    }
    idx++;
  }
  uint32_t sh_name = shTable_[elfHeader_->e_shstrndx]->sh_size;
  for(auto & sec : new_secs) {
    if(sec.additional) {
      sec.header_asm += ".4byte " + to_string(sh_name) + "\n";
      sec.header_asm += ".4byte " + to_string(SHT_PROGBITS) + "\n";
      sec.header_asm += ".8byte " + to_string(SHF_ALLOC) + "\n";
      sec.header_asm += ".8byte " + sec.start_sym + " - .elf_header_start\n";
      sec.header_asm += ".8byte " + sec.start_sym + " - .elf_header_start\n";
      sec.header_asm += ".8byte " + sec.end_sym + " - " + sec.start_sym + "\n";
      sec.header_asm += ".4byte " + to_string(0) + "\n";
      sec.header_asm += ".4byte " + to_string(0) + "\n";
      sec.header_asm += ".8byte " + to_string(sec.align) + "\n";
      sec.header_asm += ".8byte " + to_string(0) + "\n";
      sh_name += (sec.name.size()) + 1;
      secs_in_old_order.push_back(sec);
    }
  }

  //Check if a NULL header is present and add it.

  for(auto & sh : shTable_) {
    if(sh->sh_type == SHT_NULL) {
      ofile<<".4byte "<<sh->sh_name<<endl;
      ofile<<".4byte "<<sh->sh_type<<endl;
      ofile<<".8byte "<<sh->sh_flags<<endl;
      ofile<<".8byte 0\n";
      ofile<<".8byte 0\n";
      ofile<<".8byte 0\n";
      ofile<<".4byte "<< sh->sh_link<<endl;
      ofile<<".4byte "<< sh->sh_info<<endl;
      ofile<<".8byte "<< sh->sh_addralign<<endl;
      ofile<<".8byte "<< sh->sh_entsize<<endl;
    }
  }

  for (auto & sec : secs_in_old_order) {
    ofile<<sec.header_asm;
  }

  ofile.close();
}

void
ElfClass::printPHdrs(string fname) {
  
  vector <section> new_secs = newSections();
  pheader cur_ph;
  pheader att_ph;
  for(auto & sec : new_secs) {
    if(sec.load == false)
      continue;
    if(SAME_ACCESS_PERM(cur_ph.p_flag, sec.sec_type)) {
      SEGEND(cur_ph,sec);
    }
    else {
      if(cur_ph.p_flag != pheader_flags::DONTCARE)
        newPheader(cur_ph);
      pheader new_ph;
      SECTOSEG(new_ph,sec);
      if(newPheaders().size() == 0)
        new_ph.start_sym = ".0"; //Set the start of first segment to beginning of file
      cur_ph = new_ph;
    }
    if(sec.is_att) {
      att_ph.start_sym = sec.start_sym;
      att_ph.file_end_sym = sec.end_sym;
      att_ph.mem_end_sym = sec.end_sym;
    }
  }
  newPheader(cur_ph);
  ofstream ofile;
  ofile.open(fname);
  ofile<<".pheader_loc:\n";
  uint64_t addrs = utils::GET_ADDRESS(binaryName(),elfHeader_->e_phoff);
  utils::bind(addrs, ".pheader_loc", SymBind::FORCEBIND);
  //ofile<<"."<<addrs<<":\n";
  for(auto & p : phTable_) {
    if(p->p_type != PT_LOAD) {

      pheader ph(p->p_offset,p->p_vaddr,p->p_filesz,p->p_memsz);
      newPheader(ph);
      string label = utils::getLabel(p->p_vaddr);
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Word))<<" "<<p->p_type<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Word))<<" "<<p->p_flags<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Off))<<" "<<label<<" - .elf_header_start"<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Addr))<<" "<<label<<" - .elf_header_start"<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Addr))<<" "<<label<<" - .elf_header_start"<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Xword))<<" "<<p->p_filesz<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Xword))<<" "<<p->p_memsz<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Xword))<<" "<<p->p_align<<endl;
    }
  }
  auto newPHdrs_ = newPheaders();
  for(auto & p : newPHdrs_) {
    if(p.p_flag != pheader_flags::DONTCARE) {
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Word))<<" "<<PT_LOAD<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Word))<<" "<<PFLAG(p.p_flag)<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Off))<<" "<<p.start_sym<<" - .elf_header_start"<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Addr))<<" "<<p.start_sym<<" - .elf_header_start"<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Addr))<<" "<<p.start_sym<<" - .elf_header_start"<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Xword))<<" "<<p.file_end_sym
        <<" - "<<p.start_sym<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Xword))<<" "<<p.mem_end_sym<<
       " - "<<p.start_sym<<endl;
      ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Xword))<<" "<<segAlign()<<endl;
    }
  }

  ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Word))<<" "<<PT_SBI_ATT<<endl;
  ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Word))<<" "<<PF_R<<endl;
  ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Off))<<" "<<att_ph.start_sym<<" - .elf_header_start"<<endl;
  ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Addr))<<" "<<att_ph.start_sym<<" - .elf_header_start"<<endl;
  ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Addr))<<" "<<att_ph.start_sym<<" - .elf_header_start"<<endl;
  ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Xword))<<" "<<att_ph.file_end_sym
    <<" - "<<att_ph.start_sym<<endl;
  ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Xword))<<" "<<att_ph.mem_end_sym<<
   " - "<<att_ph.start_sym<<endl;
  ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Xword))<<" "<<1<<endl;
  int sz = newPHdrs_.size() + 1;
  while(sz <= (elfHeader_->e_phnum + 3)) {
    ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Word))<<" "<<PT_NULL<<endl;
    ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Word))<<" "<<PF_R<<endl;
    ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Off))<<" "<<0<<endl;
    ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Addr))<<" "<<0<<endl;
    ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Addr))<<" "<<0<<endl;
    ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Xword))<<" "<<0<<endl;
    ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Xword))<<" "<<0<<endl;
    ofile<<TYPE_TO_ASM_DIRECTIVE(sizeof(Elf64_Xword))<<" "<<1<<endl;
    sz++;
  }

  ofile.close();
}

void
ElfClass::updAllPHdrsV2(string bname) {
  LOG("-------------Updating Program Headers------------");
  vector <pheader> all_load_ph = prgrmHeader (pheader_types::LOAD, pheader_flags::DONTCARE);
  sort_pheaders(all_load_ph);

  uint64_t load_start = all_load_ph[0].address;
  ElfClass elf_obj(bname);
  vector <Elf64_Phdr *> ph_tbl = elf_obj.phTable();
  uint64_t page = load_start;
  LOG("Module start: "<<hex<<load_start);
  for(auto & p : ph_tbl) {

    //Change the header of all loadable segments.
    if (p->p_type == PT_LOAD) {
      p->p_vaddr = page + (p->p_offset % p->p_align);
      p->p_paddr = p->p_vaddr;
      if((p->p_vaddr + p->p_memsz) % p->p_align != 0) {

        //If seg doesn't end at page boundary, then extent the seg size to the
        //beginning of next seg

        for(auto & p2 : ph_tbl) {
          if(p2->p_type == PT_LOAD && p2->p_offset >= (p->p_offset + p->p_memsz)) {
            uint64_t seg_size = p->p_memsz + (p2->p_offset - (p->p_offset + p->p_memsz));
            int page_cnt = (p->p_vaddr + seg_size) / p->p_align;
            if ((p->p_vaddr + seg_size) % p->p_align != 0)
              page_cnt++;
            page = page_cnt * p->p_align;
            break;
          }
        }
      }
      else {
        int page_cnt = (p->p_vaddr + p->p_memsz) / p->p_align;
        if ((p->p_vaddr + p->p_memsz) % p->p_align != 0)
          page_cnt++;
        page = page_cnt * p->p_align;
      }
    }
  }

  for(auto & p : ph_tbl) {
    //Change the memory and file offsets of all other non-loadable segments.
    //(example - EH segment, dynamic table segment, etc.)

    if (p->p_type != PT_LOAD && p->p_type != PT_GNU_STACK) {
      for (auto & p2 : ph_tbl) {
        if(p2->p_type == PT_LOAD && p2->p_offset <= p->p_offset 
           && (p2->p_offset + p2->p_memsz) > p->p_offset)
          p->p_vaddr = p2->p_vaddr + p->p_offset - p2->p_offset;
      }
      if(p->p_type == PT_SBI_ATT) {
        attOffset_ = p->p_offset;
        attSize_ = p->p_memsz;
      }
    }
  }

  uint64_t ph_off = elf_obj.elfHeader().e_phoff;

  for(auto & p : ph_tbl) {
    //Program header written at two places in the file.
    //1. At file offset = 0 or beginning of the ELF file. Loader checks at the
    //   beginning of the file while loading.
    //2. At memory offset = 0 or first file offset to be loaded onto memory.
    //   After the program is loaded, the program headers will be searched for
    //   at memory offset = 0
    
    utils::WRITE_TO_FILE (bname, p, ph_off, sizeof (Elf64_Phdr));
    ph_off += sizeof (Elf64_Phdr);
  }
}

void
ElfClass::updAllPHdrs (string bname) {
  /* Updates memory offsets of all program headers after re-assembly, to point
   * to new code and data locations.
   */

  LOG ("---------------updating program headers------------------");
  Elf64_Shdr *sh = shTable_[allSections_[".mycodesegment"].hdr_indx];
  uint64_t code_segment_offset = sh->sh_offset;
  vector <pheader> all_data_ph = prgrmHeader (pheader_types::LOAD, pheader_flags::RW);
  pheader data_ph = all_data_ph[0]; //Assuming that there is only one RW prgrm header
  Elf64_Half ph_count = elfHeader_->e_phnum;
  Elf64_Off ph_offset = elfHeader_->e_phoff;

  uint64_t load_align = 0;

  uint64_t page = 0;
  map < uint64_t, uint64_t > segment_map;

  int last_load_segment_index = 0;

  for(int i = 0; i < ph_count; i++) {

    //Change the header of all loadable segments.

    if (phTable_[i]->p_type == PT_LOAD) {
      load_align = phTable_[i]->p_align;
      uint64_t new_offset;
      //Just change the file offset to point to new location in the EXE
      //file.
      //Memory offsets of old code and data remain the same, so no need to change.
      new_offset = code_segment_offset + phTable_[i]->p_offset;
      if (data_ph.offset == phTable_[i]->p_offset)
        phTable_[i]->p_memsz += 8;
      phTable_[i]->p_offset = new_offset;
      segment_map[new_offset] = phTable_[i]->p_vaddr;

      page =
        (phTable_[i]->p_vaddr +
         phTable_[i]->p_memsz) / phTable_[i]->p_align;
      if ((phTable_[i]->p_vaddr +
           phTable_[i]->p_memsz) % phTable_[i]->p_align != 0)
        page++;
      last_load_segment_index = i;
    }
  }


  //Add a new program header for instrumented code.

  uint64_t new_codesegment_start = newSymOfft_[".new_codesegment_start"];
  uint64_t new_codesegment_end = newSymOfft_[".new_codesegment_end"];

  Elf64_Phdr *ph;
  ph = (Elf64_Phdr *) malloc (sizeof (Elf64_Phdr));
  ph->p_type = PT_LOAD;
  ph->p_flags = 5;
  ph->p_vaddr = (page * load_align);
  ph->p_paddr = ph->p_vaddr;
  ph->p_offset = new_codesegment_start;
  ph->p_align = load_align;
  ph->p_filesz = new_codesegment_end - new_codesegment_start;
  ph->p_memsz = new_codesegment_end - new_codesegment_start;

  phTable_.insert (phTable_.begin () + last_load_segment_index + 1, ph);

  segment_map[new_codesegment_start] = page * load_align;

  if (phTable_[0]->p_type == PT_PHDR) {
    phTable_[0]->p_offset = phTable_[0]->p_offset + code_segment_offset;
    phTable_[0]->p_filesz = phTable_[0]->p_filesz + sizeof (Elf64_Phdr);
    phTable_[0]->p_memsz = phTable_[0]->p_memsz + sizeof (Elf64_Phdr);
  }


  for(int i = 0; i < ph_count; i++) {
    //Change the memory and file offsets of all other non-loadable segments.
    //(example - EH segment, dynamic table segment, etc.)

    if (phTable_[i]->p_type != PT_LOAD && phTable_[i]->p_type != PT_PHDR &&
        phTable_[i]->p_type != PT_GNU_STACK) {
      uint64_t orig_offset = phTable_[i]->p_offset;
      phTable_[i]->p_offset =
        newSymOfft_["." + to_string (phTable_[i]->p_vaddr)];
      phTable_[i]->p_filesz =
        newSymOfft_["." +
    		       to_string (phTable_[i]->p_vaddr +
    				  phTable_[i]->p_filesz)] -
        phTable_[i]->p_offset;
      phTable_[i]->p_memsz =
        newSymOfft_["." +
    		       to_string (phTable_[i]->p_vaddr +
    				  phTable_[i]->p_memsz)] -
        phTable_[i]->p_offset;
      map < uint64_t, uint64_t >::iterator it;
      map < uint64_t, uint64_t >::iterator prev_it;
      it = segment_map.begin ();
      LOG ("orig offset: " << hex << orig_offset << " new offset: "
           << hex << phTable_[i]->p_offset);
      while (it != segment_map.end ()) {
          LOG ("checking segment: " << hex << it->first << " page:"
    	   << it->second);
          uint64_t segment_end = it->first;
          if (phTable_[i]->p_offset < segment_end) {
    	  break;
    	}
        prev_it = it;
        it++;
      }
      LOG ("selected segment: " << hex << prev_it->first << " page: "
           << prev_it->second);
      phTable_[i]->p_vaddr = prev_it->second + phTable_[i]->p_offset
        - prev_it->first;
      phTable_[i]->p_paddr = phTable_[i]->p_vaddr;
    }
  }


  //Print for debugging
  for(int i = 0; i < (ph_count + 1); i++) {
    LOG ("Type: " << hex << phTable_[i]->p_type << "offset: "
     << hex << phTable_[i]->p_offset << "vaddr: " << hex << phTable_[i]->
     p_vaddr);
  }

  //Write the new program headers onto the ELF file.
  //Update ELF header to point to new program header location.

  uint64_t new_pheader_location = code_segment_offset + ph_offset;
  uint64_t old_pheader_location = ph_offset;
  for(unsigned int i = 0; i < phTable_.size (); i++) {
    //Program header written at two places in the file.
    //1. At file offset = 0 or beginning of the ELF file. Loader checks at the
    //   beginning of the file while loading.
    //2. At memory offset = 0 or first file offset to be loaded onto memory.
    //   After the program is loaded, the program headers will be searched for
    //   at memory offset = 0
    
    utils::WRITE_TO_FILE (bname, phTable_[i], new_pheader_location,
  		    sizeof (Elf64_Phdr));
    utils::WRITE_TO_FILE (bname, phTable_[i], old_pheader_location,
  		    sizeof (Elf64_Phdr));
    new_pheader_location += sizeof (Elf64_Phdr);
    old_pheader_location += sizeof (Elf64_Phdr);
  }

  elfHeader_->e_phnum += 1;
  //uint64_t old_ph_off = elfHeader_->e_phoff;
  elfHeader_->e_phoff = code_segment_offset + ph_offset;

  utils::WRITE_TO_FILE (bname, elfHeader_, 0, sizeof (Elf64_Ehdr));

  utils::WRITE_TO_FILE (bname, elfHeader_, code_segment_offset,
			sizeof (Elf64_Ehdr));

  elfHeader_->e_phoff = ph_offset;
  LOG ("new code segment start: " << new_codesegment_start);
  utils::WRITE_TO_FILE (bname, elfHeader_, new_codesegment_start,
			sizeof (Elf64_Ehdr));
  elfHeader_->e_phoff = code_segment_offset + ph_offset;
}

void
ElfClass::updAllSecHdrsV2(string bname) {
  LOG("----------Updating section headers---------------");
  vector <section> new_secs = newSections();
  for(auto & sec : allSections_) {
    if(sec.second.sh->sh_addr != 0) {
      for(auto & new_sec : new_secs) {
        if(new_sec.name == sec.first) {
          shTable_[sec.second.hdr_indx]->sh_addr = newSymAddrs_[new_sec.start_sym];
        }
      }
    }
  }
  uint64_t new_sec_tab_offset = elfHeader_->e_shoff;
  for(auto & sh : shTable_) {
    LOG ("section offset - " << hex << sh->sh_offset 
        << " addrs: " << hex << sh->sh_addr << " size: " << sh->sh_size);
    utils::WRITE_TO_FILE (bname, sh, new_sec_tab_offset,sizeof (Elf64_Shdr));
    new_sec_tab_offset += sizeof (Elf64_Shdr);
  }
}

void
ElfClass::updAllSecHdrs (string bname) {
    /*---------------------------------------------------------------------*
    1. Changes section headers of all sections to point to the new datasegment.
    *---------------------------------------------------------------------*/
  //----add or update instrumentation stub section------------------//
  //
  LOG ("----------Updating section headers---------------");
  //Elf64_Shdr *sh = shTable_[allSections_[".mycodesegment"]];

  int section_count = elfHeader_->e_shnum;

  auto it = allSections_.begin ();
  //for(unsigned int i = 0;i<section_count;i++)
  while (it != allSections_.end ()) {
    LOG ("Changing headers for section: " << it->first);
    string sec_name = it->first;
    int i = it->second.hdr_indx;
    uint64_t new_offset = 0;
    uint64_t new_end = 0;
    uint64_t new_vma = 0;

    if (shTable_[i]->sh_addr != 0) {
      //Check for <sec_name>_dup symbol. The current assembly generator puts this
      //symbol.
      //If not found check for the label for corresponding section start
      //address.

      if (if_exists (sec_name + "_dup", newSymOfft_)) {
        new_offset = newSymOfft_[sec_name + "_dup"];
        new_vma = newSymAddrs_[sec_name + "_dup"];
      }
      else {
        new_offset =
          newSymOfft_["." + to_string (shTable_[i]->sh_addr)];
        new_vma =
          newSymAddrs_["." + to_string (shTable_[i]->sh_addr)];
      }

      if (newSymOfft_.find (sec_name + "_dup_end") != newSymOfft_.end ()) {
        new_end = newSymOfft_[sec_name + "_dup_end"];
        shTable_[i]->sh_size = new_end - new_offset;
      }

      shTable_[i]->sh_offset = new_offset;
      shTable_[i]->sh_addr = new_vma;
    }
    it++;

  }

  uint64_t new_sec_tab_offset = elfHeader_->e_shoff;
  for(int i = 0; i < section_count; i++) {
    LOG ("section offset - " << hex << shTable_[i]->
     sh_offset << " addrs: " << hex << shTable_[i]->
     sh_addr << " size: " << shTable_[i]->sh_size);
    utils::WRITE_TO_FILE (bname, shTable_[i], new_sec_tab_offset,
  		    sizeof (Elf64_Shdr));
    new_sec_tab_offset += sizeof (Elf64_Shdr);
  }

}

void
ElfClass::insertDataSeg (string bname) {

  //Writes the writable data segment onto the space reserved by assembly
  //generator.

  string orig_bin = origBname ();
  ElfClass elf_obj (orig_bin.c_str ());
  vector<pheader> ph_lst = elf_obj.prgrmHeader (pheader_types::LOAD, pheader_flags::RW);
  for(auto & ph : ph_lst) {
    uint8_t *segment_data = (uint8_t *) malloc (ph.mem_sz);
    utils::READ_FROM_FILE (orig_bin, (void *) segment_data, ph.offset,
      		 ph.mem_sz - 8);

    uint64_t offset = newSymOfft_[".datasegment_start"];
    LOG ("writing data segment at: " << hex << offset);
    utils::WRITE_TO_FILE (bname, (void *) segment_data, offset, ph.mem_sz - 8);
  }

}

uint64_t
ElfClass::generateHashTbl(string &bin_asm, section &att_sec) {
  utils::append_files(bin_asm,"tmp.s");
  string obj_file = "tmp.o";
  string cmd = "g++ -c tmp.s";// + bin_asm;
  if(system (cmd.c_str ()) != 0)
    LOG("System command failed: "<<cmd);
  ElfClass elf_obj (obj_file.c_str ());
  uint64_t start_addr = elf_obj.symbolVal(att_sec.start_sym);
  uint64_t end_addr = elf_obj.symbolVal(att_sec.end_sym);
  attSize_ = end_addr - start_addr;
  DEF_LOG("Att table addr: "<<hex<<start_addr<<" size: "<<attSize_);
  string dump = xtrctSection(obj_file,".text");
  //auto offset = utils::GET_OFFSET(obj_file,start_addr);
  //DEF_LOG("Att table offset: "<<hex<<offset);
  attTbl_ = (char *) malloc (attSize_);
  utils::READ_FROM_FILE (dump, (void *)attTbl_, start_addr, attSize_);
  createHash(attTbl_,attSize_);
  hashEntryCnt_ = ((AttRec *)attTbl_)->hashInd_;
  return hashEntryCnt_;
}

string
ElfClass::hashTblAsm() {
  string hash_asm = "";
  if(attTbl_ != NULL) {
    AttRec *tbl_start = (AttRec *)(attTbl_ + 3 * sizeof(void *));
    uint64_t entry_cnt = (attSize_/(3 * sizeof(void *))) - 2;
    uint64_t prev_ind = 0;
    map<uint64_t, uint64_t> hash_map;
    for(uint64_t i = 0; i < entry_cnt; i++) {
      hash_map[tbl_start[i].hashInd_] = tbl_start[i].new_;
    }
    uint64_t total_skip = 0;
    for(auto & e : hash_map) {
      DEF_LOG("hash ind: "<<hex<<e.first<<" ptr: "<<hex<<e.second);
      uint64_t skip_bytes = (e.first - prev_ind) * sizeof(void *);
      total_skip += skip_bytes;
      DEF_LOG("Total skip: "<<hex<<total_skip<<" entry skip: "<<hex<<skip_bytes);
      hash_asm += ".skip " + to_string(skip_bytes) + "\n";
      hash_asm += ".8byte " + to_string(e.second) + "\n";
      prev_ind = e.first + 1;
    }
  }
  return hash_asm;
}

void
ElfClass::insertHashTbl (string bname) {
  utils::WRITE_TO_FILE (bname, (void *)attTbl_, attOffset_,attSize_);
}

void
ElfClass::updateWithoutObjCopy(string bname,string obj_file) {
  string new_bname = binaryName() + "_2";
  
  string cmd = "cp " + bname + " " + new_bname; 

  if(system (cmd.c_str ()) != 0) {
    LOG("System command failed: "<<cmd);
    exit(0);
  }
  
  vector < section > data_segment_sections = sections (section_types::RW);
  oldDataSeg_ = data_segment_sections[0].vma;
  updAllPHdrsV2(new_bname);
  shTable_.clear ();
  phTable_.clear ();
  parse (new_bname.c_str ());

  populateNewSymOffts (obj_file);

  populateNewSymAddrs ();
  updAllSecHdrsV2(new_bname);
  insertDataSeg (new_bname);
  //updSymTbl (new_bname);
  updRelaSections (new_bname);
  //updTramps (new_bname);
  updDynSection (new_bname);
  changeEntryPnt (new_bname);
  insertHashTbl (new_bname);
  instBname(new_bname);
}

void
ElfClass::printNonLoadSecs(string asm_file) {
  vector <section> non_load_secs = sections(section_types::NONLOAD);
  int ctr = 0;
  ofstream ofile;
  ofile.open(asm_file,ofstream::out | ofstream::app);
  string shstr = secIdxToNm(elfHeader_->e_shstrndx);
  for(auto & sec : non_load_secs) {
    section new_sec = sec;
    new_sec.start_sym = ".nonload" + to_string(ctr);
    new_sec.load = false;
    new_sec.end_sym = ".nonload" + to_string(ctr) + "_end";
    ofile<<".nonload"<<ctr<<":\n";
    uint8_t *bytes = (uint8_t *)malloc(sec.size);
    utils::READ_FROM_FILE(binaryName(),bytes,sec.offset,sec.size);
    for(size_t i = 0; i < sec.size; i++)
      ofile<<".byte "<<(uint32_t)(bytes[i])<<endl;
    if(sec.name == shstr) {
      vector <string> additional_secs = additionSecs();
      for(auto & str : additional_secs)
        ofile<<".string \""<<str<<"\""<<endl;
    }
    ofile<<".nonload"<<ctr<<"_end:\n";
    free(bytes);
    ctr++;
    newSection(new_sec);
  }
  ofile.close();
}

void
ElfClass::rewrite (string asm_file) {

  //printPHdrs("pheader.s");
  //printExeHdr("exe_hdr.s");

  //utils::append_files("exe_hdr.s","final_asm.s");
  //utils::append_files("pheader.s","final_asm.s");
  utils::append_files(asm_file,"final_asm.s");

  printNewSectionHdrs("section_hdrs.s");
  utils::append_files("section_hdrs.s","final_asm.s");

  string obj_file = "final_asm.o";
  //obj_file = obj_file.replace (obj_file.rfind ("."), 2, ".o");	// + ".o";
  string cmd = "g++ -c final_asm.s";// + asm_file;

  if(system (cmd.c_str ()) != 0)
    LOG("System command failed: "<<cmd);


  string dump_name = xtrctSection (obj_file, ".text");
  
  if(NOOBJCOPY) {
    updateWithoutObjCopy(dump_name,obj_file);
    return;
  }

  string bname = binaryName ();
  string new_bname = bname + "_2";

  cmd = "objcopy --add-section .mycodesegment=" + dump_name +
    " --set-section-flags .mycodesegment=alloc,noload " + bname
    + " " + new_bname;

  if(system (cmd.c_str ()) == 0)
    LOG("System command failed: "<<cmd);

  vector < section > data_segment_sections = sections (section_types::RW);
  oldDataSeg_ = data_segment_sections[0].vma;

  shTable_.clear ();
  phTable_.clear ();
  parse (new_bname.c_str ());

  populateNewSymOffts (obj_file);
  updAllPHdrs (new_bname);

  populateNewSymAddrs ();
  updAllSecHdrs (new_bname);
  insertDataSeg (new_bname);
  updSymTbl (new_bname);
  updRelaSections (new_bname);
  updTramps (new_bname);
  updDynSection (new_bname);
  changeEntryPnt (new_bname);
  instBname(new_bname);
}

void
ElfClass::changeEntryPnt (string bname) {
  uint64_t code_segment_offset = codeSegOffset();

  elfHeader_->e_entry = newSymVal (elfHeader_->e_entry);
    //encode (newSymVal (elfHeader_->e_entry), elfHeader_->e_entry);

  LOG ("new entry point: " << elfHeader_->e_entry);

  FILE *f = fopen (bname.c_str (), "rb+");
  if (f == NULL) {
    LOG ("file couldn't be opened-" << bname);
    exit (0);
  }


  uint64_t new_codesegment_start = newSymOfft_[".new_codesegment_start"];

  utils::WRITE_TO_FILE (bname, elfHeader_, 0, sizeof (Elf64_Ehdr));
  utils::WRITE_TO_FILE (bname, elfHeader_, code_segment_offset,
			sizeof (Elf64_Ehdr));

  //elfHeader_->e_phoff -= code_segment_offset;

  //utils::WRITE_TO_FILE (bname, elfHeader_, new_codesegment_start,
	//		sizeof (Elf64_Ehdr));

}


void
ElfClass::updDynSection (string bname) {
  LOG ("--------------updating dynamic section---------------");
  section sec = secHeader (".dynamic");
  uint64_t dyn_offset = sec.offset;

  uint64_t size = sec.size;

  int dyn_count = size / sizeof (Elf64_Dyn);

  Elf64_Dyn *dyn = (Elf64_Dyn *) malloc (size);
  utils::READ_FROM_FILE (bname, dyn, dyn_offset, size);


  /*
     Each of the tag types mentioned below have an offset or pointer entry that need to be updated.
     Other than these tag types, tags that are even numbered also hold pointer values and need to be updated.
   */

  for(int i = 0; i < dyn_count; i++) {
    string label = "." + to_string (dyn[i].d_un.d_ptr);
    if (dyn[i].d_tag == DT_PLTGOT || dyn[i].d_tag == DT_HASH || dyn[i].d_tag
    == DT_STRTAB || dyn[i].d_tag == DT_SYMTAB || dyn[i].d_tag ==
    DT_RELA || dyn[i].d_tag == DT_INIT || dyn[i].d_tag == DT_FINI ||
    dyn[i].d_tag == DT_REL || dyn[i].d_tag == DT_DEBUG ||
    dyn[i].d_tag == DT_JMPREL || dyn[i].d_tag == DT_INIT_ARRAY ||
    dyn[i].d_tag == DT_FINI_ARRAY || dyn[i].d_tag == DT_AUXILIARY ||
    dyn[i].d_tag == DT_FILTER || dyn[i].d_tag == DT_CONFIG ||
    dyn[i].d_tag == DT_DEPAUDIT || dyn[i].d_tag == DT_AUDIT ||
    dyn[i].d_tag == DT_PLTPAD || dyn[i].d_tag == DT_MOVETAB ||
    dyn[i].d_tag == DT_SYMINFO || dyn[i].d_tag == DT_VERDEF ||
    dyn[i].d_tag == DT_VERNEED || dyn[i].d_tag ==
    0x000000006ffffff0 || dyn[i].d_tag == 0x000000006ffffef5) {
      dyn[i].d_un.d_ptr = newSymVal(dyn[i].d_un.d_ptr);
        //encode(newSymVal(dyn[i].d_un.d_ptr),dyn[i].d_un.d_ptr);
    }
    else if (dyn[i].d_tag > DT_ENCODING && (dyn[i].d_tag < DT_HIOS ||
  				      dyn[i].d_tag > DT_LOPROC)) {
      if (dyn[i].d_tag % 2 == 0) {
        dyn[i].d_un.d_ptr = newSymVal(dyn[i].d_un.d_ptr);
        //encode(newSymVal(dyn[i].d_un.d_ptr),dyn[i].d_un.d_ptr);
      }
    }
    /*
       else if(dyn[i].d_tag == DT_SONAME) {
       if(bname.find("ld-2.27.so") != string::npos) {
       LOG("SO NAME offset: "<<hex<<dyn[i].d_un.d_val);
       section dyn_str_sec = secHeader(".dynstr");
       char soname[] = "ld-chngd-x86-64.so.2";
       utils::WRITE_TO_FILE(bname,soname,dyn_str_sec.offset + dyn[i].d_un.d_val,20);
       }
       }
       else if(dyn[i].d_tag == DT_NEEDED) {
       LOG("Shared lib name offset: "<<hex<<dyn[i].d_un.d_val);
       section dyn_str_sec = secHeader(".dynstr");
       char name[20];
       utils::READ_FROM_FILE(bname,name,dyn_str_sec.offset + dyn[i].d_un.d_val,20);
       LOG("lib name: "<<name);
       if(strncmp(name,"ld-linux-x86-64.so.2",20) == 0) {
       char newname[] = "ld-chngd-x86-64.so.2";
       utils::WRITE_TO_FILE(bname,newname,dyn_str_sec.offset + dyn[i].d_un.d_val,20);
       }
       }
     */
  }
  utils::WRITE_TO_FILE (bname, dyn, dyn_offset, size);

  free (dyn);

}

void
ElfClass::updTramps (string bname) {
  //Updates GOT tables.

  section sec = secHeader (".got");
  if (sec.offset != 0) {
    LOG ("handling .got\n");

    uint64_t *trampoline = (uint64_t *) malloc (sec.size);
    utils::READ_FROM_FILE (bname, (void *) trampoline, sec.offset, sec.size);

    for(uint64_t i = 0, ctr = 0; i < sec.size; i += 8, ctr++) {
      uint64_t val = trampoline[ctr];
      if (val == 0)
        continue;

      trampoline[ctr] = newSymVal (val);//encode (newSymVal (val), val);	// * 0x0010000000000001;
    }


    utils::WRITE_TO_FILE (bname, (void *) trampoline, sec.offset, sec.size);
    free (trampoline);
  }
  sec = secHeader (".got.plt");
  if (sec.offset != 0) {
    LOG ("handling .got.plt\n");
    uint64_t *trampoline = (uint64_t *) malloc (sec.size);
    utils::READ_FROM_FILE (bname, (void *) trampoline, sec.offset, sec.size);

    for(uint64_t i = 0, ctr = 0; i < sec.size; i += 8, ctr++) {
      uint64_t val = trampoline[ctr];
      if (val == 0)
        continue;

      trampoline[ctr] = newSymVal (val);//encode (newSymVal (val), val);	// * 0x0010000000000001;
    }


    utils::WRITE_TO_FILE (bname, (void *) trampoline, sec.offset, sec.size);
    free (trampoline);

  }
}


void
ElfClass::updRelaSections (string bname) {

  //Updates relocation tables.

  vector < section > rela_sections = sections (section_types::RELA);

  for(size_t i = 0; i < rela_sections.size (); i++) {
    uint64_t offset = rela_sections[i].offset;
    uint64_t size = rela_sections[i].size;
    Elf64_Rela *rl = (Elf64_Rela *) malloc (size);

    LOG ("changing rela section: " << rela_sections[i].
     name << " at offset :" << offset);

    utils::READ_FROM_FILE (bname, rl, offset, size);
    int entry_count = size / sizeof (Elf64_Rela);
    for(int j = 0; j < entry_count; j++) {
      rl[j].r_offset = newSymVal(rl[j].r_offset);
      LOG ("offset: " << hex << rl[j].r_offset);

      /*
         for entries of type R_X86_64_IRELATIVE and R_X86_64_RELATIVE,
         addend needs to be updated to point to location in new codesegment
       */

      if (rl[j].r_info == R_X86_64_IRELATIVE || rl[j].r_info == R_X86_64_RELATIVE) {
        uint64_t orig_ptr = rl[j].r_addend;
        rl[j].r_addend = encode(newSymVal(rl[j].r_addend),orig_ptr);
        if(encoded(orig_ptr) && enctype() == EncType::ENC_GTT_ATT) {
          if(rl[j].r_info == R_X86_64_IRELATIVE)
            rl[j].r_info = R_X86_64_ISBIENC0;
          else
            rl[j].r_info = R_X86_64_SBIENC0;
        }
        LOG ("addend: " << hex << rl[j].r_addend);
      }
    }

    utils::WRITE_TO_FILE (bname, rl, offset, size);
    free (rl);
  }

}

uint64_t
ElfClass::newSymVal (uint64_t old_offset) {
  if (old_offset == 0)
    return 0;
  if (old_offset >= oldDataSeg_)
    return newSymAddrs_[".datasegment_start"] + old_offset -
      oldDataSeg_;
  else if(utils::sym_bindings.find(old_offset) != utils::sym_bindings.end())
    return newSymAddrs_[utils::sym_bindings[old_offset]];
  else
    return newSymAddrs_["." + to_string (old_offset)];	// - new_codesegment_offset;
}

void
ElfClass::updSymTbl (string bname) {
    /*----------------------------------------------------------------*
    1. Updates offsets in symbols tables (.symtab and .dynsym)
    *----------------------------------------------------------------*/

  vector < section > sym_sections = sections (section_types::SYM);
  for(size_t i = 0; i < sym_sections.size (); i++) {

    Elf64_Sym *sym_tbl = (Elf64_Sym *) malloc (sym_sections[i].size);
    utils::READ_FROM_FILE (bname, (void
  			     *) sym_tbl, sym_sections[i].offset,
  		     sym_sections[i].size);
    uint32_t sym_count = (sym_sections[i].size) / sizeof (Elf64_Sym);

    LOG ("Updating symbols: " << sym_count);

    for (uint32_t j = 0; j < sym_count; j++) {
      if (sym_tbl[j].st_value == 0 || (sym_tbl[j].st_info & 0xf) == STT_TLS)
        continue;

      sym_tbl[j].st_value	 = newSymVal(sym_tbl[j].st_value); 
        //= encode (newSymVal (sym_tbl[j].st_value),
    	//      sym_tbl[j].st_value);

    }
    utils::WRITE_TO_FILE (bname, sym_tbl, sym_sections[i].offset,
  		    sym_sections[i].size);
    free (sym_tbl);
  }

}


void
ElfClass::populateNewSymAddrs () {
  //calculates and populates the new address of all symbols after re-assembly.

  LOG ("-----------populating new symbol address------------");
  map < string, off_t >::iterator new_sym_it;
  new_sym_it = newSymOfft_.begin ();
  while (new_sym_it != newSymOfft_.end ()) {
    int ph_count = phTable_.size ();
    uint64_t offset = new_sym_it->second;
    for(int i = 0; i < ph_count; i++) {
      if (phTable_[i]->p_type == PT_LOAD && offset >= phTable_[i]->p_offset
          && offset <= (phTable_[i]->p_offset + phTable_[i]->p_memsz)) {
        uint64_t addrs =
          offset - phTable_[i]->p_offset + phTable_[i]->p_vaddr;
        newSymAddrs_[new_sym_it->first] = addrs;	// - all_ph[i].p_offset);
        LOG(new_sym_it->first<<" - "<<hex<<addrs);
      }
    }

    new_sym_it++;

  }

}

void
ElfClass::readJmpSlots () {

  /* Finds out the memory location designated to store the address of standard
   * library functions used by the ELF executable.
   */
  LOG("----------Reading jump slots----------------------"); 
  string bname = binaryName ();
  Elf64_Shdr *dynsym_sh = NULL;

  for(size_t i = 0; i < shTable_.size (); i++) {
    if (shTable_[i]->sh_type == SHT_DYNSYM) {
      dynsym_sh = shTable_[i];
      break;
    }
  }
  if(dynsym_sh == NULL) {
    LOG("Error: No dynamic symbol section in the executable");
    //exit(1);
    return;
  }
  uint64_t string_tbl_idx = dynsym_sh->sh_link;
  uint64_t string_tbl_offset = shTable_[string_tbl_idx]->sh_offset;
  uint64_t string_tbl_size = shTable_[string_tbl_idx]->sh_size;

  char *all_strings = (char *) malloc (string_tbl_size);

  Elf64_Sym *sym_tbl = (Elf64_Sym *) malloc (dynsym_sh->sh_size);

  utils::READ_FROM_FILE (bname, sym_tbl, dynsym_sh->sh_offset,
			 dynsym_sh->sh_size);

  utils::READ_FROM_FILE (bname, all_strings, string_tbl_offset,
			 string_tbl_size);

  vector <section> rela_sections = sections (section_types::RELA);


  for(size_t i = 0; i < rela_sections.size (); i++) {
    uint64_t offset = rela_sections[i].offset;
    uint64_t size = rela_sections[i].size;
    Elf64_Rela *rl = (Elf64_Rela *) malloc (size);


    utils::READ_FROM_FILE (bname, rl, offset, size);
    int entry_count = size / sizeof (Elf64_Rela);
    for(int j = 0; j < entry_count; j++) {

      uint32_t type = (uint32_t) rl[j].r_info;

      if (type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT || type == R_X86_64_IRELATIVE) {
        string symname;
        if(type == R_X86_64_IRELATIVE) {
          symname = to_string(rl[j].r_addend);
        }
        else {
          uint32_t indx = (uint32_t) (rl[j].r_info >> 32);
          uint64_t strng_tbl_indx = sym_tbl[indx].st_name;

          for(int i = strng_tbl_indx; all_strings[i] != '\0'; i++)
            symname.push_back (all_strings[i]);
        }
        //LOG("jump slot: "<<hex<<rl[j].r_offset<<" symbol name: "<<symname);
        //allJmpSlots_[rl[j].r_offset] = symname;

        allJmpSlots_[symname] = rl[j].r_offset;
      }

    }

    free (rl);

  }
}


/*
vector<uint64_t>
ElfClass::pcRelRelocs

vector<uint64_t>
ElfClass::extraRelocs() {

  vector<uint64_t> ptrs;

  string bname = binaryName ();
  Elf64_Shdr *sym_sh = NULL;

  for(size_t i = 0; i < shTable_.size (); i++) {
    if (shTable_[i]->sh_type == SHT_SYMTAB) {
      sym_sh = shTable_[i];
      break;
    }
  }
  if(sym_sh == NULL) {
    LOG("Error: No symbol section in the executable");
    exit(1);
  }
  uint64_t string_tbl_idx = sym_sh->sh_link;
  uint64_t string_tbl_offset = shTable_[string_tbl_idx]->sh_offset;
  uint64_t string_tbl_size = shTable_[string_tbl_idx]->sh_size;

  char *all_strings = (char *) malloc (string_tbl_size);

  Elf64_Sym *sym_tbl = (Elf64_Sym *) malloc (sym_sh->sh_size);

  utils::READ_FROM_FILE (bname, sym_tbl, sym_sh->sh_offset,
			 sym_sh->sh_size);

  utils::READ_FROM_FILE (bname, all_strings, string_tbl_offset,
			 string_tbl_size);

  vector < section > rela_sections = sections (section_types::RELA);


  for(size_t i = 0; i < rela_sections.size (); i++) {
    uint64_t offset = rela_sections[i].offset;
    uint64_t size = rela_sections[i].size;
    Elf64_Rela *rl = (Elf64_Rela *) malloc (size);


    utils::READ_FROM_FILE (bname, rl, offset, size);
    int entry_count = size / sizeof (Elf64_Rela);
    for(int j = 0; j < entry_count; j++) {

      uint32_t type = (uint32_t) rl[j].r_info;

      if (type == R_X86_64_PLT32 || type == R_X86_64_PC32) {
        uint32_t indx = (uint32_t) (rl[j].r_info >> 32);
        uint64_t strng_tbl_indx = sym_tbl[indx].st_name;

        string symname;
        for(int i = strng_tbl_indx; all_strings[i] != '\0'; i++)
          symname.push_back (all_strings[i]);
        LOG("Rel type: "<<dec<<type<<" sym: "<<symname<<":"<<hex<<allSyms_[symname]
          <<" offt: "<<hex<<rl[j].r_offset
          <<" addend: "<<hex<<rl[j].r_addend);

      }
    }

    free (rl);

  }
}
*/
set < uint64_t > ElfClass::exitPlts () {
  set < uint64_t > exit_plts;
  for(size_t i = 0; i < exitSyms.size (); i++) {
    if (allJmpSlots_.find (exitSyms[i]) != allJmpSlots_.end ()) {
      LOG("Exit plt: "<<hex<<allJmpSlots_[exitSyms[i]]);
      exit_plts.insert (allJmpSlots_[exitSyms[i]]);
    }
  }
  return exit_plts;
}

set <uint64_t> ElfClass::mayExitPlts() {

  set < uint64_t > exit_plts;
  for(size_t i = 0; i < mayExitSyms_.size (); i++) {
    if (allJmpSlots_.find (mayExitSyms_[i]) != allJmpSlots_.end ()) {
      LOG("Exit plt: "<<hex<<allJmpSlots_[mayExitSyms_[i]]);
      exit_plts.insert (allJmpSlots_[mayExitSyms_[i]]);
    }
  }
  return exit_plts;
}

uint64_t
ElfClass::jmpSlot (string name) {
  if (allJmpSlots_.find (name) != allJmpSlots_.end ())
    return allJmpSlots_[name];
  else
    return 0;
}

set<uint64_t>
ElfClass::allJmpSlots () {
  set <uint64_t> all_slots;
  auto it = allJmpSlots_.begin();
  while (it != allJmpSlots_.end()) {
    all_slots.insert (it->second);
    it++;
  }
  return all_slots;
}


uint64_t 
ElfClass::fileOfft(uint64_t ptr) {
  uint64_t offt = 0;
  for(auto p : phTable_) {
    if (p->p_type == PT_LOAD && p->p_vaddr <= ptr
        && (p->p_vaddr + p->p_memsz) > ptr) {
      offt = p->p_offset + (ptr - p->p_vaddr);
      return offt;
    }
  }
  return offt;
}
uint64_t 
ElfClass::memAddrs(uint64_t offt) {
  uint64_t addrs = 0;
  for(auto p : phTable_) {
    if (p->p_type == PT_LOAD && p->p_offset <= offt
        && (p->p_offset + p->p_memsz) > offt) {
      addrs = p->p_vaddr + (offt - p->p_offset);

      return addrs;
    }
  }
  return addrs;
}

exe_type 
ElfClass::type() {
  if(elfHeader_->e_type == ET_DYN)
    return exe_type::PIE;
  else
    return exe_type::NOPIE;
}
