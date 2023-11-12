#ifndef _ENCODE_H
#define _ENCODE_H

#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iterator>
#include <vector>
#include <regex>
#include <map>
#include <math.h>
#include <algorithm>
#include "config.h"

using namespace std;

enum class EncType {
  ENC_GTT_ATT,
  ENC_MULT_INV,
  ENC_IND_ATF
};

struct __attribute__((packed)) AttRec {
  uint64_t old_;
  uint64_t new_;
  uint64_t hashInd_;
  char tramp_[16];
};

struct AttEntry {
  uint64_t val_;
  string lookupEntrySym_;
  string tgtEntrySym_;
  string oldPtr_;
  string newPtr_;
  string newPtrSym_;
  string tramp_;
  int oldOrNew_;
  int hashInd_ = -1;
};

class Encode {
  vector <AttEntry> attTable_;
  int hashTblBit_;
  int hashTblSize_;
  uint64_t randKey_;
  int ctr = 0;
  bool done = false;

  uint64_t getHash(uint64_t ptr) {
    ptr = ptr * randKey_;
    ptr = ptr >> (64 - hashTblBit_);
    ptr = ptr & (hashTblSize_ - 1);
    return ptr;
  }

  bool genAllHash(AttRec *att_tbl, uint64_t entry_cnt) {
    unordered_map<uint64_t,uint64_t> hash_map;

    for(uint64_t i = 0; i < entry_cnt; i++) {
      uint64_t ptr = att_tbl[i].old_;
      if(ptr == 0)
        continue;
      ptr = getHash(ptr);
      //cout<<"hash: "<<hex<<att_tbl[i].old_<<"->"<<hex<<ptr<<endl;
      if(hash_map.find(ptr) == hash_map.end() ||
         hash_map[ptr] == att_tbl[i].old_) {
        hash_map[ptr] = att_tbl[i].old_;
        att_tbl[i].hashInd_ = ptr;
      }
      else {
        //cout<<"collision: "<<hex<<att_tbl[i].old_<<"->"<<hex<<hash_map[ptr]<<endl;
        for(auto j = 1; j < hashTblSize_; j++) {
          auto new_ind = (ptr + (j * j)) % hashTblSize_; 
          if(hash_map.find(new_ind) == hash_map.end() ||
             hash_map[new_ind] == att_tbl[i].old_) {
            hash_map[new_ind] = att_tbl[i].old_;
            att_tbl[i].hashInd_ = new_ind;
            break;
          }
        }
      }
    }
    return true;
  }

public:
  void addAttEntry(uint64_t addrs, string lookup, string tgt, string new_sym, int tt) {
    AttEntry a;
    a.val_ = addrs;
    a.oldPtr_ = lookup;
    a.newPtr_ = tgt;
    a.oldOrNew_ = tt;
    a.newPtrSym_ = new_sym;// "_tramp_" + to_string(tt);
    a.tramp_ = new_sym + "_tramp_" + to_string(tt);
    attTable_.push_back(a);
  };


  string attTableAsm() {
    //createHash();
    string tbl = ".hash_key: .8byte " + to_string(randKey_) + "\n";
    tbl += ".hash_tbl_bit_sz: .8byte " + to_string(hashTblBit_) + "\n";
    tbl += ".hash_tbl_sz: .8byte " + to_string(hashTblSize_) + "\n";
    tbl += ".hash_tbl: .8byte .hash_tbl_start - .elf_header_start\n";
    tbl += ".load_start:\n.8byte 0\n.8byte 0\n.8byte 0\n";
    tbl += ".byte 0x90\n"; 
    tbl += ".byte 0x90\n"; 
    tbl += ".byte 0x90\n"; 
    tbl += ".byte 0x90\n"; 
    tbl += ".byte 0x90\n"; 
    tbl += ".byte 0x90\n"; 
    tbl += ".byte 0x90\n";
    tbl += ".byte 0x90\n"; 
    tbl += ".byte 0x90\n";
    tbl += ".byte 0x90\n.4byte 0x90909090\n";
    tbl += ".byte 0x90\n.byte 0x90\n";
    int ctr = 0;
    for (auto & e : attTable_) {
      e.lookupEntrySym_ = ".attentry_lookup_" + to_string(e.val_);
      e.tgtEntrySym_ = ".attentry_tgt_" + to_string(e.val_);
      string enc_ptr_sym = "." + to_string(e.val_) + "_enc_ptr";
      string tramp_sym = "." + to_string(e.val_) + "_tramp_ptr";
      if(e.oldOrNew_ == 1) {
        e.lookupEntrySym_ = ".attentry_lookup_" + e.newPtrSym_;
        e.tgtEntrySym_ = ".attentry_tgt_" + e.newPtrSym_;
        enc_ptr_sym = e.newPtrSym_ + "_enc_ptr";
        tramp_sym = e.newPtrSym_ + "_tramp_ptr";

        //e.lookupEntrySym_ += "_new";
        //e.tgtEntrySym_ += "_new";
        //enc_ptr_sym += "_new";
        //tramp_sym += "_new";
      }
      tbl += e.lookupEntrySym_ + ":\n"
          + e.oldPtr_ + "\n" + e.tgtEntrySym_ + ":\n"
          + e.newPtr_ + "\n"
          + enc_ptr_sym + ":\n" 
          + ".8byte " + to_string(e.oldOrNew_) + "\n"
          + tramp_sym + ":\n"
          + ".byte 0x64\n" 
          + ".byte 0x48\n" 
          + ".byte 0x8b\n" 
          + ".byte 0x04\n" 
          + ".byte 0x25\n" 
          + ".byte 0x88\n" 
          + ".byte 0x00\n"
          + ".byte 0x00\n" 
          + ".byte 0x00\n"
          + ".byte 0xe9\n" + ".4byte " + e.newPtrSym_ + " - " + tramp_sym + " - 14\n"
          + ".byte 0x90\n" + ".byte 0x90\n";
          //+ ".8byte " + e.tramp_ + " - .elf_header_start\n"
      ctr++;
    }
    tbl += ".loader_map_start: .8byte 0\n.gtt_node: .8byte 0\n.loader_map_end: .8byte 0\n";
    tbl += ".att_arr: .8byte 0\n.gtt: .8byte 0\n.syscall_checker: .8byte 0\n";
    tbl += ".vdso_start: .8byte 0\n.vdso_end: .8byte 0\n";
    return tbl;
  };

  string trampAsm() {
    string tramp_asm = "";
    for (auto & e : attTable_) {
      if(e.newPtrSym_.length() > 0) {
        tramp_asm += e.tramp_ + ":\n"
                   + "mov %fs:0x88,%rax\n" 
                   //+ "mov 24(%rsp),%rax\n"
                   + "add $40,%rsp\n"
                   + "jmp " + e.newPtrSym_ + "\n";
      }
    }
    return tramp_asm;
  }

  int attIndex(uint64_t val) {
    int ctr = 1;
    for(auto & e : attTable_) {
      if(e.val_ == val)
        return ctr;
      ctr++;
    }
    return -1;
  };
  string atfFunction() {
    string atf = "";
    string str;
    ifstream ifile;
    ifile.open(TOOL_PATH"/src/instrument/atf.s");
    while(getline(ifile,str))
      atf += str;
    return atf;
  }
  void createHash(char *att_tbl, uint64_t size) {
    AttRec *tbl_start = (AttRec *)att_tbl;
    //Ignore first record and last record;
    att_tbl += (4 * 8);
    size -= (8 * 8);
    auto entry_cnt = size/sizeof(AttRec);
    auto hash_entry = entry_cnt + entry_cnt * 0.8;
    double l = ceil(log2(hash_entry));
    //l += 1;
    hashTblBit_ = l;
    hashTblSize_ = powl(2,hashTblBit_);
    //bool repeat = true;
    srand((unsigned) time(0));
    uint64_t y  = rand() & 0xff;
    y |= (uint64_t)(rand() & 0xff) << 8;
    y |= (uint64_t)(rand() & 0xff) << 16;
    y |= (uint64_t)(rand() & 0xff) << 24;
    y |= (uint64_t)(rand() & 0xff) << 32;
    y |= (uint64_t)(rand() & 0xff) << 40;
    y |= (uint64_t)(rand() & 0xff) << 48;
    y |= (uint64_t)(rand() & 0xff) << 56;
    //y |= (uint64_t)(rand() & 0xff) << 64;
    if(y % 2 == 0)
      y++;
    randKey_ = 0x9e3779b97f4a7c55;//y;
    genAllHash((AttRec *)att_tbl, size/sizeof(AttRec));
    tbl_start->old_ = randKey_;
    tbl_start->new_ = hashTblBit_;
    tbl_start->hashInd_ = hashTblSize_;
  }
  /*
  void createHash(char *att_tbl, uint64_t size) {
    AttRec *tbl_start = (AttRec *)att_tbl;
    //Ignore first record and last record;
    att_tbl += (4 * 8);
    size -= (8 * 8);
    double l = log2(attTable_.size());
    l += 1;
    hashTblBit_ = l;
    bool repeat = true;
    srand((unsigned) time(0));
    uint64_t y  = rand() & 0xff;
    y |= (uint64_t)(rand() & 0xff) << 8;
    y |= (uint64_t)(rand() & 0xff) << 16;
    y |= (uint64_t)(rand() & 0xff) << 24;
    y |= (uint64_t)(rand() & 0xff) << 32;
    y |= (uint64_t)(rand() & 0xff) << 40;
    y |= (uint64_t)(rand() & 0xff) << 48;
    y |= (uint64_t)(rand() & 0xff) << 56;
    //y |= (uint64_t)(rand() & 0xff) << 64;
    if(y % 2 == 0)
      y++;
    randKey_ = 0x9e3779b97f4a7c55;//y;
    while(repeat) {
      if(ctr >= 10)
        break;
      ctr++;
      repeat = false;
      done = true;
      hashTblSize_ = powl(2,hashTblBit_);
      done = genAllHash((AttRec *)att_tbl, size/sizeof(AttRec));
      if(done == false) {
        repeat = true;
        randKey_ += 2;
      }
    }
    if(done == false) {
      while(true) {
        hashTblBit_++;
        hashTblSize_ = powl(2,hashTblBit_);
        bool done = genAllHash((AttRec *)att_tbl, size/sizeof(AttRec));
        if(done)
          break;
      }
    }
    tbl_start->old_ = randKey_;
    tbl_start->new_ = hashTblBit_;
    tbl_start->hashInd_ = hashTblSize_;
    //cout<<"Hash tbl bit size: "<<hex<<hashTblBit_<<endl;
    //cout<<"Hash tbl entry cnt: "<<hex<<hashTblSize_<<endl;
  }
  */
  virtual uint64_t encodePtr(uint64_t addrs,uint64_t new_ptr,uint64_t tramp_ptr) = 0;
  virtual string encodeLea(string op, uint64_t ptr) = 0;
  virtual string decodeIcf(string hook_target, string args, string mne) = 0;
  virtual EncType enctype() = 0;
};


class GttAtt : public Encode {
  static int decode_counter;
  public:
    uint64_t encodePtr(uint64_t addrs,uint64_t new_ptr,uint64_t tramp_ptr) {
      int att_ind = attIndex(addrs);
      if(att_ind != -1)
        return att_ind;
      return addrs;
    };
    string encodeLea(string op, uint64_t ptr) {
        size_t pos = op.find (",");
        string reg = op.substr (pos + 2);
        if(reg.find("%") == string::npos)
          reg = "%" + reg;
        //string inst = "pushf\n";
        //inst += "movabs $0x00000000f0000000," + reg + "\n"
        //      + "add .gtt_ind(%rip)," + reg + "\n"
        //      + "shl $28," + reg + "\n"
        //      + "add ." + to_string(ptr) + "_enc_ptr(%rip)," + reg +"\n"
        //      + "shl $4," + reg + "\n"
        //      + "popf\n";
        string inst = "mov ." + to_string(ptr) + "_enc_ptr(%rip)," + reg + "\n";
        return inst;
    }
    string encodeRet(uint64_t ptr) {
        string inst = "mov ." + to_string(ptr) + "_enc_ptr(%rip),%rax\n";
        return inst;
    }

    string decodeIcf(string hook_target, string args, string mne) {
      string inst_code = "";
      inst_code += "mov %rax,%fs:0x88\n";
      inst_code += args;
      inst_code += ".decode_" + to_string(decode_counter) + ":\n"
                 + "cmp $0,%rax\n" + "jg .at_" + to_string(decode_counter) + "\n"
                 + "sub $16,%rsp\n"
                 + "mov %rcx,0(%rsp)\n"
                 + "mov %rdx,8(%rsp)\n"
                 + "mov .att_arr(%rip),%rdx\n"
                 + "mov %rax,%rcx\n"
                 + "shr $4,%eax\n"
                 + "and $0xfffff,%rax\n"
                 + "shr $32,%rcx\n"
                 + "and $0xff,%rcx\n"
                 + "mov 0x0(%rdx,%rcx,8),%rdx\n"
                 + "lea 0x0(%rax,%rax,4),%rax\n"
                 + "lea 24(%rdx,%rax,8),%rax\n"
                 + "mov 0(%rsp),%rcx\n"
                 + "mov 8(%rsp),%rdx\n"
                 + "add $16,%rsp\n"
                 + mne + " *%rax\n"
                 + "jmp .fall_" + to_string(decode_counter) + "\n";
      inst_code += ".at_" + to_string(decode_counter) + ":\n"
                 + mne + " ." + hook_target + "\n" + ".fall_" + to_string(decode_counter) +":\n";

      decode_counter++;
      return inst_code;
    }
    string decodeRet(string hook_target, string args, string mne) {
      string inst_code = "";
      inst_code += "mov %rax,%fs:0x88\n";
      inst_code += args;
      inst_code += ".decode_" + to_string(decode_counter) + ":\n"
                 + "cmp $0,%rax\n" + "jg .at_" + to_string(decode_counter) + "\n"
                 + "sub $24,%rsp\n"
                 + "mov %rcx,0(%rsp)\n"
                 + "mov %rdx,8(%rsp)\n"
                 + "mov .att_arr(%rip),%rdx\n"
                 + "mov %rax,%rcx\n"
                 + "shr $4,%eax\n"
                 + "and $0xfffff,%rax\n"
                 + "shr $32,%rcx\n"
                 + "and $0xff,%rcx\n"
                 + "mov 0x0(%rdx,%rcx,8),%rdx\n"
                 + "lea 0x0(%rax,%rax,4),%rax\n"
                 + "lea 24(%rdx,%rax,8),%rax\n"
                 + "mov 0(%rsp),%rcx\n"
                 + "mov 8(%rsp),%rdx\n"
                 + "add $16,%rsp\n"
                 + "mov %rax,0(%rsp)\n"
                 + "mov %fs:0x88,%rax\n"
                 + "ret\n";
      inst_code += ".at_" + to_string(decode_counter) + ":\n"
                 + mne + " ." + hook_target + "\n" + ".fall_" + to_string(decode_counter) +":\n";

      decode_counter++;
      return inst_code;
    }
    string decodeRAX() {
      string inst_code = "";
      inst_code += ".decode_RAX:\n";
      inst_code += "cmp $0,%rax\n"; 
      inst_code += "jg .at_RAX\n";
      inst_code += "sub $16,%rsp\n";
      inst_code += "mov %rcx,0(%rsp)\n";
      inst_code += "mov %rdx,8(%rsp)\n";
      inst_code += "mov .att_arr(%rip),%rdx\n";
      inst_code += "mov %rax,%rcx\n";
      inst_code += "shr $4,%eax\n";
      inst_code += "and $0xfffff,%rax\n";
      inst_code += "shr $32,%rcx\n";
      inst_code += "and $0xff,%rcx\n";
      inst_code += "mov 0x0(%rdx,%rcx,8),%rdx\n";
      inst_code += "lea 0x0(%rax,%rax,4),%rax\n";
      inst_code += "lea 24(%rdx,%rax,8),%rax\n";
      inst_code += "mov 0(%rsp),%rcx\n";
      inst_code += "mov 8(%rsp),%rdx\n";
      inst_code += "add $16,%rsp\n";
      inst_code += "ret\n";
      inst_code += ".at_RAX:\n"; 
      inst_code += "jmp .GTF_translate\n";
      return inst_code;
    }
    string shadowTramp() {
      //Assume that rax has target
      string inst_code = "";
      inst_code += ".shadow_tramp:\n";
      inst_code += "cmpq $0,%fs:0x78\n";
      inst_code += "jne .push_ra\n";
      inst_code += "callq .init_shstk\n";
      inst_code += ".push_ra:\n";
      inst_code += "addq $16,%fs:0x78\n";
      inst_code += "push %rax\n";
      inst_code += "mov %fs:0x78,%rax\n";
      inst_code += "push %rbx\n";
      inst_code += "mov 16(%rsp),%rbx\n";
      inst_code += "mov %rbx,-8(%rax)\n";
      inst_code += "lea 16(%rsp),%rbx\n";
      inst_code += "mov %rbx,-16(%rax)\n";
      inst_code += "pop %rbx\n";
      inst_code += "pop %rax\n";
      inst_code += "cmp $0,%rax\njg .at_tramp\n";
      inst_code +=  "sub $16,%rsp\n";
      inst_code +=  "mov %rcx,0(%rsp)\n";
      inst_code +=  "mov %rdx,8(%rsp)\n";
      inst_code +=  "mov .att_arr(%rip),%rdx\n";
      inst_code +=  "mov %rax,%rcx\n";
      inst_code +=  "shr $4,%eax\n";
      inst_code +=  "and $0xfffff,%rax\n";
      inst_code +=  "shr $32,%rcx\n";
      inst_code +=  "and $0xff,%rcx\n";
      inst_code +=  "mov 0x0(%rdx,%rcx,8),%rdx\n";
      inst_code +=  "lea 0x0(%rax,%rax,4),%rax\n";
      inst_code +=  "lea 24(%rdx,%rax,8),%rax\n";
      inst_code +=  "mov 0(%rsp),%rcx\n";
      inst_code +=  "mov 8(%rsp),%rdx\n";
      inst_code +=  "add $16,%rsp\n";
      inst_code +=  "jmp *%rax\n";
      inst_code += ".at_tramp:\n";
      inst_code += "jmp .GTF_reg\n";
      return inst_code;
    }
    EncType enctype() { return EncType::ENC_GTT_ATT; }
};

class MultInv : public Encode {
  static int decode_counter;
  uint64_t ODD_A = 3;
  uint64_t ODD_X = 768614336404564651; 
  public:
    uint64_t encodePtr(uint64_t addrs,uint64_t new_ptr,uint64_t tramp_ptr) {
      /*
      int att_ind = attIndex(addrs);
      if(att_ind != -1)
        return att_ind;
      return addrs;
      */
      return tramp_ptr;
    }
    string encodeLea(string op, uint64_t ptr) {
        size_t pos = op.find (",");
        string reg = op.substr (pos + 2);
        if(reg.find("%") == string::npos)
          reg = "%" + reg;
        /*
        string inst = "pushf\n";
        if(reg.find("rdx") != string::npos) {
          string xtra_reg = "%rax";
          inst += "push " + xtra_reg + "\n"
                + "lea ." + to_string(ptr) + "_tramp_ptr(%rip)," + xtra_reg +"\n";
          inst += "movabs $" + to_string(ODD_X) + ",%rdx\n"
                + "mulx " + xtra_reg + "," + xtra_reg + ",%rdx\n"
                + "movabs $0x8000000000000000,%rdx\n"
                + "or %rdx," + xtra_reg + "\n"
                + "mov " + xtra_reg + ",%rdx\n"
                + "pop " + xtra_reg + "\npopf\n";
        }
        else {
          inst += "push %rdx\n";
          inst += "lea ." + to_string(ptr) + "_tramp_ptr(%rip)," + reg +"\n";
          inst += "movabs $" + to_string(ODD_X) + ",%rdx\n"
                + "mulx " + reg + "," + reg + ",%rdx\n"
                + "movabs $0x8000000000000000,%rdx\n"
                + "or %rdx," + reg + "\n"
                + "pop %rdx\npopf\n";
        }
        */
        string inst = "mov ." + to_string(ptr) + "_enc_ptr(%rip)," + reg + "\n";
        return inst;
    }
    string encodeRet(uint64_t ptr) {
        string inst = "mov ." + to_string(ptr) + "_enc_ptr(%rip),%rax\n";
        return inst;
    }

    string decodeIcf(string hook_target, string args, string mne) {
      string inst_code = "";
      inst_code += "mov %rax,%fs:0x88\n";
      inst_code += args;
      inst_code += ".decode_" + to_string(decode_counter) + ":\n"
                 + "cmp $0,%rax\n" + "jg .at_" + to_string(decode_counter) + "\n"
                 + "push %rdx\n"
                 + "movabs $" + to_string(ODD_A) + ",%rdx\n"
                 + "mulx %rax,%rax,%rdx\n"
                 + "movabs $0x7fffffffffffffff,%rdx\n"
                 + "and %rdx,%rax\n"
                 + "pop %rdx\n"
                 + mne + " *%rax\n"
                 + "jmp .fall_" + to_string(decode_counter) + "\n";
      inst_code += ".at_" + to_string(decode_counter) + ":\n"
                 + mne + " ." + hook_target + "\n" + ".fall_" + to_string(decode_counter) +":\n";

      decode_counter++;
      return inst_code;
    }
    string decodeRet(string hook_target, string args, string mne) {
      string inst_code = "";
      inst_code += "mov %rax,%fs:0x88\n";
      inst_code += args;
      inst_code += ".decode_" + to_string(decode_counter) + ":\n"
                 + "cmp $0,%rax\n" + "jg .at_" + to_string(decode_counter) + "\n"
                 + "push %rdx\n"
                 + "movabs $" + to_string(ODD_A) + ",%rdx\n"
                 + "mulx %rax,%rax,%rdx\n"
                 + "movabs $0x7fffffffffffffff,%rdx\n"
                 + "and %rdx,%rax\n"
                 + "pop %rdx\n"
                 + "sub $16,%rax\n"
                 + "mov (%rax),%rax\n"
                 + "push %rax\n"
                 + "mov %fs:0x88,%rax\n"
                 + "ret\n";
      inst_code += ".at_" + to_string(decode_counter) + ":\n"
                 + mne + " ." + hook_target + "\n" + ".fall_" + to_string(decode_counter) +":\n";

      decode_counter++;
      return inst_code;
    }
    string decodeRAX() {
      string inst_code = "";
      inst_code += ".decode_RAX:\n";
      inst_code += "cmp $0,%rax\n";
      inst_code += "jg .at_RAX\n";
      inst_code += "push %rdx\n";
      inst_code += "movabs $" + to_string(ODD_A) + ",%rdx\n";
      inst_code += "mulx %rax,%rax,%rdx\n";
      inst_code += "movabs $0x7fffffffffffffff,%rdx\n";
      inst_code += "and %rdx,%rax\n";
      inst_code += "sub $16,%rax\n";
      inst_code += "mov (%rax),%rax\n";
      inst_code += "pop %rdx\n";
      inst_code += "ret\n";
      inst_code += ".at_RAX:\n";
      inst_code += "jmp .GTF_translate\n";
      return inst_code;
    }
    string shadowTramp() {
      //Assume that rax has target
      string inst_code = "";
      inst_code += ".shadow_tramp:\n";
      inst_code += "cmpq $0,%fs:0x78\n";
      inst_code += "jne .push_ra\n";
      inst_code += "callq .init_shstk\n";
      inst_code += ".push_ra:\n";
      inst_code += "addq $16,%fs:0x78\n";
      inst_code += "push %rax\n";
      inst_code += "mov %fs:0x78,%rax\n";
      inst_code += "push %rbx\n";
      inst_code += "mov 16(%rsp),%rbx\n";
      inst_code += "mov %rbx,-8(%rax)\n";
      inst_code += "lea 16(%rsp),%rbx\n";
      inst_code += "mov %rbx,-16(%rax)\n";
      inst_code += "pop %rbx\n";
      inst_code += "pop %rax\n";
      inst_code += "cmp $0,%rax\n";
      inst_code += "jg .at_tramp\n";
      inst_code += "push %rdx\n";
      inst_code += "movabs $" + to_string(ODD_A) + ",%rdx\n"
                 + "mulx %rax,%rax,%rdx\n"
                 + "movabs $0x7fffffffffffffff,%rdx\n"
                 + "and %rdx,%rax\n"
                 + "pop %rdx\n"
                 + "jmp *%rax\n";
      inst_code += ".at_tramp:\n";
      inst_code += "jmp .GTF_reg\n";
      return inst_code;
    }
    EncType enctype() { return EncType::ENC_MULT_INV; }
};

class IndAtf : public Encode {
  public:
    uint64_t encodePtr(uint64_t addrs) { return addrs; };
    string encodeLea(string mne, string op, uint64_t ins_loc, uint64_t ptr) { return ""; };
    string decodeIcf(string mnemonic, string op1, uint64_t loc) {return ""; };
    EncType enctype() { return EncType::ENC_IND_ATF; }
};

#endif
