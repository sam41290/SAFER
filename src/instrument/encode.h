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
  ENC_IND_ATF
};

struct AttRec {
  uint64_t old_;
  uint64_t new_;
  uint64_t hashInd_;
};

struct AttEntry {
  uint64_t val_;
  string lookupEntrySym_;
  string tgtEntrySym_;
  string oldPtr_;
  string newPtr_;
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
      ptr = getHash(ptr);
      //cout<<"hash: "<<hex<<att_tbl[i].old_<<"->"<<hex<<ptr<<endl;
      if(hash_map.find(ptr) == hash_map.end() ||
         hash_map[ptr] == att_tbl[i].old_) {
        hash_map[ptr] = att_tbl[i].old_;
        att_tbl[i].hashInd_ = ptr;
      }
      else {
        //cout<<"collision: "<<hex<<att_tbl[i].old_<<"->"<<hex<<hash_map[ptr]<<endl;
        return false;
      }
    }
    return true;
  }

public:
  void addAttEntry(uint64_t addrs, string lookup, string tgt, int tt) {
    AttEntry a;
    a.val_ = addrs;
    a.oldPtr_ = lookup;
    a.newPtr_ = tgt;
    a.oldOrNew_ = tt;
    attTable_.push_back(a);
  };

  string attTableAsm() {
    //createHash();
    string tbl = ".att_key: .8byte " + to_string(randKey_) + "\n";
    tbl += ".att_tbl_bit: .8byte " + to_string(hashTblBit_) + "\n";
    tbl += ".att_tbl_sz: .8byte " + to_string(hashTblSize_) + "\n";
    int ctr = 0;
    for (auto & e : attTable_) {
      e.lookupEntrySym_ = ".attentry_lookup_" + to_string(e.val_);
      e.tgtEntrySym_ = ".attentry_tgt_" + to_string(e.val_);
      string enc_ptr_sym = "." + to_string(e.val_) + "_enc_ptr";
      if(e.oldOrNew_ == 1) {
        e.lookupEntrySym_ += "_new";
        e.tgtEntrySym_ += "_new";
        enc_ptr_sym += "_new";
      }
      tbl += e.lookupEntrySym_ + ":\n"
          + e.oldPtr_ + "\n" + e.tgtEntrySym_ + ":\n"
          + e.newPtr_ + "\n"
          + enc_ptr_sym + ":\n" 
          + ".8byte " + to_string(e.oldOrNew_) + "\n";
      ctr++;
    }
    tbl += ".dispatcher: .8byte 0\n.gtt_ind: .8byte 0\n.syscall_checker: .8byte 0\n";
    return tbl;
  };

  int attIndex(uint64_t val) {
    int ctr = 0;
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
    att_tbl += (3 * 8);
    size -= (3 * 8);
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
      done = genAllHash((AttRec *)att_tbl, size/24);
      if(done == false) {
        repeat = true;
        randKey_ += 2;
      }
    }
    if(done == false) {
      while(true) {
        hashTblBit_++;
        hashTblSize_ = powl(2,hashTblBit_);
        bool done = genAllHash((AttRec *)att_tbl, size/24);
        if(done)
          break;
      }
    }
    tbl_start->old_ = randKey_;
    tbl_start->new_ = hashTblBit_;
    tbl_start->hashInd_ = hashTblSize_;
  }
  virtual uint64_t encodePtr(uint64_t addrs) = 0;
  virtual string encodeLea(string mne, string op, uint64_t ins_loc, uint64_t ptr) = 0;
  virtual string decodeIcf(string mnemonic, string op1, uint64_t loc) = 0;
  virtual EncType enctype() = 0;
};


class GttAtt : public Encode {
  public:
    uint64_t encodePtr(uint64_t addrs) {
      int att_ind = attIndex(addrs);
      if(att_ind != -1)
        return att_ind;
      return addrs;
    };
    string encodeLea(string mne, string op, uint64_t ins_loc, uint64_t ptr) {
      string asm_ins = "";
      int att_ind = attIndex(ptr);
      if(att_ind != -1) {
        size_t pos = op.find (",");
        string reg = op.substr (pos + 2);
        //uint64_t enc_ptr = 0x440000000000 + att_ind;
        //asm_ins += "pushf\nmov $" 
        //        + to_string(enc_ptr) + "," + reg + "\n"
        //        + "add .gtt_ind(%rip)," + reg + "\n"
        //        + "popf\n";

        asm_ins = "mov ." + to_string(ptr) + "_enc_ptr(%rip)," + reg + "\n";
      }
      return asm_ins; 
    }
    string decodeIcf(string mne, string op, uint64_t loc) {
      string asm_ins = "";
      asm_ins += "push %rdi\nmov "
              + op + ", %rdi\n"
              + mne + " .dispatcher(%rip)\n";
      return asm_ins; 
    }
    EncType enctype() { return EncType::ENC_GTT_ATT; }
};

class IndAtf : public Encode {
  public:
    uint64_t encodePtr(uint64_t addrs) { return addrs; };
    string encodeLea(string mne, string op, uint64_t ins_loc, uint64_t ptr) { return ""; };
    string decodeIcf(string mnemonic, string op1, uint64_t loc) {return ""; };
    EncType enctype() { return EncType::ENC_IND_ATF; }
};

#endif
