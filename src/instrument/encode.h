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

struct AttEntry {
  uint64_t val_;
  string lookupEntrySym_;
  string tgtEntrySym_;
  string oldPtr_;
  string newPtr_;
  int tt_;
  int hashInd_ = -1;
};

class Encode {
  vector <AttEntry> attTable_;
  int hashTblBit_;
  int hashTblSize_;
  uint32_t randKey_;
  int ctr = 0;
  bool done = false;

  uint32_t getHash(uint64_t ptr) {
    ptr = ptr * randKey_;
    ptr = ptr >> (32 - hashTblBit_);
    ptr = ptr & (hashTblSize_ - 1);
    return ptr;
  }

  bool genAllHash() {
    unordered_map<int,int> hash_map;
    for(auto & a : attTable_) {
      uint32_t ptr = a.val_;
      ptr = getHash(ptr);
      if(hash_map.find(ptr) == hash_map.end()) {
        hash_map[ptr] = a.val_;
        a.hashInd_ = ptr;
      }
      else {
        return false;
      }
    }
    return true;
  }

  void createHash() {
    hashTblBit_ = 16;
    bool repeat = true;
    srand((unsigned) time(0));
    while(repeat) {
      if(ctr >= 10)
        break;
      ctr++;
      repeat = false;
      done = true;
      hashTblSize_ = powl(2,hashTblBit_);
      uint32_t y  = rand() & 0xff;
      y |= (rand() & 0xff) << 8;
      y |= (rand() & 0xff) << 16;
      y |= (rand() & 0xff) << 24;
      if(y % 2 == 0)
        y++;
      randKey_ = y;
      done = genAllHash();
      if(done == false)
        repeat = true;
    }
    if(done == false) {
      while(true) {
        hashTblBit_++;
        hashTblSize_ = powl(2,hashTblBit_);
        bool done = genAllHash();
        if(done)
          break;
      }
    }
  }
public:
  void addAttEntry(uint64_t addrs, string lookup, string tgt, int tt) {
    AttEntry a;
    a.val_ = addrs;
    a.oldPtr_ = lookup;
    a.newPtr_ = tgt;
    a.tt_ = tt;
    attTable_.push_back(a);
  };

  string attTableAsm() {
    createHash();
    string tbl = ".att_key: .8byte " + to_string(randKey_) + "\n";
    tbl += ".att_tbl_bit: .8byte " + to_string(hashTblBit_) + "\n";
    tbl += ".att_tbl_sz: .8byte " + to_string(hashTblSize_) + "\n";
    int ctr = 0;
    for (auto & e : attTable_) {
      e.lookupEntrySym_ = ".attentry_lookup_" + to_string(e.val_);
      e.tgtEntrySym_ = ".attentry_tgt_" + to_string(e.val_);
      tbl += e.lookupEntrySym_ + ":\n"
          + e.oldPtr_ + "\n" + e.tgtEntrySym_ + ":\n"
          + e.newPtr_ + "\n"
          + "." + to_string(e.val_) + "_enc_ptr:\n" 
          + ".8byte " + to_string(e.hashInd_) + "\n";
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
