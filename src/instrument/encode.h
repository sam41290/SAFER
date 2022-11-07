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
};

class Encode {
  vector <AttEntry> attTable_;
public:
  void addAttEntry(uint64_t addrs, string lookup, string tgt) {
    AttEntry a;
    a.val_ = addrs;
    a.oldPtr_ = lookup;
    a.newPtr_ = tgt;
    attTable_.push_back(a);
  };

  string attTableAsm() {
    string tbl = ".atf_ptr: .8byte .atf - .elf_header_start\n";
    int ctr = 0;
    for (auto & e : attTable_) {
      e.lookupEntrySym_ = ".attentry_lookup" + to_string(ctr);
      e.tgtEntrySym_ = ".attentry_tgt" + to_string(ctr);
      tbl += e.lookupEntrySym_ + ":\n"
          + e.oldPtr_ + "\n" + e.tgtEntrySym_ + ":\n"
          + e.newPtr_ + "\n"
          /*+ "." + to_string(e.val_) + "_enc_ptr:*/ + ".8byte " + to_string((int)EncType()) + "\n";
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
