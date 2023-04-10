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
  uint64_t tramp_;
  uint64_t hashInd_;
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
  
  uint64_t pos[2];
  uint64_t rand1;
  uint64_t rand2;
  
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
        cout<<"collision: "<<hex<<att_tbl[i].old_<<"->"<<hex<<hash_map[ptr]<<endl;
        return false;
      }
    }
    return true;
  }
  void cuckooHashInit() {
    srand((unsigned) time(0));
    rand1  = rand() & 0xff;
    rand1 |= (uint64_t)(rand() & 0xff) << 8;
    rand1 |= (uint64_t)(rand() & 0xff) << 16;
    rand1 |= (uint64_t)(rand() & 0xff) << 24;
    rand1 |= (uint64_t)(rand() & 0xff) << 32;
    rand1 |= (uint64_t)(rand() & 0xff) << 40;
    rand1 |= (uint64_t)(rand() & 0xff) << 48;
    rand1 |= (uint64_t)(rand() & 0xff) << 56;
    //y |= (uint64_t)(rand() & 0xff) << 64;
    if(rand1 % 2 == 0)
      rand1++;
 
    //srand((unsigned) time(0));
    //chash_rand2 = 23478289 * rand();
//    srand((unsigned) time(0));
    rand2  = rand() & 0xff;
    rand2 |= (uint64_t)(rand() & 0xff) << 8;
    rand2 |= (uint64_t)(rand() & 0xff) << 16;
    rand2 |= (uint64_t)(rand() & 0xff) << 24;
    rand2 |= (uint64_t)(rand() & 0xff) << 32;
    rand2 |= (uint64_t)(rand() & 0xff) << 40;
    rand2 |= (uint64_t)(rand() & 0xff) << 48;
    rand2 |= (uint64_t)(rand() & 0xff) << 56;
    //y |= (uint64_t)(rand() & 0xff) << 64;
    if(rand2 % 2 == 0)
      rand2++;
  } 

  uint64_t cuckooHash(int hash_fn, uint64_t ptr) {
    
    if (hash_fn == 1) {
      ptr = ptr * rand1;
    //  uint64_t lim = pow(2, hashTblBit_);
    //  key = key & (lim - 1);
      ptr = ptr >> (64 - hashTblBit_ + 1);
      ptr = ptr & (hashTblSize_ - 1);
 
    } else {
      ptr = ptr * rand2;
     // uint64_t lim = pow(2, hashTblBit_);
     // ptr = ptr & (lim - 1);
      ptr = ptr >> (64 - hashTblBit_ + 1);
      ptr = ptr & (hashTblSize_ - 1);

    }
    printf("Returned key: %ld\n", ptr);
    return ptr;
  }
  
  int cuckooPlace(vector<unordered_map<uint64_t, uint64_t>> &hash_maps,
    uint64_t old_val, int table, uint64_t cnt, uint64_t entry_cnt) {    
   
    // If we end up in a cycle
    if (cnt == entry_cnt) {
      printf("Cycle in cuckoo hash\n");
      return -1;
    }

    // Check if the value is already at any of the the two positions
    for (int i = 0; i < 2; i++) {
      pos[i] = cuckooHash(i + 1, old_val);
      if (hash_maps[i].find(pos[i]) != hash_maps[i].end() &&
          hash_maps[i][pos[i]] == old_val)
        return 0;
    }

    // Now we check if another value if present at the given position
    // If so, evict it otherwise just store the value at the spot
    if (hash_maps[table].find(pos[table]) != hash_maps[table].end()) {
      uint64_t displaced = hash_maps[table][pos[table]];
      hash_maps[table][pos[table]] = old_val;
      printf("Placed by CuckooPlace at: %d\n", pos[table]);
      return cuckooPlace(hash_maps, displaced, (table + 1) % 2, cnt + 1, entry_cnt);
    } else {
       hash_maps[table][pos[table]] = old_val;
       printf("Placed by CuckooPlace at: %d\n", pos[table]);
    }
    return 0;
  }

  int cuckooPlaceAtt(vector<unordered_map<uint64_t, uint64_t>> &hash_maps,
      AttRec *att_tbl, uint64_t entry_cnt) {
    // We traverse the maps for every entry
    printf("Inside cuckooPlaceAtt\n");
    for (uint64_t i = 0; i < entry_cnt; i++) {
      AttRec *ptr = &att_tbl[i];
      for (auto &it : hash_maps[0]) {
        if (it.second == ptr->old_) {
          ptr->hashInd_ = it.first;
        }
      }
      // second hash table, we add the size of 1 table to the hashInd
      // to flatten the two hash tables into a single table so that
      // the printed assembly is similar to what it was earlier
      for (auto &it : hash_maps[1]) {
        AttRec *ptr = &att_tbl[i];
        if (it.second == att_tbl[i].old_) {
          ptr->hashInd_ = it.first + (hashTblSize_ / 2);
        }
      }
    }
    return 0;
  }
  bool genCuckooHash(AttRec *att_tbl, uint64_t entry_cnt) {
    // We generate 2 hash maps
    // TODO: we can simplify this later
    vector<unordered_map<uint64_t,uint64_t>> hash_maps(2);
    int ret = 0;
    printf("Entry cnt: %ld\n", entry_cnt);
    for (uint64_t i = 0, cnt = 0; i < entry_cnt; i++, cnt = 0) {
      printf("CuckooPlace called for: %lx\n", att_tbl[i].old_);
      ret = cuckooPlace(hash_maps, att_tbl[i].old_, 0, cnt, entry_cnt);
      if (ret == -1) {
        return false;
      }
    }
    // After cuckooPlace is successful in populating the two hash tables,
    // we have to put the hash table index in the att table
    printf("Hashmap sizes: %ld, %ld\n", hash_maps[0].size(), hash_maps[1].size()); 
    for (auto it : hash_maps[0]) {
      printf("%ld -> %lx\n", it.first, it.second);
    }
    printf("second\n");
    for (auto it : hash_maps[1]) {
      printf("%ld -> %lx\n", it.first, it.second);
    }
    if (ret == 0) {
      ret = cuckooPlaceAtt(hash_maps, att_tbl, entry_cnt);
    }
    printf("Final hash tbl size %lu", hashTblSize_);
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
    string tbl = ".att_key: .8byte " + to_string(randKey_) + "\n";
    tbl += ".att_tbl_bit: .8byte " + to_string(hashTblBit_) + "\n";
    tbl += ".att_tbl_sz: .8byte " + to_string(hashTblSize_) + "\n";
    int ctr = 0;
    for (auto & e : attTable_) {
      e.lookupEntrySym_ = ".attentry_lookup_" + to_string(e.val_);
      e.tgtEntrySym_ = ".attentry_tgt_" + to_string(e.val_);
      string enc_ptr_sym = "." + to_string(e.val_) + "_enc_ptr";
      string tramp_sym = "." + to_string(e.val_) + "_tramp_ptr";
      if(e.oldOrNew_ == 1) {
        e.lookupEntrySym_ += "_new";
        e.tgtEntrySym_ += "_new";
        enc_ptr_sym += "_new";
        tramp_sym += "_new";
      }
      tbl += e.lookupEntrySym_ + ":\n"
          + e.oldPtr_ + "\n" + e.tgtEntrySym_ + ":\n"
          + e.newPtr_ + "\n"
          + tramp_sym + ":\n"
          + ".8byte " + e.tramp_ + " - .elf_header_start\n"
          + enc_ptr_sym + ":\n" 
          + ".8byte " + to_string(e.oldOrNew_) + "\n";
      ctr++;
    }
    string seg_fault = ".8byte .segfault_handler - .elf_header_start\n.8byte\
      .segfault_handler - .elf_header_start\n.8byte 0\n.8byte 0\n";
    tbl += seg_fault;
    tbl += ".dispatcher_stack: .8byte 0\n.dispatcher_reg: .8byte 0\n.syscall_checker: .8byte 0\n";
    return tbl;
  };

  string trampAsm() {
    string tramp_asm = "";
    for (auto & e : attTable_) {
      if(e.newPtrSym_.length() > 0) {
        tramp_asm += e.tramp_ + ":\n"
                   + "mov 24(%rsp),%rax\n"
                   + "add $40,%rsp\n"
                   + "jmp " + e.newPtrSym_ + "\n";
      }
    }
    return tramp_asm;
  }

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
    size -= (6 * 8);
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
    printf("Final hash table size is: %d\n", hashTblSize_); 
    tbl_start->old_ = randKey_;
    tbl_start->new_ = hashTblBit_;
    tbl_start->tramp_ = hashTblSize_;
    //cout<<"Hash tbl bit size: "<<hex<<hashTblBit_<<endl;
    //cout<<"Hash tbl entry cnt: "<<hex<<hashTblSize_<<endl;
  }
  void createCuckooHash(char *att_tbl, uint64_t size) {
    AttRec *tbl_start = (AttRec *)att_tbl;
    bool done = 0;
    int tries = 150;
    
    // Ignore first record and last record
    att_tbl += (3 * 8);
    size -= (6 * 8);   

    // Calculate the bits required based on the number of att
    // table entries
    double l = log2(attTable_.size());
    l += 1;
    // Since we want to have a 50% load factor. This will give the
    // total number of bits that would be divided between 2 hash tables
    l += 1;
    hashTblBit_ = l;
    hashTblSize_ = powl(2,hashTblBit_);
    printf("hash table size is: %d\n", hashTblSize_); 
    while (!done && tries > 0) {
      tries--;  
      // Init the random values used in hash functions
      cuckooHashInit();
      // Now we can generate the cuckoo hash table
      done = genCuckooHash((AttRec *)att_tbl, size/sizeof(AttRec));
    }
    printf("Exhausted tries: done = %d\n", done);
    // Now we will start increasing size of the table 
    while (!done) {
      hashTblBit_++;
      hashTblSize_ = powl(2,hashTblBit_);
      tries = 10;
      while (tries--) {
        cuckooHashInit();
        done = genCuckooHash((AttRec *)att_tbl, size/sizeof(AttRec));
        if (done)
         break;
      }
    }
   
    tbl_start->old_ = rand1;
    tbl_start->new_ = rand2;
    tbl_start->tramp_ = hashTblBit_;
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
