#include "SaInput.h"

using namespace SBI;

void addIns(map <uint64_t,string> &all_ins,vector <string> &allstr) {
  for(auto & str : allstr) {
    vector <string> words = utils::split_string(str,' ');
    string loc = words[0];
    loc.replace(0,1,"");
    loc.replace(loc.find(":"),1,"");
    uint64_t addrs = stoll(loc);
    if(words[1].find("ret") != string::npos)
      str = words[0] + " ret";
    if(words[1].find("ud2") != string::npos)
      str = words[0] + " nop";
    all_ins[addrs] = str;
  }
}

void
SaInput::dumpIndrctTgt(string fname, unordered_map<int64_t, vector<int64_t>> ind_tgts) {
  ofstream ofile;
  ofile.open(fname);
  for(auto & x : ind_tgts) {
    ofile<<x.first<<": ";
    for(auto & t : x.second)
      ofile<<t<<" ";
    ofile<<endl;
  }
  ofile.close();
}

void
SaInput::dumpInsSizes(string file_name,unordered_map<int64_t,int64_t> &sizes) {
  ofstream ofile;
  ofile.open(file_name);
  for(auto & s : sizes) {
    ofile<<s.first<<" "<<s.second<<endl;
  }
  ofile.close();
}

unordered_map<int64_t,int64_t>
SaInput::insSizes(vector <BasicBlock *>bb_lst) {
  unordered_map<int64_t,int64_t> ins_sz;
  for(auto & bb : bb_lst) {
    auto sz = bb->insSizes();
    ins_sz.insert(sz.begin(),sz.end());
  }
  return ins_sz;
}


void
SaInput::indTgts(vector <BasicBlock *> & bb_list, 
    unordered_map<int64_t, vector<int64_t>> & ind_tgts) {

  vector <BasicBlock *> all_ind_tgts;

  for(auto & bb : bb_list) {
    if(ind_tgts.find(bb->end()) == ind_tgts.end()) {
      unordered_set <BasicBlock *> ind_bbs = bb->indirectTgts();

      for(auto & ind_bb : ind_bbs) {
        vector <BasicBlock *> lst = bbSeq(ind_bb);
        if(CFValidity::validIns(lst)) {
          ind_tgts[bb->end()].push_back(ind_bb->start());
          indTgts(lst, ind_tgts);
          all_ind_tgts.insert(all_ind_tgts.end(),lst.begin(),lst.end());
        }
      }
    }
  }

  bb_list.insert(bb_list.end(),all_ind_tgts.begin(),all_ind_tgts.end());
}

void
SaInput::genFnFile(string file_name,uint64_t entry,vector<BasicBlock *> &bbList) {
  map <uint64_t,string> all_ins;
  LOG("Generating asm file for: "<<hex<<entry);
  for(auto & bb : bbList) {
    if(all_ins.find(bb->start()) == all_ins.end()) {
      vector <string> all_asm = bb->allAsm();
      if(bb->isCall() && bb->callType() == BBType::NON_RETURNING) {
        string last_ins = all_asm[all_asm.size() - 1];
        vector <string> words = utils::split_string(last_ins,' ');
        string loc = words[0];
        last_ins = loc + " hlt";
        //LOG("Replacing not returning call with hlt: "<<hex<<bb->start());
        all_asm[all_asm.size() - 1] = last_ins;
      }
      addIns(all_ins,all_asm);
    }
  }
  vector <BasicBlock *> new_bbs;
  for(auto & bb : bbList) {
    if(bb->isCall() == false && bb->target() != 0 &&
       all_ins.find(bb->target()) == all_ins.end()) {
      LOG("Adding dummy tgt: "<<hex<<bb->target());
      uint8_t b[] = {0xf4};
      char mne[] = "hlt";
      char op[] = "";
      Instruction *ins = new Instruction(bb->target(),mne,op,b,1);
      vector <Instruction *> ins_list;
      ins_list.push_back(ins);
      BasicBlock * new_bb = new BasicBlock(bb->target(),bb->target()
          + 1,bb->source(),bb->rootSrc(),ins_list);
      new_bbs.push_back(new_bb);
      all_ins[bb->target()] = "." + to_string(bb->target()) + ": hlt";
    }
    if(bb->fallThrough() != 0 &&
       all_ins.find(bb->fallThrough()) == all_ins.end()) {
      LOG("Adding dummy fall: "<<hex<<bb->fallThrough());
      uint8_t b[] = {0xf4};
      char mne[] = "hlt";
      char op[] = "";
      Instruction *ins = new Instruction(bb->fallThrough(),mne,op,b,1);
      vector <Instruction *> ins_list;
      ins_list.push_back(ins);
      BasicBlock * new_bb = new BasicBlock(bb->fallThrough(),bb->fallThrough()
          + 1,bb->source(),bb->rootSrc(),ins_list);
      new_bbs.push_back(new_bb);
      all_ins[bb->fallThrough()] = "." + to_string(bb->fallThrough()) + ": hlt";
    }
  }
  bbList.insert(bbList.end(),new_bbs.begin(),new_bbs.end());
  ofstream ofile;
  ofile.open(file_name);
  for (auto & ins : all_ins) {
    vector <string> words = utils::split_string(ins.second,' ');
    for(auto & w : words) {
      if(w == "lea")
        w = "leaq";
      else if(w == "add")
        w = "addq";
      else if(w == "notrack")
        continue;
      ofile<<w<<" ";
    }
    ofile<<endl;
  }
  ofile.close();
  LOG("Asm file generated");
}

