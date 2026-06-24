
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "Binary.h"
#include "Dfs.h"
#include "dataflow.h"
#include "lifter.h"
#include "arch.h"
#include "sba_function.h"
#include "scc.h"
#include "block.h"
#include "insn.h"
#include "rtl.h"
#include "expr.h"

using namespace std;

using namespace SBI;
#define REGVALTYPE_TO_GPR(x) (GPR)((int)x - 4)
#define GPR_TO_REGVALTYPE(x) (RegValType)((int)x + 4)

#include <string>
#include <optional>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <vector>
#include <algorithm>

#include <string>
#include <unordered_map>
#include <algorithm>
#include <cctype>
#include <optional>
#include <tuple>

unordered_map<uint64_t,tuple<RTL*,vector<uint8_t>>> LiftedProg::progRtlMap_;
unordered_map <uint64_t, DataFlow *> LiftedProg::liftedFuncs_;
Cfg *LiftedProg::cfg_;
bool LiftedProg::deeperDetails_ = true;

AnalysisHandler *
LiftedProg::liftFn(uint64_t addrs) {
  if(liftedFuncs_.find(addrs) == liftedFuncs_.end()) return NULL;
  auto df = liftedFuncs_[addrs];
  unordered_map<int64_t, vector<int64_t>> ind_tgts;

  auto bb_list = df->getAllBBs();
  cfg_->indTgts(bb_list, ind_tgts);

  unordered_map<IMM,unordered_set<IMM>> icfs;
  for(auto & ind : ind_tgts) {
    auto ic = ind.first;
    auto tgts = ind.second;
    for(auto & t : tgts)
      icfs[ic].insert(t);
  }
  cout<<"Preping RTL list..."<<endl; 
  vector<tuple<IMM,RTL*,vector<uint8_t>>> rtl;
  for(auto & bb : bb_list) {
    //cout<<"BB: "<<hex<<bb->start()<<endl;
    auto ins_list = bb->insList();
    for(auto & ins : ins_list) {
      if(progRtlMap_.find(ins->location()) == progRtlMap_.end()) {
        cout<<"Ins not lifted..no RTL: "<<hex<<ins->location()<<endl;
        continue;
      }
      auto t = progRtlMap_[ins->location()];
      rtl.push_back(make_tuple(ins->location(), get<0>(t), get<1>(t)));
    }
  }
  cout<<"Creating handler..."<<endl;
  auto h = create_handler_2(rtl,vector<IMM>{addrs}, icfs);
  return h;
}

LiftedProg::LiftedProg(Cfg *cfg, unordered_set <int> entry_list) {
  cfg_ = cfg;
  entryList_ = entry_list;
  vector <BasicBlock *> all_bb_list;
  unordered_set <uint64_t> bb_added;
  for (auto & entry : entryList_) {
    auto bb = cfg_->getBB(entry);
    if (bb != NULL) {
      auto p = cfg->ptr(entry);
      if(p != NULL && 
        (p->source() == PointerSource::JUMPTABLE ||
	 p->source() == PointerSource::GAP_PTR) && bb->parents().size() <= 0) 
        continue;
      cout<<"Creating dataflow object: "<<hex<<entry<<endl;
      auto df = new DataFlow(bb, cfg_);
      df->deeperDetails_ = deeperDetails_;
      auto bb_list = df->getAllBBs();
      auto local_bb_list = cfg->bbSeq(bb);
      if(cfg->validCF(local_bb_list)) {
        //all_bb_list.insert(all_bb_list.end(), bb_list.begin(), bb_list.end());
	for(auto & bb2 : bb_list) {
	  //cout<<"BB: "<<hex<<bb2->start()<<endl;
	  if(bb_added.find(bb2->start()) == bb_added.end()) {
	    all_bb_list.push_back(bb2);
	    bb_added.insert(bb2->start());
	  }
	}
        liftedFuncs_[entry] = df;
      }
      else cout<<"Invalid CF...ignoring:"<<hex<<entry<<endl;
    }
  }
  cout<<"Creating program assembly file"<<endl;
  string file_name =  TOOL_PATH"/apps/syscallpolicy/tmp/" + cfg_->exeName_ + ".s";
  cfg_->genFnFile(file_name,0,all_bb_list);
  auto ins_sz = cfg_->insSizes(all_bb_list);
  cout<<"Lifting program"<<endl;
  progRtl_ = load_2(file_name, ins_sz);
  for (auto [offset, rtl, raw]: progRtl_) {
    progRtlMap_[offset] = make_tuple(rtl, raw);
  }

  for(auto & lf : liftedFuncs_) {
    cout<<"Analyzing function "<<hex<<lf.first<<endl;
    unordered_map<int64_t, vector<int64_t>> ind_tgts;
    auto bb_list = lf.second->getAllBBs();
    cfg_->indTgts(bb_list, ind_tgts);

    unordered_map<IMM,unordered_set<IMM>> icfs;
    for(auto & ind : ind_tgts) {
      auto ic = ind.first;
      auto tgts = ind.second;
      for(auto & t : tgts)
        icfs[ic].insert(t);
    }
    cout<<"Preping RTL list..."<<endl; 
    vector<tuple<IMM,RTL*,vector<uint8_t>>> rtl;
    for(auto & bb : bb_list) {
      //cout<<"BB: "<<hex<<bb->start()<<endl;
      auto ins_list = bb->insList();
      for(auto & ins : ins_list) {
        if(progRtlMap_.find(ins->location()) == progRtlMap_.end()) {
          cout<<"Ins not lifted..no RTL: "<<hex<<ins->location()<<endl;
          continue;
        }
        auto t = progRtlMap_[ins->location()];
        rtl.push_back(make_tuple(ins->location(), get<0>(t), get<1>(t)));
      }
    }
    //cout<<"Creating handler..."<<endl;
    //auto h = create_handler_2(rtl,vector<IMM>{lf.first}, icfs);
    //cout<<"Analyzing..."<<endl;
    //lf.second->baseLHHandler(h);
    //lf.second->getBaseLHHandler();
    //if(lf.second->bad() == false) lf.second->collectInfo();
    //cout<<"Analyzing done. Bad = "<<lf.second->bad()<<endl;
    //delete h;
    //lf.second->clear();
  }
  //exit(0);

}

RTL *
LiftedProg::getRtl(uint64_t ins_addr) {
  auto t = progRtlMap_[ins_addr];
  auto rtl = get<0>(t);
  return rtl;
}

vector<string>
LiftedProg::regsReadByIns(uint64_t ins_addr) {
  //cout<<"Getting regs read by Ins at: "<<hex<<ins_addr<<endl;
  vector<string> used_args;
  if(progRtlMap_.find(ins_addr) == progRtlMap_.end()) return used_args;
  auto t = progRtlMap_[ins_addr];
  auto rtl = get<0>(t);
  if(rtl == NULL) return used_args;
  return rtl->readsReg();

}
vector<string>
LiftedProg::regsWrittenByIns(uint64_t ins_addr) {
  //cout<<"Getting regs written by Ins at: "<<hex<<ins_addr<<endl;
  vector<string> used_args;
  if(progRtlMap_.find(ins_addr) == progRtlMap_.end()) return used_args;
  auto t = progRtlMap_[ins_addr];
  auto rtl = get<0>(t);
  if(rtl == NULL) return used_args;
  return rtl->writesReg();
}

unordered_set <string>
LiftedProg::regsUsedInDeref(uint64_t ins_addr) {
  unordered_set<string> used_regs;
  if(progRtlMap_.find(ins_addr) == progRtlMap_.end()) return used_regs;
  auto t = progRtlMap_[ins_addr];
  auto rtl = get<0>(t);
  if(rtl == NULL) return used_regs;
  auto pattern = new Mem(Expr::EXPR_MODE::NONE, NULL);
  auto vec = rtl->find(RTL::RTL_EQUAL::OPCODE,pattern);
  for(auto & v : vec) {
    auto list = v->readsReg();
    used_regs.insert(list.begin(), list.end());
  }
  delete pattern;
  return used_regs;
}

string
LiftedProg::memWriteExpr(uint64_t ins_addr) {
  if(progRtlMap_.find(ins_addr) == progRtlMap_.end()) return "";
  auto t = progRtlMap_[ins_addr];
  auto rtl = get<0>(t);
  if(rtl == NULL) return "";
  if(rtl->rtl_type() == RTL::RTL_TYPE::STATEMENT) {
    auto copy = dynamic_cast<Assign *>(rtl);
    if (copy == NULL) return "";
    auto dst = copy->dst();
    if(dst->expr_type() == Expr::EXPR_TYPE::VAR) {
      auto m = dynamic_cast<Mem *>(dst);
      if(m == NULL) return "";
      auto regs = m->readsReg();
      if(regs.size() > 0)
        return regs[0];
      else return "mem";
    }
  }
  return "";
}

string
LiftedProg::sourceReg(uint64_t ins_addr) {
  if(progRtlMap_.find(ins_addr) == progRtlMap_.end()) return "";
  auto t = progRtlMap_[ins_addr];
  auto rtl = get<0>(t);
  if(rtl == NULL) return "";
  if(rtl->rtl_type() == RTL::RTL_TYPE::STATEMENT) {
    auto copy = dynamic_cast<Assign *>(rtl);
    if (copy == NULL) return "";
    auto src = copy->src();
    if(src->expr_type() == Expr::EXPR_TYPE::VAR) {
      auto m = dynamic_cast<Reg *>(src);
      if(m == NULL) return "";
      auto regs = m->readsReg(); 
      if(regs.size() > 0)
        return regs[0];
      else return "mem";
    }
  }
  return "";
}

string
LiftedProg::taintedSourceReg(uint64_t ins_addr) {
  if(progRtlMap_.find(ins_addr) == progRtlMap_.end()) return "";
  auto t = progRtlMap_[ins_addr];
  auto rtl = get<0>(t);
  if(rtl == NULL) return "";
  if(rtl->rtl_type() == RTL::RTL_TYPE::STATEMENT) {
    auto copy = dynamic_cast<Assign *>(rtl);
    if (copy == NULL) return "";
    auto src = copy->src();
    if(src->expr_type() == Expr::EXPR_TYPE::VAR) {
      auto m = dynamic_cast<Reg *>(src);
      if(m == NULL) {
        auto m = dynamic_cast<Mem *>(src);
	if(m == NULL) return "";
        auto regs = m->readsReg();
	if(regs.size() > 0)
          return regs[0];
	else return "mem";
      }
      else {
        auto regs = m->readsReg();
        return regs[0];
      }
    }
  }
  return "";
}

TempState blankState() {
  TempState state;
  for(auto i = 0; i < 16; i++) {
    RegVal r;
    r.val = (RegValType)(i + 4);
    state.regState.push_back(r);
  }
  return state;
}
static inline void to_lower(std::string& s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return char(std::tolower(c)); });
}

static inline void strip_leading_percent(std::string& s) {
    if (!s.empty() && s.front() == '%') s.erase(0, 1);
}

/// Normalize any part of {rax,rbx,rcx,rdx,rsp,rbp,rsi,rdi} to the 16-bit base reg.
/// Returns std::nullopt if the input isn't one of these GPRs.
string to_base16_gpr(std::string name) {
    // Trim spaces
    auto notspace = [](int ch){ return !std::isspace(ch); };
    name.erase(name.begin(), std::find_if(name.begin(), name.end(), notspace));
    name.erase(std::find_if(name.rbegin(), name.rend(), notspace).base(), name.end());

    strip_leading_percent(name);
    to_lower(name);

    static const std::unordered_map<std::string, std::string> lut = {
        // rax family
        {"rax","ax"}, {"eax","ax"}, {"ax","ax"}, {"al","ax"}, {"ah","ax"},
        // rbx family
        {"rbx","bx"}, {"ebx","bx"}, {"bx","bx"}, {"bl","bx"}, {"bh","bx"},
        // rcx family
        {"rcx","cx"}, {"ecx","cx"}, {"cx","cx"}, {"cl","cx"}, {"ch","cx"},
        // rdx family
        {"rdx","dx"}, {"edx","dx"}, {"dx","dx"}, {"dl","dx"}, {"dh","dx"},
        // rsp family
        {"rsp","sp"}, {"esp","sp"}, {"sp","sp"}, {"spl","sp"},
        // rbp family
        {"rbp","bp"}, {"ebp","bp"}, {"bp","bp"}, {"bpl","bp"},
        // rsi family
        {"rsi","si"}, {"esi","si"}, {"si","si"}, {"sil","si"},
        // rdi family
        {"rdi","di"}, {"edi","di"}, {"di","di"}, {"dil","di"},
    };

    if (auto it = lut.find(name); it != lut.end()) return it->second;
    return name; // not one of the handled regs
}

static inline std::string trim(std::string s) {
    auto notspace = [](int ch){ return !std::isspace(ch); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notspace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
    return s;
}

static inline std::string strip_percent(std::string s) {
    return (!s.empty() && s[0] == '%') ? s.substr(1) : s;
}

static inline bool ieq(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (std::tolower(a[i]) != std::tolower(b[i])) return false;
    return true;
}

static std::optional<int64_t> parse_int64(const std::string& s) {
    if (s.empty()) return std::nullopt;
    // Allow +/-, hex 0x..., or decimal
    size_t i = 0; bool neg = false;
    if (s[i] == '+' || s[i] == '-') { neg = (s[i] == '-'); ++i; }
    if (i + 2 <= s.size() && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X')) {
        i += 2;
        if (i >= s.size()) return std::nullopt;
        int64_t val = 0;
        for (; i < s.size(); ++i) {
            char c = s[i];
            int d = (c >= '0' && c <= '9') ? (c - '0') :
                    (c >= 'a' && c <= 'f') ? (c - 'a' + 10) :
                    (c >= 'A' && c <= 'F') ? (c - 'A' + 10) : -1;
            if (d < 0) return std::nullopt;
            val = (val << 4) + d;
        }
        return neg ? -val : val;
    } else {
        // decimal
        int64_t val = 0;
        if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i]))) return std::nullopt;
        for (; i < s.size(); ++i) {
            if (!std::isdigit(static_cast<unsigned char>(s[i]))) return std::nullopt;
            val = val * 10 + (s[i] - '0');
        }
        return neg ? -val : val;
    }
}

ParsedOperand parse_att_indirect_operand(std::string text) {
    ParsedOperand out;

    text = trim(text);
    // Strip mnemonic if user passes "call *%rax" or "jmp *0x10(%rax)"
    auto lower = text; std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (std::string m : {"callq", "call", "jmpq", "jmp"}) {
        if (lower.rfind(m, 0) == 0) {  // starts with mnemonic
            text = trim(text.substr(m.size()));
            break;
        }
    }

    // Leading '*' indicates indirection (required for AT&T call/jmp when not immediate)
    if (!text.empty() && text[0] == '*') {
        out.has_indirection = true;
        text = trim(text.substr(1));
    }

    // Register form: *%rax
    if (!text.empty() && text[0] == '%') {
        out.kind = ParsedOperand::Kind::Register;
        out.reg = strip_percent(text);
        return out;
    }

    // At this point, we expect a memory form:
    // [disp-or-symbol][(base[,index[,scale]])]
    out.kind = ParsedOperand::Kind::Memory;

    // Find parenthesized addressing part, if any
    std::string before, paren;
    size_t lp = text.find('(');
    if (lp == std::string::npos) {
        before = trim(text);
    } else {
        size_t rp = text.rfind(')');
        if (rp == std::string::npos || rp < lp) {
            out.kind = ParsedOperand::Kind::Invalid;
            return out;
        }
        before = trim(text.substr(0, lp));
        paren  = trim(text.substr(lp + 1, rp - lp - 1)); // inside (...)
    }

    // Parse displacement/symbol before parentheses
    if (!before.empty()) {
        // If it's numeric, store as disp; otherwise treat as symbol (covers foo, foo@GOTPCREL, +/-prefixed numbers with spaces handled earlier)
        if (auto d = parse_int64(before)) out.disp = *d;
        else out.symbol = before; // leave verbatim
    }

    // Parse (base,index,scale)
    if (!paren.empty()) {
        // Split by commas (up to 3 parts)
        std::vector<std::string> parts;
        size_t start = 0;
        while (start <= paren.size()) {
            size_t comma = paren.find(',', start);
            std::string tok = trim(paren.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
            parts.push_back(tok);
            if (comma == std::string::npos) break;
            start = comma + 1;
        }

        if (!parts.empty() && !parts[0].empty()) {
            out.base = strip_percent(parts[0]);
        }
        if (parts.size() >= 2 && !parts[1].empty()) {
            out.index = strip_percent(parts[1]);
        }
        if (parts.size() >= 3 && !parts[2].empty()) {
            if (auto s = parse_int64(parts[2])) {
                int sc = static_cast<int>(*s);
                if (sc == 1 || sc == 2 || sc == 4 || sc == 8) out.scale = sc;
                else out.kind = ParsedOperand::Kind::Invalid; // illegal scale
            } else {
                out.kind = ParsedOperand::Kind::Invalid;
            }
        }
    }

    // Normalize base/index names to lowercase and detect RIP-relative
    auto norm = [](std::optional<std::string>& r) {
        if (!r) return;
        for (auto& c : *r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    };
    norm(out.base);
    norm(out.index);
    if (out.base && ieq(*out.base, "rip")) out.rip_relative = true;

    return out;
}

//struct ParsedOperand {
//    enum class Kind { Register, Memory, Invalid } kind = Kind::Invalid;
//
//    // For Kind::Register
//    std::string reg;          // e.g. "rax"
//
//    // For Kind::Memory
//    std::optional<std::string> base;   // e.g. "rax", "rip"
//    std::optional<std::string> index;  // e.g. "rbx"
//    int scale = 1;                      // 1,2,4,8 (default 1 if omitted)
//    std::optional<int64_t> disp;        // numeric displacement if present and numeric
//    std::optional<std::string> symbol;  // symbolic displacement (e.g. "foo", "foo@GOTPCREL")
//    bool rip_relative = false;          // true if base == rip
//    bool has_indirection = false;       // true if operand had leading '*'
//};
int regInd(string reg) {
  int ind = -1;
  for (auto & r : utils::gprSuffixes) {
    if(r == reg) return (ind + 1);
    ind++;
  }
  ind = -1;
  for (auto & r : utils::gpr) {
    if(r.find(reg) != string::npos) return (ind + 1);
    ind++;
  }
  return -1;
}

string regName(string reg) {
  auto ind = regInd(reg);
  if (ind == -1) return "";
  auto name = utils::gpr[ind];
  if(name.find("%") == 0) name = name.replace(0,1,"");
  return name;
}


string
DataFlow::escapesInThisIns(Instruction *ins, string & reg, 
		           unordered_set <uint64_t> known_escape_sites) {
  if(known_escape_sites.find(ins->location()) != known_escape_sites.end())
    return "";
  string res = "";
  //cout<<"Checking if reg escapes at INS: "<<reg<<" "<<hex<<ins->location()<<endl;
  //auto inp_regs = LiftedProg::taintedSourceReg(ins->location());
  auto i_reg = LiftedProg::taintedSourceReg(ins->location());
  if(i_reg.size() <= 0 || i_reg =="mem") return "";
  //for(auto & i_reg : inp_regs) {
    auto full_reg_name = regName(i_reg);
    if(full_reg_name == reg) {
      if(ins->isIndirectCf()) {
        res = "escaped";
	return res;
      }
      else {
        auto out_regs = LiftedProg::regsWrittenByIns(ins->location());
        if(out_regs.size() <= 0) {
	  auto mem_write = LiftedProg::memWriteExpr(ins->location());
	  if(mem_write.size() <= 0) return "";
	  else if(mem_write.find("sp") != string::npos) return "rsp";
	  else if(mem_write.size() > 0) {
	    cout<<"Reg "<<reg<<" escapes to memory at: "<<hex<<ins->location()<<" "<<ins->asmIns()<<endl;
            res = "escaped";
            return res;
	  }
	  else return "";
        }
        else {
	  auto out = regName(out_regs[0]);
	  if(out == "") {
	    cout<<"Clobbered..our reg not gpr: "<<out_regs[0]<<endl;
	    return "hard clobber";
	  }
	  cout<<"New tgt reg: "<<out<<endl;
	  return out;
	}
      }
    }
  //}
  auto out_regs = LiftedProg::regsWrittenByIns(ins->location());
  for(auto & o_reg : out_regs) {
    auto full_reg_name = regName(o_reg);
    if(full_reg_name == reg) return "soft clobbered";
  }
  return res;
}

string
DataFlow::escapesInThisBB(BasicBlock *bb, string reg, 
		          unordered_set <uint64_t> known_escape_sites) {
  //cout<<"Checking if reg escapes in bb: "<<reg<<" "<<hex<<bb->start()<<endl;
  string res = "";
  auto ins_list = bb->insList();
  for(auto & ins : ins_list) {	  
    if(ins->asmIns().find("ret") != string::npos && reg.find("ax") != string::npos) {
      cout<<"Reg "<<reg<<" escapes to return val at: "<<hex<<ins->location()<<endl;
      return "escaped";
    }
    unordered_set<string> args_reg = {"rdi","rsi","rcx","rdx","rcx","r8","r9"};
    if(ins->isIndirectCf() && known_escape_sites.find(ins->location()) == known_escape_sites.end()) {
      if(bb->indirectTgts().size() > 0) return reg;
      if(args_reg.find(reg) != args_reg.end() || ins->asmIns().find(reg) != string::npos) {
        cout<<"Reg "<<reg<<" escapes to indirect function at: "<<hex<<ins->location()<<" "<<ins->asmIns()<<endl;
        return "escaped";
      }
    }
    auto ins_res = escapesInThisIns(ins, reg, known_escape_sites);
    if(ins_res.size() <= 0) continue;
    else if(ins_res.find("clobber") != string::npos) return ins_res;
    else if(ins_res == "escaped") {
      return ins_res;
    }
    else {
      reg = ins_res;
    }
  }
  res = reg;
  return res;
}

bool
DataFlow::escapeAnalysisDFS(BasicBlock *bb, string reg, 
		            unordered_set <uint64_t> &checked,
			    unordered_set <uint64_t> known_escape_sites) {
  if(checked.find(bb->start()) != checked.end()) return false;
  checked.insert(bb->start());
  auto res = escapesInThisBB(bb, reg, known_escape_sites);
  if(res == "escaped") return true;
  else if(res.find("clobber") != string::npos) return false;
  else if (res.size() > 0) reg = res;
  if(bb->targetBB() != NULL) {
    if(bb->isCall()) {
      //unordered_set<string> args_reg = {"di","si","cx","dx","cx","r8","r9"};
      unordered_set<string> args_reg = {"rdi","rsi","rcx","rdx","rcx","r8","r9"};
      if(args_reg.find(reg) != args_reg.end()) {
        auto res = escapeAnalysisDFS(bb->targetBB(), reg, checked, known_escape_sites);
        if(res == true) return true;
      }
    }
    else {
      auto res = escapeAnalysisDFS(bb->targetBB(), reg, checked, known_escape_sites);
      if(res == true) return true;
    } 
  }
  if(bb->fallThroughBB() != NULL) {
    auto res = escapeAnalysisDFS(bb->fallThroughBB(), reg, checked, known_escape_sites);
    if(res == true) return true; 
  }
  auto ind_tgts = bb->indirectTgts();
  for(auto & t : ind_tgts) {
    auto res = escapeAnalysisDFS(t, reg, checked, known_escape_sites);
    if(res == true) return true; 
  }
  return false;
}

bool
DataFlow::escapes(string reg, uint64_t start_loc, unordered_set<uint64_t> known_escape_sites) {
  cout<<"Checking if reg escapes: "<<reg<<endl;
  auto bb = cfg_->withinBB(start_loc);
  if(bb != NULL) {
    auto ins_list = bb->insList();
    for(auto & ins : ins_list) {
      if(ins->location() > start_loc) {
	auto res = escapesInThisIns(ins, reg, known_escape_sites);
        if(res == "escaped") return true; 
        else if(res.find("clobber") != string::npos) return false;
        else if (res.size() > 0) reg = res;
      }
    }
    unordered_set <uint64_t> checked;
    if(bb->targetBB() != NULL) {
      if(bb->isCall()) {
        unordered_set<string> args_reg = {"rdi","rsi","rcx","rdx","rcx","r8","r9"};
        if(args_reg.find(reg) != args_reg.end()) {
          auto res = escapeAnalysisDFS(bb->targetBB(), reg, checked, known_escape_sites);
          if(res == true) return true;
        }
      }
      else {
        auto res = escapeAnalysisDFS(bb->targetBB(), reg, checked, known_escape_sites);
        if(res == true) return true;
      } 
    }
    if(bb->fallThroughBB() != NULL) {
      auto res = escapeAnalysisDFS(bb->fallThroughBB(), reg, checked, known_escape_sites);
      if(res == true) return true; 
    }
  }
  return false;
}

string
DataFlow::raxUseInBB(BasicBlock *bb, unordered_set<uint64_t> & checked) {
  if (checked.find(bb->start()) != checked.end()) return "U";
  checked.insert(bb->start());
  auto ins_list = bb->insList();
  for(auto & ins : ins_list) {
    auto regs_read = LiftedProg::regsReadByIns(ins->location());
    for(auto & r : regs_read) if (r == "ax") return "R";
    auto regs_written = LiftedProg::regsWrittenByIns(ins->location());
    for(auto & r : regs_written) if (r == "ax") return "W";
  }
  if(bb->isCall()) return "U";
  string tgt_status = "U", fall_status = "U";
  if(bb->targetBB() != NULL) tgt_status = raxUseInBB(bb->targetBB(), checked);
  if(bb->fallThroughBB() != NULL) fall_status = raxUseInBB(bb->fallThroughBB(), checked);

  if(tgt_status == "R" && fall_status != "W") return "R";
  if(fall_status == "R" && tgt_status != "W") return "R";

  if(tgt_status == "W" || fall_status == "W") return "W";

  return "U";
}

void
DataFlow::callSiteRetType(FuncInfo *info) {
  unordered_map<uint64_t, bool> ret_type_map;
  for (auto & cs : info->callSiteInfo_) {
    auto fall = cs->fall;
    if (fall != NULL) {
      unordered_set <uint64_t> checked;
      auto fall_status = raxUseInBB(fall, checked);
      if(fall_status == "R") cs->expectsRetVal_ = true;
    }
  }
}


void 
DataFlow::usedArgsInBB(BasicBlock *bb, unordered_map<string, string> &reg_status_map) {
  unordered_set<string> args_reg = {"rdi","rsi","rcx","rdx","rcx","r8","r9"};
  auto ins_list = bb->insList();
  for(auto & ins : ins_list) {
    auto regs_read = LiftedProg::regsReadByIns(ins->location());
    //cout<<"Regs read by ins: "<<hex<<ins->location()<<endl;
    for(auto & r : regs_read) {
      auto rname = regName(r);
      if(rname == "") continue;
      //cout<<r<<" "<<rname<<endl;
      if (args_reg.find(rname) != args_reg.end() && reg_status_map.find(rname) == reg_status_map.end()) {
        reg_status_map[rname] = "R";
      }
    }
    auto regs_written = LiftedProg::regsWrittenByIns(ins->location());
    //cout<<"Regs written by ins: "<<hex<<ins->location()<<endl;
    for(auto & r : regs_written) {
      auto rname = regName(r);
      if(rname == "") continue;
      //cout<<r<<" "<<rname<<endl;
      if (args_reg.find(rname) != args_reg.end() && reg_status_map.find(rname) == reg_status_map.end()) {
        reg_status_map[rname] = "W";
      }
    }
  }

  for(auto & r : args_reg) {
    if(reg_status_map.find(r) == reg_status_map.end()) reg_status_map[r] = "U";
  }
}

unordered_set<string>
DataFlow::memAccessInBB(BasicBlock *bb, unordered_set<string> &source_regs) {
  auto ins_list = bb->insList(); 
  unordered_set<string> res;
  for(auto & ins : ins_list) {
    auto regs_used = LiftedProg::regsUsedInDeref(ins->location());
    for(auto & r : regs_used) {
      auto val = getBaseLHValAt(r, ins->location());
      if (val != NULL && !val->top() && !val->notlocal()) {
        auto base = val->base();
        auto const& range = val->range();
        if(base > X86_64::NUM_REG || base <= 0 || base == 0x11) { 
          //cout<<"\tMem access with const or unknown pointer"<<endl;
        }
        else {
          auto dep_reg = X86_64::to_string((X86_64::REG)base);
          //cout<<"\t"<<r<<": "<<hex<<base<<" - "<<dep_reg<<endl;
	  auto full_reg_name = regName(dep_reg);
	  if(source_regs.find(full_reg_name) != source_regs.end()) {
	    res.insert(full_reg_name);
	  }
        }
      }
      else {
        //cout<<"\tTracking reg val is TOP or unknown"<<endl;
      }
    }
  }
  return res;
}

void
DataFlow::assignType(unordered_map <string, string> &reg_map) {
  cout<<"Assigning argument type in function: "<<hex<<entry_->start()<<endl;
  auto bb_list = getAllBBs();
  unordered_set <string> source_regs;
  for(auto & r : reg_map) {
    if(r.second == "R") {
      source_regs.insert(r.first);
    }
  }
  for(auto & bb : bb_list) {
    auto res = memAccessInBB(bb, source_regs);
    for(auto & r : res) {
      if(reg_map[r] == "R") reg_map[r] = "pointer";
    }
  }
}

unordered_map <string, string>
DataFlow::usedArgsDfs(BasicBlock *bb, unordered_set <uint64_t> &checked, int call_depth = 0) {
  unordered_map <string, string> res, tgt_res, fall_res;
  unordered_set<string> args_reg = {"rdi","rsi","rcx","rdx","rcx","r8","r9"};
  if(checked.find(bb->start()) != checked.end()) return res;
  checked.insert(bb->start());
  usedArgsInBB(bb, res);
  if(bb->lastIns()->isCall()) {
    if (bb->target() != 0 && call_depth < 2) {
      auto callee = LiftedProg::getLiftedFn(bb->target());
      if(callee->info() == NULL) callee->collectBasicInfo();
      tgt_res = callee->usedArgs(call_depth + 1);

      for(auto & cs : info_->callSiteInfo_) {
	if(cs->location == bb->lastIns()->location()) {
	  for(auto & r : args_reg) {
	    auto ind = regInd(r);
	    auto v = cs->state.regState[regInd(r)].val;
	    if (v != RegValType::UNKNOWN &&
	        v != RegValType::POINTER &&
	        v != RegValType::CONSTANT &&
	        v != RegValType::VARINT) {
	      auto ind = (int)v - 4;
	      auto dep_reg = utils::gpr[ind];
	      dep_reg = dep_reg.replace(0,1,"");
	      if(args_reg.find(dep_reg) != args_reg.end() && 
	         tgt_res.find(dep_reg) != tgt_res.end()) {
	        if(tgt_res[dep_reg] != "W" && tgt_res[dep_reg] != "U")
		  res[dep_reg] = tgt_res[dep_reg];
	      }
	    }
	  } 
	  break;
	}
      }
    }
    if(bb->fallThroughBB() != NULL) {
      fall_res = usedArgsDfs(bb->fallThroughBB(), checked, call_depth);
      for(auto & r : fall_res) {
	if(res[r.first] == "U") res[r.first] = r.second;
      }
    }
    return res;
  }
  bool all_covered = true;
  for(auto & r : res) {
    if(r.second == "U") {
      all_covered = false;
      break;
    }
  }
  if(all_covered == false) {
    if(bb->lastIns()->isCall() == false && bb->target() != 0) 
      tgt_res = usedArgsDfs(bb->targetBB(), checked, call_depth);
    if(bb->fallThroughBB() != NULL) 
      fall_res = usedArgsDfs(bb->fallThroughBB(), checked, call_depth);
    
    //cout<<"Merging arg status at BB: "<<hex<<bb->start()<<endl;
    
    for(auto & r : args_reg) {
      if(res[r] == "U") {
	if(tgt_res.find(r) != tgt_res.end()) {
	  res[r] = tgt_res[r];
	}
	if(res[r] != "W" && fall_res.find(r) != fall_res.end()) {
	  if(fall_res[r] == "W" || fall_res[r] == "U") res[r] = fall_res[r];
	  else if(res[r] == "R") res[r] = fall_res[r];
	}
      }
      //cout<<"\t final: "<<res[r]<<endl;
    }
    auto ind_tgts = bb->indirectTgts();
    int ctr = 0;
    for(auto & t : ind_tgts) {
      auto ind_res = usedArgsDfs(t, checked, call_depth);
      ctr += 1;
      for(auto & r : ind_res) {
        //cout<<"From ind: "<<r.second<<endl;
	if(res[r.first] != "W") {
          if(r.second == "W" || r.second == "U" || ctr == 1) res[r.first] = r.second;
	  else if(res[r.first] == "R") res[r.first] = r.second;
	}
      }
    }
  }
  return res;
}

unordered_map<string, string>
DataFlow::usedArgs(int call_depth = 0) {
  //cout<<"Getting used args data for "<<hex<<entry_->start()<<" call depth "<<call_depth<<endl;
  if(usedArgsStats_.find(call_depth) != usedArgsStats_.end()) return usedArgsStats_[call_depth];
  unordered_set<uint64_t> checked;
  unordered_map<string, string> res;
  if(call_depth >= 2) return res;
  res = usedArgsDfs(entry_, checked, call_depth);
  bool read = false;
  for(auto & r : res) {
    if(r.second == "R") {
      read = true;
      break;
    }
  }
  if(read)
    assignType(res);
  usedArgsStats_[call_depth] = res;
  //if(call_depth == 0) {
  //  usedArgsStatsDone_ = true;
  //  usedArgsStats_ = res;
  //}
  clear();
  return res;
}

//CFPattern
//DatFlow::formCFPattern(Instruction *ins) {
//  if(ins->asmIns().find("rip") != string::npos || ins->asmIns().find("sp") != string::npos)
//    return false;
//  auto rtl = LiftedProg::getRtl(ins->location());
//  if(rtl == NULL) return false;
//  auto tgt = rtl->target();
//  auto addr = tgt->addr();
//  if(addr->var_type() == Var::VAR_TYPE::MEM) {
//  }
//  else if(addr->var_type() == Var::VAR_TYPE::REG) {
//  }
//  
//}

unordered_map <uint64_t, IndCFInfo *> cf_expr;

IndCFInfo *
DataFlow::indirectCFExpr(uint64_t cf_loc) {
  if(cf_expr.find(cf_loc) != cf_expr.end()) return cf_expr[cf_loc];
  getBaseLHHandler();
  auto f = baseLHFunc_;
  uint64_t base = 0;
  uint64_t stride = 0;
  cout<<"Jump loc: "<<hex<<cf_loc<<endl;
  IndCFInfo *info = new IndCFInfo();
  for (auto [jump_loc, expr]: f->target_expr) {
    if (jump_loc == cf_loc) {
      for (BaseStride* X = expr; X != nullptr; X = X->next_value()) {
        cout<<"\tDynamic: "<<X->dynamic()<<endl;
        cout<<"\tCst: "<<X->cst()<<endl;
        cout<<"\tMem: "<<X->mem()<<endl;
        cout<<"\tNMem: "<<X->nmem()<<endl;
        auto b = (IMM)X->base();
        auto s = (IMM)X->stride();
	base = b;
	stride = s;
        cout<<"\tBase: "<<hex<<b<<endl;
        cout<<"\tStride: "<<hex<<s<<endl;
	if (X->nmem()) {
	  PtrTable t;
	  if(s > 1 || s < -1) t.stride = s;
	  if(b > 0 && cfg_->getBB(b) != NULL) { 
	    t.location = b;
	    t.kind = PtrTable::Kind::CodeTab;
	    info->table.push_back(t);
	  }
	}
	else if(X->mem()) {
	  PtrTable t;
	  if(s == 8) t.stride = s;
	  if(b > 0 && cfg_->ptr(b) != NULL) { 
	    t.location = b;
	    t.kind = PtrTable::Kind::DataTab;
	    info->table.push_back(t);
	  }
	}
      }
    }
  }
  if (info->table.size() <= 0) {
    auto bb_list = getAllBBs();
    for(auto & bb : bb_list) {
      if(bb->lastIns()->location() == cf_loc) {
	auto ins = bb->lastIns();
	auto op = ins->op1();
	auto parsed_op = parse_att_indirect_operand(op);
	string track_reg = "";
	if (parsed_op.kind == ParsedOperand::Kind::Memory) {
	  track_reg = (parsed_op.base? ""+*parsed_op.base: "(none)");
	  info->kind = IndCFInfo::Kind::Memory;
	}
	else {
	  track_reg = parsed_op.reg;
	  //cout<<"\tRegister target: "<<parsed_op.reg<<endl;
	  info->kind = IndCFInfo::Kind::Register;
	}
        track_reg = to_base16_gpr(track_reg);
	auto val = getBaseLHValAt(track_reg, cf_loc);
        if (val != NULL && !val->top() && !val->notlocal()) {
          auto base = val->base();
          auto const& range = val->range();
	  if (base == 0 || base == 0x11) {
	    if (range.lo() == range.hi()) {
              info->rval.val = RegValType::CONSTANT;
              info->rval.addend.push_back(range.lo());
	    }
	    else {
	      if (base == 0x11) {
	        if (cfg_->withinCodeSec(range.lo())) {
	          for(auto lo = range.lo(); lo < range.hi(); lo++) {
	            if(cfg_->ptr(lo) != NULL) {
	              info->rval.val = RegValType::CONSTANT;
                      info->rval.addend.push_back(range.lo());
	            }
	          }
	        }
	        else {
	          info->rval.val = RegValType::CONSTANT;
                  info->rval.addend.push_back(range.lo());
	        }
	      }
	      else info->rval.val = RegValType::VARINT;
	    }
          }
          else if(base > X86_64::NUM_REG || base < 0) { // Some arithmetic..potentially not pointer
            //cout<<"\tTracking reg val is unknown -- base > NUM_REG"<<endl;
            info->rval.val = RegValType::UNKNOWN;
          }
          else {
            auto dep_reg = X86_64::to_string((X86_64::REG)base);
            //cout<<"\t"<<track_reg<<": "<<hex<<base<<" - "<<dep_reg<<endl;
	    if(dep_reg == "sp" || range.lo() != 0 || range.hi() != 0)
              info->rval.val = RegValType::UNKNOWN;
	    else
              info->rval.val = (RegValType)(regInd(dep_reg) + 4);
          }
	}
	else { 
	  //cout<<"\tTracking reg val is TOP or unknown"<<endl;
          info->rval.val = RegValType::UNKNOWN;
	}
      }
    }
  }
  cf_expr[cf_loc] = info;
  return info;
}

bool
DataFlow::isFunctionEntry(uint64_t entry) {
  auto fn_map = cfg_->funcMap();
  auto fn = is_within(entry,fn_map);
  if(fn != fn_map.end()) {
    if(fn->second->entryExists(entry)) {
      //cout<<"Entry exists: "<<hex<<entry<<" function: "<<hex<<fn->first<<endl;
      return true;
    }
  }
  return false;
}

unordered_map <uint64_t, TempState> call_site_state;

void
DataFlow::updateCallSiteRegState(CallSite *cs, string &reg, BaseLH *val) {
  if (val != NULL && !val->top() && !val->notlocal()) {
    auto base = val->base();
    auto const& range = val->range();
    if (base == 0 || base == 0x11) {
      if (range.lo() == range.hi()) {
        if (cfg_->ptr(range.lo()) != NULL) {
          cs->state.regState[regInd(reg)].val = RegValType::CONSTANT;
          cs->state.regState[regInd(reg)].addend.push_back(range.lo());
        }
        else cs->state.regState[regInd(reg)].val = RegValType::VARINT;
      }
      else {
        if (base == 0x11) {
          if (cfg_->withinCodeSec(range.lo())) {
            for(auto lo = range.lo(); lo < range.hi(); lo++) {
              if(cfg_->ptr(lo) != NULL) {
                cs->state.regState[regInd(reg)].val = RegValType::CONSTANT;
                cs->state.regState[regInd(reg)].addend.push_back(range.lo());
      	      }
            }
          }
          else {
            cs->state.regState[regInd(reg)].val = RegValType::CONSTANT;
            cs->state.regState[regInd(reg)].addend.push_back(range.lo());
          }
        }
        else cs->state.regState[regInd(reg)].val = RegValType::VARINT;
      }
    }
    else if(base > X86_64::NUM_REG || base < 0) { // Some arithmetic..potentially not pointer
      cs->state.regState[regInd(reg)].val = RegValType::UNKNOWN;
    }
    else {
      auto dep_reg = X86_64::to_string((X86_64::REG)base);
      if(dep_reg == "sp")
        cs->state.regState[regInd(reg)].val = RegValType::POINTER;
      else if(range.lo() != 0 || range.hi() != 0) {
        cs->state.regState[regInd(reg)].val = (RegValType)(regInd(dep_reg) + 4);
        cs->state.regState[regInd(reg)].addend.push_back(range.lo());
      }
      else
        cs->state.regState[regInd(reg)].val = (RegValType)(regInd(dep_reg) + 4);
    }
  }
  else {
    cs->state.regState[regInd(reg)].val = RegValType::UNKNOWN;
  }
}

void
DataFlow::getCallArgState(vector<CallSite *> &cs_list) {
  vector<string> args_reg = {"di","si","cx","dx","cx","r8","r9"};
  
//DataFlow::getBaseLHValAt(unordered_map<uint64_t, vector <string>> &track_map) {
  
  unordered_map<uint64_t, vector<string>> track_map;
  for(auto & cs : cs_list) {
    auto call_loc = cs->location;
    if(call_site_state.find(call_loc) != call_site_state.end()) cs->state = call_site_state[call_loc];
    else cs->state = blankState();
    for(auto & reg : args_reg) {
      if(cs->state.regState[regInd(reg)].val == RegValType::CONSTANT ||
         cs->state.regState[regInd(reg)].val == RegValType::VARINT ||
         cs->state.regState[regInd(reg)].val == RegValType::POINTER)
        continue;
      track_map[call_loc].push_back(reg);
    }
  }
  auto res = getBaseLHValAt(track_map);

  for(auto & cs : cs_list) {
    if(res.find(cs->location) != res.end()) {
      auto reg_val_map = res[cs->location];
      for(auto & r : reg_val_map) {
	auto reg = r.first;
	auto val  = r.second;
	updateCallSiteRegState(cs, reg, val);
      }
    }
    call_site_state[cs->location] = cs->state;
  }
}

void
DataFlow::getCallArgsState(CallSite *cs) {
  vector<string> args_reg = {"di","si","cx","dx","cx","r8","r9"};
  auto call_loc = cs->location;
  if(call_site_state.find(call_loc) != call_site_state.end()) cs->state = call_site_state[call_loc];
  else cs->state = blankState();
  //cout<<"Getting call site args: "<<hex<<call_loc<<" function: "<<hex<<entry_->start()<<endl;
  for(auto & reg : args_reg) {
    if(cs->state.regState[regInd(reg)].val == RegValType::CONSTANT ||
       cs->state.regState[regInd(reg)].val == RegValType::VARINT ||
       cs->state.regState[regInd(reg)].val == RegValType::POINTER)
      continue;
    auto val = getBaseLHValAt(reg, call_loc);
    updateCallSiteRegState(cs, reg, val);
  }
  call_site_state[call_loc] = cs->state;
}

FuncInfo * 
DataFlow::getFuncInfo() {
  collectInfo();
  return info_;
}

unordered_set <uint64_t>
DataFlow::knownCodePtrUsagePoints(FuncInfo *info, uint64_t used_addrs) {
  unordered_set <uint64_t> res;
  for(auto & cs : info->callSiteInfo_) {
    if(cs->ind != NULL) {
      auto tbl = cs->ind->table;
      for(auto & t : tbl) {
        if(t.location == used_addrs) res.insert(cs->location);
      }
    }
  }
  return res;
}

unordered_map <uint64_t, uint64_t> escaped_addr;
unordered_map <uint64_t, uint64_t> local_addr;

void
DataFlow::addEscapedAddrs(FuncInfo *info, Instruction *ins, uint64_t addrs) {
  cout<<"Checking if pointer escapes: "<<hex<<addrs<<" taken at ins "<<hex<<ins->location()<<endl;
  if(escaped_addr.find(addrs) != escaped_addr.end() && escaped_addr[addrs] == ins->location()) {
    info->escapedAddress_.insert(addrs);
    return;
  }
  if(local_addr.find(addrs) != local_addr.end() && local_addr[addrs] == ins->location()) {
    return;
  }
  if(cfg_->isJmpTbl(addrs)) return;
  if(ins->asmIns().find("ret") != string::npos) return;
  if(ins->isIndirectCf()) {
    if(ins->isPltJmp()) return;
    auto ptrs = cfg_->pointers();
    bool stored_ptr_found = false;
    for(auto & p : ptrs) {
      auto holders = p.second->storages(SymbolType::CONSTANT);
      for(auto & h : holders) {
        if(h == addrs && isFunctionEntry(p.first)) {
          info->escapedAddress_.insert(p.first);
	  stored_ptr_found = true;
	  break;
	}
      }
      if(stored_ptr_found) break;
    }
  }
  //else if(isFunctionEntry(addrs)) info->escapedAddress_.insert(addrs);
  else {
    auto known_usage_points = knownCodePtrUsagePoints(info, addrs);
    auto regs_written = LiftedProg::regsWrittenByIns(ins->location());
    //if(regs_written.size() <= 0) info->escapedAddress_.insert(addrs);
    //else {
    bool escaped = false;
    for(auto & r : regs_written) {
      auto full_reg_name = regName(r);
      if(escapes(full_reg_name, ins->location(),known_usage_points)) {
	escaped_addr[addrs] = ins->location();
        info->escapedAddress_.insert(addrs);
	escaped = true;
        break;
      }
    }
    if(escaped == false) local_addr[addrs] = ins->location();
    //}
  }
}

void
DataFlow::vtableAccess(FuncInfo *info) {
  cout<<"Finding possible vtable stores..."<<endl;
  auto bb_list = getAllBBs();
  for(auto & bb : bb_list) {
    auto ins_list = bb->insList();
    for(auto & ins : ins_list) {
      if(ins->asmIns().find("(%rdi)") == string::npos) continue;
      if(ins->asmIns().find(":") != string::npos) continue;
      cout<<"Checking mem write in :"<<ins->asmIns()<<endl;
      auto mem_write_expr = LiftedProg::memWriteExpr(ins->location());
      if(mem_write_expr.size() == 0) continue;
      cout<<"Mem write: "<<mem_write_expr<<endl;
      auto full_reg_name = regName(mem_write_expr);
      cout<<"Mem write reg: "<<full_reg_name<<endl;
      if(full_reg_name.find("rdi") != string::npos) {
	// Possibly vtable store..get source
	auto src_reg = LiftedProg::sourceReg(ins->location());
	if(src_reg.size() == 0 || src_reg.find("sp") != string::npos) continue;
        auto val = getBaseLHValAt(src_reg, ins->location());
        if (val != NULL && !val->top() && !val->notlocal()) {
          auto base = val->base();
          auto const& range = val->range();
          if (base == 0 || base == 0x11) {
            if (range.lo() == range.hi()) {
	      auto const_op = range.lo();
              if (cfg_->withinRoSection(const_op) || cfg_->withinRWSection(const_op)) {
		info->psblVtable_.insert(const_op);
		info->psblVtable_.insert(const_op + 16);
		info->psblVtable_.insert(const_op - 16);
	      }
	    }
	    else if (base == 0x11) {
	      auto hi = range.hi();
	      auto lo = range.lo();
	      if(hi - lo == 16 || hi - lo == 32) {
		while(lo <= hi) {
		  info->psblVtable_.insert(lo);
		  lo += 16;
		}
	      }
	    }
	  }
	}
      }
    }
  }
}

void
DataFlow::collectATInfo(FuncInfo *info) {
  cout<<"Collecting AT info..."<<endl;
  auto bb_list = getAllBBs();
  for(auto & bb : bb_list) {
    auto ins_list = bb->insList();
    for(auto & ins : ins_list) {
      if(ins->asmIns().find("lea") != string::npos && ins->ripRltvOfft() != 0) {
	uint64_t addrs = ins->ripRltvOfft();
        info->loadsAddress_.insert(addrs);
	addEscapedAddrs(info, ins, addrs);
      }
      else if(ins->constOp() != 0 || ins->constPtr() != 0) {
	auto c_op = ins->constOp() > 0 ? ins->constOp() : ins->constPtr();
	auto p = cfg_->ptr(c_op);
	if(p != NULL && p->addressTaken()) {
	  info->loadsAddress_.insert(c_op);
	  auto addrs = c_op;
	  addEscapedAddrs(info, ins, addrs);
	}
      }
      else if(ins->asmIns().find("mov") != string::npos && ins->ripRltvOfft() != 0) {
        auto op = ins->op1();
	auto words = utils::split_string(op,",");
	if (words.size() > 1) {
	  auto tgt_op = words[1];
	  auto src_op = words[0];
	  if(tgt_op.find("%rip") != string::npos) 
	    info->memWrites_.insert(ins->ripRltvOfft()); 
	  else if(src_op.find("%rip") != string::npos) { 
	    info->readsAddress_.insert(ins->ripRltvOfft());
	    uint64_t addrs = ins->ripRltvOfft();
	    addEscapedAddrs(info, ins, addrs);
	  }
	}
      }
    }
  }
}

void
DataFlow::collectCallsiteInfo(FuncInfo *info) {
  cout<<"Collecting call site info..."<<endl;
  auto bb_list = getAllBBs();

  vector<CallSite *> cs_list;

  for(auto & bb : bb_list) {
    if((bb->lastIns()->isCall() || 
        /*bb->lastIns()->isUnconditionalJmp() ||*/ 
        bb->lastIns()->isIndirectCf()) && 
        bb->lastIns()->asmIns().find("ret") == string::npos) {

      if(bb->target() != 0) {
	if(bb->lastIns()->isCall()/* || isFunctionEntry(bb->target())*/) {
          CallSite * cs_info = new CallSite();
          cs_info->location = bb->lastIns()->location();
	  cs_info->target.insert(bb->target());
	  cs_info->fall = bb->fallThroughBB();
          cs_list.push_back(cs_info);
	}
      }
      else {
        CallSite * cs_info = new CallSite();
        cs_info->location = bb->lastIns()->location();
	cs_info->fall = bb->fallThroughBB();
	cs_info->isIndirect = true;
	if (bb->indirectTgts().size() > 0) {
	  cs_info->jtable = true;
	  cs_info->resolved = true;
	}
	else if(bb->lastIns()->isPltJmp()) {
	  cs_info->pltTarget = bb->lastIns()->pltTarget();
	  cs_info->isIndirect = false;
	  cs_info->resolved = true;
	}
	else if(cfg_->withinPltSec(bb->lastIns()->location())) {
	  cs_info->isIndirect = false;
	  cs_info->resolved = true;
	}
	else {
          if(deeperDetails_)
	    cs_info->ind = indirectCFExpr(bb->lastIns()->location());
	  cs_info->resolved = false;
	}
        cs_list.push_back(cs_info);
      }
    }
  }
  if(deeperDetails_)
    getCallArgState(cs_list);
  for(auto & cs : cs_list) info->callSiteInfo_.push_back(cs);
}

void
DataFlow::collectBasicInfo() {
  if(info_ == NULL) {
    FuncInfo *info = new FuncInfo();
    collectCallsiteInfo(info);
    if(deeperDetails_)
      collectATInfo(info);
    info_ = info;
    if(deeperDetails_) {
      info->ret_ = returnType();
      callSiteRetType(info);
    }
  }
}

void
DataFlow::collectInfo() {
  cout<<"Collecting fn info..."<<endl;
  collectBasicInfo();
  if(deeperDetails_) {
    auto reg_status_map = usedArgs();
    cout<<"Argument register use stat:"<<endl;
    for(auto & r : reg_status_map) cout<<"\t"<<r.first<<" - "<<r.second<<endl;
    info_->argsUse_ = reg_status_map;
  }
  clear();
  //vtableAccess(info);
}

/*
bool
DataFlow::callTgtIsRegPlusImm(Instruction *ins) {
  if(ins->asmIns().find("rip") != string::npos || ins->asmIns().find("sp") != string::npos)
    return false;
  auto rtl = LiftedProg::getRtl(ins->location());
  if(rtl == NULL) return false;
  auto tgt = rtl->target();
  auto addr = tgt->addr();
  if(addr->var_type() == Var::VAR_TYPE::MEM) {
  }
  else if(addr->var_type() == Var::VAR_TYPE::REG) {
  }
}
*/
//vector<VCallSite> 
//DataFlow::detectVcalls() {
//    vector<VCallSite> out;
//
//    // 1) Scan for candidate indirect calls
//    auto bb_list = getAllBBs();
//    for (auto& bb : bb_list) {
//	auto ins_list = bb->insList();
//        for (auto & ins : ins_list) {
//            if (!ins->isIndirectCf()) continue;
//
//            // Pattern A: call [rVptr + SLOT]
//            if (mem_is_reg_plus_imm(ins, /*out*/baseReg, /*out*/slotBytes) && slotBytes % 8 == 0) {
//                // 2) Backward slice to find definition of baseReg as load [recv+off]
//                auto def = find_last_def_of_reg(cfg, bb, i, baseReg,
//                    /*predicate:*/[](const Instr& d, DefInfo& info){
//                        // match "mov rVptr, [recv + off]"
//                        return is_load_from_base_plus_imm(d, /*out*/info.memBaseReg, /*out*/info.memDisp)
//                               && writes_reg(d, info.targetReg);
//                    });
//
//                if (!def.found) continue;
//
//                unsigned recvReg = def.memBaseReg;
//                int      vptrOff = def.memDisp;
//
//                // 3) Confirm ABI: ensure 'this' is in the ABI 1st-arg reg at call
//                unsigned abiThis = X86_REG_RDI; // SysV; use RCX for Win64
//                bool this_ok = (recvReg == abiThis) || 
//                               moved_into_abi_this_before_call(cfg, bb, i, recvReg, abiThis);
//
//                if (!this_ok) continue;  // (optional) or keep but mark weaker confidence
//
//                // 4) Record the site
//                VCallSite site;
//                site.call_addr      = ins.addr;
//                site.vptr_load_addr = def.addr;
//                site.vptr_offset    = vptrOff;
//                site.slot_bytes     = slotBytes;
//                site.slot_index     = slotBytes / 8;
//                site.this_reg       = abiThis;
//                site.vptr_reg       = baseReg;
//                site.recv_reg       = recvReg;
//                out.push_back(site);
//                continue;
//            }
//
//            // Pattern B: retpoline thunk — call __x86_indirect_thunk_rax (etc.)
//            if (is_call_to_indirect_thunk(ins)) {
//                // Backward in-window: look for "mov rT, [rVptr + SLOT]" and earlier "mov rVptr, [recv+off]"
//                auto loadTarget = find_last_def_of_thunk_target(cfg, bb, i, /*out*/tgtReg, /*out*/vptrReg, /*out*/slotBytes);
//                if (!loadTarget.found || slotBytes % 8) continue;
//
//                auto vptrDef = find_last_def_of_reg(cfg, bb, loadTarget.idx, vptrReg,
//                    /*predicate:*/match_mov_from_recv_plus_off);
//
//                if (!vptrDef.found) continue;
//
//                unsigned recvReg = vptrDef.memBaseReg;
//                int vptrOff = vptrDef.memDisp;
//                unsigned abiThis = X86_REG_RDI;
//                bool this_ok = (recvReg == abiThis) ||
//                               moved_into_abi_this_before_call(cfg, bb, i, recvReg, abiThis);
//
//                if (!this_ok) continue;
//
//                VCallSite site{/*fill same as above*/};
//                // ...
//                out.push_back(site);
//            }
//        }
//    }
//    return out;
//}

unordered_map<uint64_t, unordered_map<string, BaseLH *>> 
DataFlow::getBaseLHValAt(unordered_map<uint64_t, vector <string>> &track_map) {
  getBaseLHHandler();
  auto f = baseLHFunc_;//handler->func(entry_->start()); 
  unordered_map<uint64_t, unordered_map<string, BaseLH *>> res;
  for (auto scc: f->scc_list()) {
    for (auto b: scc->block_list()) {
      auto ins_list = b->insn_list();
      for (auto & i : ins_list) {
	if(track_map.find(i->offset()) != track_map.end()) {
	  auto reg_list = track_map[i->offset()];
	  for(auto & reg : reg_list) {
            auto id = get_id(X86_64::to_reg(reg));
            auto vec = f->track(TRACK::BEFORE, id, {f,scc,b,nullptr}, vector<Insn*>{i});
            auto const& aval = vec.front();
            auto const& val = ABSVAL(BaseLH,aval);
	    auto ret = new BaseLH(val);
	    res[i->offset()][reg] = ret; 
	  }
	}
      }
    }
  }
  return res;
}

BaseLH *
DataFlow::getBaseLHValAt(string reg, uint64_t ins_address) {
  getBaseLHHandler();
  auto f = baseLHFunc_;//handler->func(entry_->start());
  bool found_ins = false;
  for (auto scc: f->scc_list()) {
    for (auto b: scc->block_list()) {
      auto ins_list = b->insn_list();
      for (auto & i : ins_list) {
	  //cout<<"Looking at ins: "<<hex<<i->offset()<<endl;
	  if (i->offset() == ins_address) {
            auto id = get_id(X86_64::to_reg(reg));
	    //cout<<"\tRegister ID for tracking: "<<id.i()<<endl;
            auto vec = f->track(TRACK::BEFORE, id, {f,scc,b,nullptr}, vector<Insn*>{i});
            auto const& aval = vec.front();
            auto const& val = ABSVAL(BaseLH,aval);
	    //auto taintval = ABSVAL(Taint,aval);
	    found_ins = true;
	    auto ret = new BaseLH(val);
	    return ret;
	  }
      }
    }
  }
  if(found_ins == false) 
    cout<<"Forward analysis could not find target ins: "<<hex<<ins_address<<endl;
  return NULL;
}

bool
DataFlow::returnType() {
  cout<<"Getting return type for: "<<hex<<entry_->start()<<endl;
  auto bb_list = getAllBBs();
  for(auto & bb : bb_list) {
    if(bb->lastIns()->asmIns().find("ret") != string::npos) {
      auto rax_val = getBaseLHValAt("ax", bb->lastIns()->location()); 
      if(rax_val != NULL) {
	if (rax_val->top() || rax_val->notlocal()) return true;
	auto base = rax_val->base();
	if (base > X86_64::NUM_REG || base < 0) return true;
	if(base != 0) {
	  auto dep_reg = X86_64::to_string((X86_64::REG)base);
	  if(dep_reg == "ax") return false;
	  return true;
	}
	else return true;
      }
      else return false;
    }
  }
  return true;
}

vector <uint64_t> 
DataFlow::getRegValAt(string reg, uint64_t ins_address) {
  vector<uint64_t> res;
  auto val = getBaseLHValAt(reg, ins_address);
  if (val != NULL && !val->top() && !val->notlocal()) {
     auto base = val->base();
     //cout<<"Register base: "<<base<<endl;
     auto const& range = val->range();
     //cout<<"Register range: "<<dec<<range.lo()<<"-"<<range.hi()<<endl;
     if ( base == 0 && range.lo() == range.hi())
       res.push_back(range.lo());
  }
  //else cout<<"Register value is top or not local"<<endl;
  return res;

}

vector <BasicBlock *> 
DataFlow::getAllBBs() {
  if (bbList_.size() > 0) return bbList_;
  else {
    bbList_ = cfg_->AllReachableBasicBlocks(entry_);
    //cout<<"Getting reachable bbs from entry: "<<hex<<entry_->start()<<endl;
    //for(auto & bb : bbList_)
    //  cout<<"BB: "<<hex<<bb->start()<<endl;
  }
  return bbList_;
}

void
DataFlow::getBaseLHHandler() {
  if (baseLHHandler_ == NULL) {
    uint64_t entry = entry_->start();
    
    baseLHHandler_ = LiftedProg::liftFn(entry);//load(vector<int>{entry}, file_name, sizeFile, jtableFile);
    if(baseLHHandler_ == NULL) {
      cout<<"Could not lift function: "<<hex<<entry<<endl;
      bad_ = true;
    }
    else baseLHFunc_ = analyze_function(baseLHHandler_, entry);
  }
}

vector<uint64_t>
DataFlow::getInstructionLocations(string mne) {
  auto bb_list = getAllBBs();
  vector<uint64_t> syscall_ins_list;
  //cout<<"Checking syscall ins"<<endl;
  for(auto & bb : bb_list) {
    auto ins_list = bb->insList();
    for(auto & ins : ins_list) {
      if(ins->asmIns().find(mne) != string::npos)
        syscall_ins_list.push_back(ins->location());
    }
  }

  return syscall_ins_list;
}

vector<uint64_t>
DataFlow::getCallSites(uint64_t callee_addrs) {
  auto bb_list = getAllBBs();
  vector<uint64_t> ins_list;
  for(auto & bb : bb_list) {
    if(bb->target() == callee_addrs) {
      ins_list.push_back(bb->lastIns()->location());
    }
  }

  return ins_list;
}




//void 
//DataFlow::baseLHHandler(AnalysisHandler * h){
//  baseLHHandler_ = h;
//  baseLHFunc_ = analyze_function(h, entry_->start());
//  if (baseLHFunc_ == NULL) bad_ = true;
//  //else collectInfo();
//}

/*
vector<RegVal>
DataFlow::getRegValRecurse(GPR reg, BasicBlock *bb, uint64_t ins_addrs) {
  //processedBBs_.insert(bb->start());
  if(executionCtr_.find(bb->start()) != executionCtr_.end()) {
    executionCtr_[bb->start()] += 1;
  }
  else executionCtr_[bb->start()] = 1;
  auto ins_list = cfg_->insPath(bb, ins_addrs);
  auto state = blankState();
  state = propagateConst(ins_list, state);

  vector<RegVal> res;

  auto v = state.regState[(int)reg];
  if(v.val == RegValType::CONSTANT)
    res.push_back(v);
  else if (v.val != RegValType::CONSTANT && v.val != RegValType::UNKNOWN &&
	   v.val != RegValType::UNDEFINED) {
    cout<<"RAX populated from reg: "<<(int)v.val<<endl;
    for(auto & p : bb->parents()) {
      //if(processedBBs_.find(p->start()) == processedBBs_.end()) {
      if(executionCtr_.find(p->start()) == executionCtr_.end() ||
	 executionCtr_[p->start()] < 2) {
	//if(p->isCall() && p->target() == bb->start()) continue;
	cout<<"Moving to parent: "<<hex<<p->start()<<endl;
        auto v2 = getRegValRecurse(REGVALTYPE_TO_GPR(v.val), p, p->end());
	for(auto & v2_res : v2) {
	  if(v2_res.val != RegValType::CONSTANT) {
	    auto state = blankState();
	    state.regState[(int)reg] = v2_res;
	    state = propagateConst(ins_list, state);
	    res.push_back(state.regState[(int)reg]);
	  }
	  else res.push_back(v2_res);
	}
      }
    }
  }
  return res;  
}
TempState
DataFlow::propagateConst(vector <Instruction *> &ins_list, TempState &state) {
  //cout<<"Starting constant propagation"<<endl;
  for(auto & ins : ins_list){
    //cout<<"Executing INS: "<<ins->location()<<": "<<ins->asmIns()<<endl;
    auto sem = ins->sem();
    auto op_list = sem->OpList;
    for(auto & op : op_list) {
      //cout<<"OP type: "<<(int)op.op<<endl;
      if(op.op == OP::UNKNOWN)
        continue;
      if(op.target.type_ == OperandType::REG && op.target.regNum_ != GPR::NONE &&
         op.target.op_ != OP::DEREF) {
        auto v = state.regState[(int)op.target.regNum_];
        state.regState[(int)op.target.regNum_] = updateState(v, state, op, ins, false);
      }
    }
  }
  return state;
}

RegVal
DataFlow::updateState(RegVal &tgt, TempState &state, Operation &op,
                      Instruction *ins, bool loop_update) {
  if(op.op == OP::STORE) {
    if(op.source1.op_ == OP::DEREF)
       tgt.val = RegValType::UNKNOWN;
    else if(op.source1.type_ == OperandType::REG) {
      auto source_val = state.regState[(int)op.source1.regNum_];
      tgt.val = source_val.val;
      tgt.addend = source_val.addend;
     
    }
    else if(op.source1.type_ == OperandType::CONSTANT) {
      tgt.val = RegValType::CONSTANT;
      tgt.addend = op.source1.constant_;
    }
  }
  else if(op.op == OP::ADD) {
    if((int)tgt.val > (int)RegValType::UNKNOWN) {
      if(op.source1.op_ == OP::DEREF)
        tgt.val = RegValType::UNKNOWN;
      else if(loop_update)
        tgt.val = RegValType::UNKNOWN;
      else if(op.source1.type_ == OperandType::REG) {
        auto source_val = state.regState[(int)op.source1.regNum_];

        if(source_val.val == RegValType::CONSTANT) {
          tgt.addend += source_val.addend;
        }
        else if(source_val.val == RegValType::FRAME_PTR) {
          tgt.val = source_val.val;
          tgt.addend += source_val.addend;
        }
        else if(source_val.val == tgt.val) {
          tgt.val = source_val.val;
          tgt.addend += source_val.addend;
        }
        else
          tgt.val = RegValType::UNKNOWN;
      }
      else if(op.source1.type_ == OperandType::CONSTANT) {
        tgt.addend += op.source1.constant_;
      }
    }
  }
  else if(op.op == OP::SUB) {
    if((int)tgt.val > (int)RegValType::UNKNOWN) {
      if(op.source1.op_ == OP::DEREF)
         tgt.val = RegValType::UNKNOWN;
      else if(loop_update)
        tgt.val = RegValType::UNKNOWN;
      else if(op.source1.type_ == OperandType::REG) {
        auto source_val = state.regState[(int)op.source1.regNum_];

        if(source_val.val == RegValType::CONSTANT) {
          tgt.addend += -1 * (source_val.addend);
        }
        else if(source_val.val == RegValType::FRAME_PTR) {
          tgt.val = source_val.val;
          tgt.addend += -1 * (source_val.addend);
        }
        else if(source_val.val == tgt.val) {
          tgt.val = source_val.val;
          tgt.addend += -1 * (source_val.addend);
        }
        else
          tgt.val = RegValType::UNKNOWN;
      }
      else if(op.source1.type_ == OperandType::CONSTANT) {
        tgt.addend += -1 * (op.source1.constant_);
      }
    }
  }
  else if(op.op == OP::LEA) {
    if(op.source1.type_ == OperandType::RLTV) {
      if(op.source1.ripRltv()) {
        tgt.val = RegValType::CONSTANT;
        tgt.addend = ins->ripRltvOfft();
      }
      else {
        auto source_val = state.regState[(int)op.source1.regNum_];
        tgt.addend = op.source1.constant_ + source_val.addend;
        tgt.val = source_val.val;
      }
    }
  }
  else if(op.op == OP::XOR) {
    //cout<<"XOR op: registers "<<(int)op.source1.regNum_<<" "<<(int)op.target.regNum_<<endl; 
    if(op.source1.regNum_ == op.target.regNum_){
      tgt.val = RegValType::CONSTANT;
      tgt.addend = 0;//ins->ripRltvOfft();
    }
    else
      tgt.val = RegValType::UNKNOWN;
  }
  else if(op.op == OP::OR) {
    if(op.source1.type_ == OperandType::CONSTANT &&
       op.source1.constant_ == 1){
      tgt.val = RegValType::CONSTANT;
      tgt.addend = 1;
    }
    else
      tgt.val = RegValType::UNKNOWN;
  }
  else if(op.op == OP::AND) {
    if(op.source1.type_ == OperandType::CONSTANT &&
       op.source1.constant_ == 0){
      tgt.val = RegValType::CONSTANT;
      tgt.addend = 0;
    }
    else
      tgt.val = RegValType::UNKNOWN;
  }
  return tgt;
}
vector<RegVal>
DataFlow::getRegValAtBackward(GPR reg, uint64_t ins_addrs) {
  auto bb = cfg_->withinBB(ins_addrs);
  if(bb != NULL) {
    //cout<<"Ins bb: "<<hex<<bb->start()<<endl;
    return getRegValRecurse(reg, bb, ins_addrs);
  }
  else {
    cout<<"No BB found for instruction address: "<<hex<<ins_addrs<<endl;
    return {};
  }
}
*/

