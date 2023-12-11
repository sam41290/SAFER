#ifndef INSDICT_H
#define INSDICT_H

#include "libutils.h"
//#include "Instruction.h"

namespace SBI {

  enum class OP {
    NONE,
    DEREF,
    ADD,
    SUB,
    STORE,
    JUMP,
    LEA,
    AND,
    OR,
    XOR,
    UNKNOWN
  };

  enum class OperandType {
    REG,
    CONSTANT,
    NIL,
    RLTV
  };

  enum class GPR {
    REG_RDI = 0,
    REG_RSI,
    REG_RBP,
    REG_RBX,
    REG_RDX,
    REG_RAX,
    REG_RCX,
    REG_RSP,
    REG_R8,
    REG_R9,
    REG_R10,
    REG_R11,
    REG_R12,
    REG_R13,
    REG_R14,
    REG_R15,
    NONE
  };

  
  class Operand {
  public:
    string reg_ = "";
    GPR regNum_ = GPR::NONE;
    int constant_ = 0;
    OP op_ = OP::NONE;
    OperandType type_ = OperandType::NIL;
    GPR regNum (string &reg) {
      if(reg.length() <= 0)
        return GPR::NONE;
      for(unsigned int i = 0; i < utils::gpr.size(); i++)
        if(reg.find(utils::gpr[i]) == 0)
          return (GPR)i;
      return GPR::NONE;
    } 
    void init(int c) {
      constant_ = c;
      type_ = OperandType::CONSTANT;
    }
    void init(string &reg, OperandType t) {
      reg_ = reg;
      type_ = t;
      regNum_ = regNum(reg);
    }
    void init(string &arg) {
      arg = utils::trim(arg);
      if(chkConstOp(arg) == false &&
         chkConstPtr(arg) == false &&
         rltvAccess(arg) == false) {
        auto pos = arg.find(")");
        if(pos != string::npos) {
          auto words = utils::split_string(arg,")");
          if(words[0].find("%")!=string::npos) {
            reg_ = words[0];
            type_ = OperandType::REG;
          }
          else if(words[0].find("0x")!=string::npos) {
            constant_ = stoll(words[0],0,16);
            type_ = OperandType::CONSTANT;
          }
          else if(isNumber(words[0])) {
            constant_ = stoll(words[0],0,10);
            type_ = OperandType::CONSTANT;
          }
        }
        else {
          reg_ = arg;
          type_ = OperandType::REG;
        }

      }
      regNum_ = regNum(reg_);
    }
    bool isNumber(string& str)
    {
        if(str.length() <= 0)
          return false;
        for (char const &c : str) {
          if (std::isdigit(c) == 0) return false;
        }
        return true;
    }
    
    bool isHexNumber(string str)
    {
      if(str.length() <= 0)
        return false;
      if(str.find("0x") == 0)
        str.replace(0,2,"");
      for (unsigned int i=0; i < str.length(); i++)
      {
        if (!isxdigit(str[i])) {
          return false;
        }
      }
      return true;
    }
    bool chkConstOp(string &s) {
      if(s.find("$") == 0) {
        s.replace(0,1,"");
    
        //DEF_LOG("Const op: "<<s);
        if(s.find("0x") != string::npos)
          constant_ = stoull(s,0,16);
        else if(isNumber(s))
          constant_ = stoull(s);
        else if(isHexNumber(s))
          constant_ = stoull(s,0,16);
        type_ = OperandType::CONSTANT;
        return true;
      }
      else if(isHexNumber(s)) {
        //DEF_LOG("hex const ptr: "<<hex<<location()<<": "<<asmIns()<<" const ptr: "<<s);
        constant_ = stoull(s,0,16);
        type_ = OperandType::CONSTANT;
        op_ = OP::DEREF;
        return true;
      }
      else if(isNumber(s)) {
        //DEF_LOG("Dec const ptr: "<<hex<<location()<<": "<<asmIns()<<" const ptr: "<<s);
        //DEF_LOG(s<<" not a hex number");
        constant_ = stoull(s);
        type_ = OperandType::CONSTANT;
        op_ = OP::DEREF;
        return true;
      }
      return false;
    }
    bool chkConstPtr(string &w) {
        if(w.find("(") != string::npos) {
          if(w.find("%") == string::npos) {
            if(w.find("*") == 0)
              w.replace(0,1,"");
            else if(w.find(" ") == 0)
              w.replace(0,1,"");
            w.replace(w.find("("),1,"");
            if(w.length() > 0) {
              if(w.find("0x") != string::npos || utils::checkHex(w))
                constant_ = stoull(w,0,16);
              else
                constant_ = stoull(w);
              type_ = OperandType::CONSTANT;
              op_ = OP::DEREF;
              return true;
            }
          }
        }
        return false;
    }
    bool rltvAccess(string &op1) {
      if(op1.size()> 0) {
      //check for RIP relative access and convert them to labels.
        auto pos = op1.find("(%r");
        if(pos != string::npos) {
          int base = 16;
          auto offset_pos = op1.rfind("0x", pos);
          reg_ = op1.substr(pos + 1,4); 
          if(offset_pos == string::npos) {
            base = 10;
            DEF_LOG("Not sure if offset is hex....considering it decimal"<<op1);
            offset_pos = op1.rfind(".", pos);
            if(offset_pos == string::npos) {
              offset_pos = op1.rfind(" ", pos);
              if(offset_pos == string::npos) {
                offset_pos = op1.rfind(",", pos);
                if(offset_pos == string::npos)
                  offset_pos = 0;
              }
            }
          }
          auto comma_pos = op1.rfind(",", pos);
          if(comma_pos != string::npos && comma_pos > offset_pos && comma_pos < pos)
            offset_pos = comma_pos;
          if(offset_pos != 0) {
            if(op1.substr(offset_pos - 1, 1) == "-") {
              offset_pos = offset_pos - 1;
            }
          }
    
          if(offset_pos == string::npos || pos == string::npos) {
            LOG("incorect RIP parsing: "<<op1);
            exit(0);
          }
          uint64_t offset;
          if((pos - offset_pos) == 0)
            offset = 0;
          else {
            string off = op1.substr(offset_pos, pos - offset_pos);
            try {
              offset = stol(off, 0, base);
            }
            catch(exception & e) {
              LOG("failed to get RIP rltv offset: " <<op1);
              //exit(0);
              offset = 0;
            }
          }
          constant_ = offset;
          type_ = OperandType::RLTV;
          return true;
          //LOG("Ins :"<<hex<<loc_<<" rip offset: "<<hex<<ripRltvOfft_);
        }
        //assm = assm + " " + ins.full_insn[2];
      }
      return false;
    }
    uint64_t constPtr() {
      if(type_ == OperandType::CONSTANT && op_ == OP::DEREF)
        return constant_;
      return 0;
    }
    uint64_t ripRltvOfft() {
      if(type_ == OperandType::RLTV &&
         reg_.find("%rip") != string::npos)
        return constant_;
      return 0;
    }
    bool ripRltv() {
      if(type_ == OperandType::RLTV &&
         reg_.find("%rip") != string::npos)
        return true;
      return false;
    }
  };
  
  struct Operation {
    Operand source1;
    Operand source2;
    //Operand source3;
    Operand target;
    vector <Operand> unknownOperands;
    OP op;
  };
  
  class InsSemantics {
  public:
    vector <Operation> OpList;

    uint64_t target_ = 0;
    bool isJump_ = false;
    bool isCall_ = false;
    bool isLea_ = false;
    bool isIndrctCf_ = false;
    uint64_t ripRltvOfft_ = 0;
    uint64_t constOp_ = 0;
    uint64_t constPtr_ = 0;
    uint64_t fallThrgh_ = 0;
    bool isUnconditionalJmp_ = false;
    bool isRltvAccess_ = false;
    //InsSemantics () {}
    bool isCanaryPrologue() {
      for(auto & opr : OpList) {
        if(opr.op == OP::STORE && opr.target.type_ == OperandType::REG) {
          if(opr.source1.reg_.find("%fs:0x28") != string::npos)
            return true;
        }
      }
      return false;
    }
    bool isCanaryEpilogue() {
      for(auto & opr : OpList) {
        if(opr.op == OP::SUB || opr.op == OP::XOR) {
          if(opr.source1.reg_.find("%fs:0x28") != string::npos ||
             opr.target.reg_.find("%fs:0x28") != string::npos)
            return true;
        }
      }
      return false;
    }
    void init(vector <uint8_t> &hex_bytes, int location) {
      DEF_LOG("Calling InsSemantics constructor");
      fallThrgh_ = location + hex_bytes.size();
      for(auto & opr : OpList) {
        if(opr.source1.type_ == OperandType::CONSTANT){
          DEF_LOG("constant source1: "<<hex<<opr.source1.constant_);
          if(opr.source1.op_ == OP::DEREF)
            constPtr_ = opr.source1.constant_;
          else
            constOp_ = opr.source1.constant_;
        }
        else if(opr.source1.ripRltv()) {
          isRltvAccess_ = true;
          ripRltvOfft_ = opr.source1.constant_ + fallThrgh_;
          DEF_LOG("RIP rltv source1: "<<hex<<ripRltvOfft_);
        }
        if(opr.source2.type_ == OperandType::CONSTANT){
          DEF_LOG("constant source2: "<<hex<<opr.source2.constant_);
          if(opr.source2.op_ == OP::DEREF)
            constPtr_ = opr.source2.constant_;
          else
            constOp_ = opr.source2.constant_;
        }
        else if(opr.source2.ripRltv()) {
          isRltvAccess_ = true;
          ripRltvOfft_ = opr.source2.constant_ + fallThrgh_;
          DEF_LOG("RIP rltv source2: "<<hex<<ripRltvOfft_);
        }
        //if(opr.source3.type_ == OperandType::CONSTANT){
        //  DEF_LOG("constant source3: "<<hex<<opr.source3.constant_);
        //  if(opr.source3.op_ == OP::DEREF)
        //    constPtr_ = opr.source3.constant_;
        //  else
        //    constOp_ = opr.source3.constant_;
        //}
        //else if(opr.source3.ripRltv()) {
        //  isRltvAccess_ = true;
        //  ripRltvOfft_ = opr.source3.constant_ + fallThrgh_;
        //  DEF_LOG("RIP rltv source3: "<<hex<<ripRltvOfft_);
        //}
        if(opr.target.type_ == OperandType::CONSTANT){
          DEF_LOG("constant target: "<<hex<<opr.target.constant_);
          if(opr.target.op_ == OP::DEREF)
            constPtr_ = opr.target.constant_;
          else
            constOp_ = opr.target.constant_;
        }
        else if(opr.target.ripRltv()) {
          isRltvAccess_ = true;
          ripRltvOfft_ = opr.target.constant_ + fallThrgh_;
          DEF_LOG("RIP rltv target: "<<hex<<ripRltvOfft_);
        }
        for(auto & un_op : opr.unknownOperands) {
          if(un_op.type_ == OperandType::CONSTANT){
            DEF_LOG("constant unknown: "<<hex<<opr.source1.constant_);
            if(un_op.op_ == OP::DEREF)
              constPtr_ = un_op.constant_;
            else
              constOp_ = un_op.constant_;
          }
          else if(un_op.ripRltv()) {
            isRltvAccess_ = true;
            ripRltvOfft_ = un_op.constant_ + fallThrgh_;
            DEF_LOG("RIP rltv unknown: "<<hex<<ripRltvOfft_);
          }
        }
      }
    }

  };

  class JUMP : public InsSemantics {
    public:
      JUMP(string &asm_opcode, string &operand, vector <uint8_t> &hex_bytes, 
           int location, bool is_bnd) {
        DEF_LOG("Calling JUMP constructor");
        Operation o;
        isJump_ = true;
        if(asm_opcode == "jmpq")
          asm_opcode = "jmp";
        if(asm_opcode.find("call") != string::npos)
          isCall_ = true;
        if(operand.find("*") != string::npos) {
          isIndrctCf_ = true;
        }
        else {
          if(operand.length() > 0)
            target_ = calcTarget(hex_bytes, location, is_bnd);
        }
        set <string> uncond_cf_ins_set = utils::get_uncond_cf_ins_set();
        if(uncond_cf_ins_set.find(asm_opcode) != uncond_cf_ins_set.end())
          isUnconditionalJmp_ = true;
        o.op = OP::JUMP;
        auto words = utils::split_string(operand,",");
        int word_cnt = words.size();
        if(word_cnt > 0) {
          o.source1.init(words[0]);
          if(words[0].find("(") != string::npos)
            o.source1.op_ = OP::DEREF;
          for(int ctr = 1; ctr > word_cnt; ctr++) {
            Operand opr;
            opr.init(words[ctr]);
            if(words[ctr].find("(") != string::npos)
              opr.op_ = OP::DEREF;
            o.unknownOperands.push_back(opr);
          }
        }
        OpList.push_back(o);
        init(hex_bytes,location);
      }
      uint64_t
      calcTarget(vector <uint8_t> &hex_bytes, int location, bool is_bnd) {
        /* Calculates the jump target_ from hex bytes of the Instruction.
         */
        string hex_target = "";
        int j = hex_bytes.size();
        int inssz = j;
        int opCnt = 0;
        //cout<<"ins size: "<<inssz<<endl;
        int64_t tgt = 0;
        int64_t next_loc = location + inssz;
        if(is_bnd)
          inssz--;
      
        if(inssz < 5) {
          opCnt = 1;
          for(int i = 1; i <= opCnt; i++) {
            string hex = utils::decToHexa(hex_bytes[j - i]);
            hex_target += hex;
          }
          int8_t offset;
      
          offset = stoi(hex_target, 0, 16);
          tgt = abs(next_loc + offset);
        }
        else {
          opCnt = 4;
          if(inssz < 5) {
            LOG("Invalid jump ins at: "<<location);
            exit(0);
          }
          for(int i = 1; i <= opCnt; i++) {
            string hex = utils::decToHexa(hex_bytes[j - i]);
            hex_target += hex;
          }
          //int64_t next_loc = loc_ + inssz;
          int32_t offset = stol(hex_target, 0, 16);
          tgt = abs(next_loc + offset);
        }
        return tgt;
      }
  };
  
  class PUSH : public InsSemantics {
  public:
    PUSH(string & mne, string & op, vector <uint8_t> &hex_bytes, int location) {
      Operation o2;
      o2.source1.init(-8);
      string reg = "%rsp";
      //o2.source2.init(reg, OperandType::REG);
      o2.target.init(reg, OperandType::REG);
      o2.op = OP::ADD;
      OpList.push_back(o2);

      Operation o1;
      o1.source1.init(op);
      if(op.find("(") != string::npos)
        o1.source1.op_ = OP::DEREF;
      o1.target.init(reg, OperandType::REG);
      o1.target.op_ = OP::DEREF;
      o1.op = OP::STORE;
      OpList.push_back(o1);
      init(hex_bytes,location);
    }
  };

  class POP : public InsSemantics {
    public:
    POP(string & mne, string & op, vector <uint8_t> &hex_bytes, int location) {
      Operation o1;
      o1.target.init(op);
      string reg = "%rsp";
      o1.source1.init(reg, OperandType::REG);
      o1.source1.op_ = OP::DEREF;
      o1.op = OP::STORE;
      OpList.push_back(o1);

      Operation o2;
      o2.source1.init(8);
      //o2.source2.init(reg, OperandType::REG);
      o2.target.init(reg, OperandType::REG);
      o2.op = OP::ADD;
      OpList.push_back(o2);
      init(hex_bytes,location);

    }
  };

  class MOV : public InsSemantics {
    public:
    MOV(string & mne, string & op, vector <uint8_t> &hex_bytes, int location) {
      Operation o;
      auto words = utils::split_string(op,",");
      int word_cnt = words.size();
      auto tgt_op = words[word_cnt - 1];
      //auto tgt_op = utils::trim(words[word_cnt - 1]);
      o.target.init(tgt_op);
      if(tgt_op.find("(") != string::npos)
        o.target.op_ = OP::DEREF;
      if(word_cnt > 0) {
        o.source1.init(words[0]);
        if(words[0].find("(") != string::npos)
          o.source1.op_ = OP::DEREF;
        for(int ctr = 1; ctr > word_cnt; ctr++) {
          Operand opr;
          opr.init(words[ctr]);
          if(words[ctr].find("(") != string::npos)
            opr.op_ = OP::DEREF;
          o.unknownOperands.push_back(opr);
        }
      }
      o.op = OP::STORE;
      OpList.push_back(o); 
      init(hex_bytes,location);
    }
  };

  class ADD : public InsSemantics {
    public:
    ADD(string & mne, string & op, vector <uint8_t> &hex_bytes, int location) {
      Operation o;
      auto words = utils::split_string(op,",");
      int word_cnt = words.size();
      auto tgt_op = words[word_cnt - 1];
      //auto tgt_op = utils::trim(words[word_cnt - 1]);
      o.target.init(tgt_op);
      //o.source2.init(tgt_op);
      if(tgt_op.find("(") != string::npos) {
        o.target.op_ = OP::DEREF;
        //o.source2.op_ = OP::DEREF;
      }
      if(word_cnt > 0) {
        o.source1.init(words[0]);
        if(words[0].find("(") != string::npos)
          o.source1.op_ = OP::DEREF;
        for(int ctr = 1; ctr > word_cnt; ctr++) {
          Operand opr;
          opr.init(words[ctr]);
          if(words[ctr].find("(") != string::npos)
            opr.op_ = OP::DEREF;
          o.unknownOperands.push_back(opr);
        }
      }
      if(mne.find("sub") != string::npos)
        o.op = OP::SUB;
      else
        o.op = OP::ADD;
      OpList.push_back(o);
      init(hex_bytes,location);
    }
  };

  class AND : public InsSemantics {
    public:
    AND(string & mne, string & op, vector <uint8_t> &hex_bytes, int location) {
      Operation o;
      auto words = utils::split_string(op,",");
      int word_cnt = words.size();
      auto tgt_op = words[word_cnt - 1];
      o.target.init(tgt_op);
      //o.source2.init(tgt_op);
      if(tgt_op.find("(") != string::npos) {
        o.target.op_ = OP::DEREF;
        //o.source2.op_ = OP::DEREF;
      }
      if(word_cnt > 0) {
        o.source1.init(words[0]);
        if(words[0].find("(") != string::npos)
          o.source1.op_ = OP::DEREF;
        for(int ctr = 1; ctr > word_cnt; ctr++) {
          Operand opr;
          opr.init(words[ctr]);
          if(words[ctr].find("(") != string::npos)
            opr.op_ = OP::DEREF;
          o.unknownOperands.push_back(opr);
        }
      }
      o.op = OP::AND;
      OpList.push_back(o);
      init(hex_bytes,location);
    }
  };
  class OR : public InsSemantics {
    public:
    OR(string & mne, string & op, vector <uint8_t> &hex_bytes, int location) {
      Operation o;
      auto words = utils::split_string(op,",");
      int word_cnt = words.size();
      //auto tgt_op = utils::trim(words[word_cnt - 1]);
      auto tgt_op = words[word_cnt - 1];
      o.target.init(tgt_op);
      //o.source2.init(tgt_op);
      if(tgt_op.find("(") != string::npos) {
        o.target.op_ = OP::DEREF;
        //o.source2.op_ = OP::DEREF;
      }
      if(word_cnt > 0) {
        o.source1.init(words[0]);
        if(words[0].find("(") != string::npos)
          o.source1.op_ = OP::DEREF;
        for(int ctr = 1; ctr > word_cnt; ctr++) {
          Operand opr;
          opr.init(words[ctr]);
          if(words[ctr].find("(") != string::npos)
            opr.op_ = OP::DEREF;
          o.unknownOperands.push_back(opr);
        }
      }
      o.op = OP::OR;
      OpList.push_back(o);
      init(hex_bytes,location);
    }
  };
  class XOR : public InsSemantics {
    public:
    XOR(string & mne, string & op, vector <uint8_t> &hex_bytes, int location) {
      Operation o;
      auto words = utils::split_string(op,",");
      int word_cnt = words.size();
      auto tgt_op = words[word_cnt - 1];
      //auto tgt_op = utils::trim(words[word_cnt - 1]);
      o.target.init(tgt_op);
      //o.source2.init(tgt_op);
      if(tgt_op.find("(") != string::npos) {
        o.target.op_ = OP::DEREF;
        //o.source2.op_ = OP::DEREF;
      }
      if(word_cnt > 0) {
        o.source1.init(words[0]);
        if(words[0].find("(") != string::npos)
          o.source1.op_ = OP::DEREF;
        for(int ctr = 1; ctr > word_cnt; ctr++) {
          Operand opr;
          opr.init(words[ctr]);
          if(words[ctr].find("(") != string::npos)
            opr.op_ = OP::DEREF;
          o.unknownOperands.push_back(opr);
        }
      }
      o.op = OP::XOR;
      OpList.push_back(o);
      init(hex_bytes,location);
    }
  };

  class LEA : public InsSemantics {
    public:
    LEA(string & mne, string & op, vector <uint8_t> &hex_bytes, int location) {
      Operation o;
      isLea_ = true;
      auto words = utils::split_string(op,",");
      int word_cnt = words.size();
      auto tgt_op = words[word_cnt - 1];
      //auto tgt_op = utils::trim(words[word_cnt - 1]);
      o.target.init(tgt_op);
      if(word_cnt > 0) {
        o.source1.init(words[0]);
        for(int ctr = 1; ctr > word_cnt; ctr++) {
          Operand opr;
          opr.init(words[ctr]);
          o.unknownOperands.push_back(opr);
        }
      }
      o.op = OP::LEA;
      OpList.push_back(o);
      init(hex_bytes,location);
    }
  };

  class UNKNOWNINS : public InsSemantics {
    public:
    UNKNOWNINS() {}
    UNKNOWNINS(string & mne, string & op, vector <uint8_t> &hex_bytes, int
        location) {
      DEF_LOG("Calling unknown constructor with params");
      Operation o;
      auto words = utils::split_string(op,",");
      for(auto & w : words) {
        Operand op;
        op.init(w);
        o.unknownOperands.push_back(op);
      }
      OpList.push_back(o);
      init(hex_bytes,location);
    }
  };

}

#endif
