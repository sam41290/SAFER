/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "expr.h"
#include "function.h"
#include "insn.h"
#include "state.h"
#include "domain.h"
#include "arithmetic.h"
// ----------------------------------- Expr ------------------------------------
Expr::Expr(EXPR_TYPE type, EXPR_MODE mode): RTL(RTL_TYPE::EXPR) {
   typeExpr_ = type;
   modeExpr_ = mode;
   cachedId_ = UnitId();
}
// ---------------------------------- Const ------------------------------------
Const::Const(int64_t i): Expr(EXPR_TYPE::CONSTANT, EXPR_MODE::NONE) {
   typeConst_ = CONST_TYPE::INTEGER;
   i_ = i;
}


Const::Const(CONST_TYPE typeConst, Expr* expr): Expr(EXPR_TYPE::CONSTANT,
EXPR_MODE::NONE) {
   typeConst_ = typeConst;
   switch (typeConst_) {
      case CONST_TYPE::INTEGER:
      case CONST_TYPE::LABEL:
         i_ = Util::to_int(expr->to_string());
         break;
      case CONST_TYPE::DOUBLE:
         d_ = Util::to_double(expr->to_string());
         break;
      default:
         break;
   }
   delete expr;
}


string Const::to_string() const {
   switch (typeConst_) {
      case CONST_TYPE::INTEGER:
         return string("(const_int ").append(std::to_string(i_)).append(")");
      case CONST_TYPE::DOUBLE:
         return string("(const_double ").append(std::to_string(d_)).append(")");
      case CONST_TYPE::LABEL:
         return string("(label_ref ").append(std::to_string(i_)).append(")");
      default:
         return string("");
   }
}


bool Const::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (Const*)(*v);
   if (v2 == nullptr)
      return false;

   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return (typeConst_==v2->const_type() || typeConst_==CONST_TYPE::ANY);
      default:
         switch (typeConst_) {
            case CONST_TYPE::INTEGER:
            case CONST_TYPE::LABEL:
               return (i_ == v2->to_int());
            case CONST_TYPE::DOUBLE:
               return (d_ == v2->to_double());
            default:
               return false;
         }
   }
}


vector<RTL*> Const::find(RTL_EQUAL typeEq, RTL* v) {
   if (equal(typeEq, v))
      return vector<RTL*>{this};
   return vector<RTL*>{};
}


Expr* Const::clone() {
   switch (typeConst_) {
      case CONST_TYPE::INTEGER:
         return new Const(i_);
      case CONST_TYPE::LABEL:
         return new Const(typeConst_, new NoType(std::to_string(i_)));
      case CONST_TYPE::DOUBLE:
         return new Const(typeConst_, new NoType(std::to_string(d_)));
      default:
         return nullptr;
   }
}


array<BaseDomain*,domainCnt> Const::eval(const array<State*,domainCnt>& s) {
   array<BaseDomain*,domainCnt> res;
   cachedId_ = UnitId(REGION::NONE, i_);
   switch (typeConst_) {
      case CONST_TYPE::INTEGER:
         res[0] = BaseLH::create_instance(Range(i_,i_));;
         res[1] = BaseLH::create_instance(Range(i_,i_));;
         break;
      case CONST_TYPE::LABEL: {
         auto base = baseRegion(REGION::STATIC);
         res[0] = BaseLH::create_instance(base, Range(i_,i_));;
         res[1] = BaseLH::create_instance(base, Range(i_,i_));;
         break;
      }
      default:
         res[0] = BaseDomain::TOP;
         res[1] = BaseDomain::TOP;
         break;
   }
   res[2] = InitDomain::create_instance(0);
   return res;
}
// ------------------------------------ Var ------------------------------------
Var::Var(VAR_TYPE typeVar, EXPR_MODE mode):Expr(EXPR_TYPE::VAR, mode) {
   typeVar_ = typeVar;
}
// ------------------------------------ Mem ------------------------------------
Mem::Mem(EXPR_MODE mode, Expr* addr): Var(VAR_TYPE::MEM, mode) {
   addr_ = addr;
}


Mem::~Mem() {
   delete addr_;
}


string Mem::to_string() const {
   return string("(mem").append(mode_string()).append(" ")
                        .append(addr_->to_string()).append(")");
}


bool Mem::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (Mem*)(*v);
   if (v2 == nullptr)
      return false;

   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return (addr_ == nullptr || addr_->equal(typeEq, v2->addr()));
      case RTL_EQUAL::RELAXED:
         return (addr_->equal(typeEq, v2->addr()));
      case RTL_EQUAL::STRICT:
         return (addr_->equal(typeEq, v2->addr()) &&
                 expr_mode() == v2->expr_mode());
     default:
         return false;
   }
}


vector<RTL*> Mem::find(RTL_EQUAL typeEq, RTL* v) {
   vector<RTL*> vList;
   if (equal(typeEq, v))
      vList.push_back(this);
   addr_->find_helper(typeEq, v, vList);
   return vList;
}


Expr* Mem::clone() {
   return new Mem(expr_mode(), addr_->clone());
}


array<BaseDomain*,domainCnt> Mem::eval(const array<State*,domainCnt>& s) {
   array<BaseDomain*,domainCnt> res;
   for (int k = 0; k < domainCnt; ++k)
      res[k] = BaseDomain::BOT;
   auto addrVec = addr_->eval(s);

   /* ------------ 0x1: uninit mem address ------------ */
   if (!InitDomain::valid(addrVec[2], addr_->mode_size())) {
      s[2]->loc().func->uninit(0x1);
      LOG(3, "uninitialized value at memory address");
   }
   /* ------------------------------------------------- */

   if (addrVec[0]->top() || BaseLH::notlocal(addrVec[0])) {
      for (int k = 0; k < domainCnt; ++k)
         res[k] = BaseDomain::TOP;
   }
   else if (addrVec[0]->bot()) {
      for (int k = 0; k < domainCnt; ++k)
         res[k] = BaseDomain::BOT;
   }
   else {
      auto tmp = (BaseLH*)addrVec[0];
      auto b = tmp->base();
      if (b == stackSym || b == staticSym || b == 0) {
         auto r = (b == stackSym)? REGION::STACK: REGION::STATIC;
         auto range = tmp->range();
         auto lo = UnitId(r, range.lo());
         auto hi = UnitId(r, range.hi());
         for (int k = 0; k < domainCnt; ++k)
            res[k] = s[k]->value_range(lo, hi);
         if (range.lo() == range.hi())
            cachedId_ = UnitId(r, range.lo());
      }
      else {
         for (int k = 0; k < domainCnt; ++k)
            res[k] = BaseDomain::TOP;
      }
   }

   for (int k = 0; k < domainCnt; ++k) {
      res[k] = res[k]->mode(mode_size());
      BaseDomain::safe_delete(addrVec[k]);
   }

   return res;
}


bool Mem::include(RTL* subExpr) const {
   return this == subExpr || addr_->include(subExpr);
}
// ------------------------------------ Reg ------------------------------------
Reg::Reg(EXPR_MODE mode, Expr* r): Var(VAR_TYPE::REG, mode) {
   r_ = ARCH::from_string(r->to_string());
   delete r;
}


Reg::Reg(EXPR_MODE mode, ARCH::REG r): Var(VAR_TYPE::REG, mode) {
   r_ = r;
}


Reg::~Reg() {}


string Reg::to_string() const {
   return string("(reg").append(mode_string()).append(" ")
                        .append(ARCH::to_string(r_)).append(")");
}


bool Reg::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (Reg*)(*v);
   if (v2 == nullptr)
      return false;

   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
      case RTL_EQUAL::RELAXED:
         return (r_ == v2->reg());
      case RTL_EQUAL::STRICT:
         return (r_ == v2->reg() && expr_mode() == v2->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> Reg::find(RTL_EQUAL typeEq, RTL* v) {
   if (equal(typeEq, v))
      return vector<RTL*>{this};
   return vector<RTL*>{};
}


Expr* Reg::clone() {
   return new Reg(expr_mode(), r_);
}


array<BaseDomain*,domainCnt> Reg::eval(const array<State*,domainCnt>& s) {
   array<BaseDomain*,domainCnt> res;
   cachedId_ = UnitId(r_);

   /* replace %rip with next_offset() */
   if (r_ == ARCH::insnPtr) {
      auto pc = s[0]->loc().insn->next_offset();
      res[0] = BaseLH::create_instance(baseRegion(REGION::STATIC),Range(pc,pc));
      res[1] = BaseLH::create_instance(baseRegion(REGION::STATIC),Range(pc,pc));
      res[2] = InitDomain::create_instance(0);
   }
   /* otherwise retrieve BaseLH and InitDomain value */
   else {
      for (int k = 0; k < domainCnt; ++k)
         res[k] = s[k]->value_unit(id());
   }

   for (int k = 0; k < domainCnt; ++k)
      res[k] = res[k]->mode(mode_size());
   return res;
}
// ---------------------------------- SubReg -----------------------------------
SubReg::SubReg(EXPR_MODE mode, Expr* expr, Expr* byteNum):
Expr(EXPR_TYPE::SUBREG, mode) {
   expr_ = expr;
   byteNum_ = Util::to_int(byteNum->to_string());
   delete byteNum;
}


SubReg::SubReg(EXPR_MODE mode, Expr* expr, int byteNum):
Expr(EXPR_TYPE::SUBREG, mode) {
   expr_ = expr;
   byteNum_ = byteNum;
}


SubReg::~SubReg() {
   delete expr_;
}


string SubReg::to_string() const {
   return string("(subreg").append(mode_string()).append(" ")
                           .append(expr_->to_string()).append(" ")
                           .append(std::to_string(byteNum_)).append(")");
}


bool SubReg::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (SubReg*)(*v);
   if (v2 == nullptr)
      return false;

   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return (byteNum_ == v2->bytenum() &&
                (expr_ == nullptr || expr_->equal(typeEq, v2->expr())));
      case RTL_EQUAL::RELAXED:
         return (byteNum_ == v2->bytenum() &&
                 expr_->equal(typeEq, v2->expr()));
      case RTL_EQUAL::STRICT:
         return (byteNum_ == v2->bytenum() &&
                 expr_->equal(typeEq, v2->expr()) &&
                 expr_mode() == v2->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> SubReg::find(RTL_EQUAL typeEq, RTL* v) {
   vector<RTL*> vList;
   if (equal(typeEq, v))
      vList.push_back(this);
   expr_->find_helper(typeEq, v, vList);
   return vList;
}


Expr* SubReg::clone() {
   return new SubReg(expr_mode(), expr_->clone(), byteNum_);
}


array<BaseDomain*,domainCnt> SubReg::eval(const array<State*,domainCnt>& s) {
   array<BaseDomain*,domainCnt> res;
   auto exprVec = expr_->eval(s);
   cachedId_ = expr_->id();

   res[0] = (exprVec[0]->top() || exprVec[0]->bot())? exprVec[0]:
            (BaseLH::notlocal(exprVec[0]) || byteNum_!=0 ||
               ((BaseLH*)(exprVec[0]))->base()==0? BaseDomain::TOP: exprVec[0]);
   res[1] = (exprVec[1]->top() || exprVec[1]->bot())? exprVec[1]:
            (BaseLH::notlocal(exprVec[1]) || byteNum_!=0 ||
               ((BaseLH*)(exprVec[1]))->base()==0? BaseDomain::TOP: exprVec[1]);
   res[2] = exprVec[2];

   for (int k = 0; k < domainCnt; ++k) {
      if (exprVec[k] != res[k])
         BaseDomain::safe_delete(exprVec[k]);
      res[k] = res[k]->mode(mode_size());
   }

   return res;
}


bool SubReg::include(RTL* subExpr) const {
   return this == subExpr || expr_->include(subExpr);
}
// ---------------------------------- If Else ----------------------------------
IfElse::IfElse(EXPR_MODE mode, Compare* cmp, Expr* if_expr, Expr* else_expr):
Expr(EXPR_TYPE::IF_ELSE, mode) {
   cmp_ = cmp;
   if_ = if_expr;
   else_ = else_expr;
}


IfElse::~IfElse() {
   delete cmp_;
   delete if_;
   delete else_;
}


string IfElse::to_string() const {
   return string("(if_then_else").append(mode_string()).append(" ")
                                 .append(cmp_->to_string()).append(" ")
                                 .append(if_->to_string()).append(" ")
                                 .append(else_->to_string()).append(")");
}


bool IfElse::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (IfElse*)(*v);
   if (v2 == nullptr)
      return false;

   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return (cmp_->equal(typeEq, v2->cmp()) &&
                (if_ == nullptr || if_->equal(typeEq, v2->if_expr())) &&
                (else_ == nullptr || else_->equal(typeEq, v2->else_expr())));
      case RTL_EQUAL::RELAXED:
         return (cmp_->equal(typeEq, v2->cmp()) &&
                 if_->equal(typeEq, v2->if_expr()) &&
                 else_->equal(typeEq, v2->else_expr()));
      case RTL_EQUAL::STRICT:
         return (cmp_->equal(typeEq, v2->cmp()) &&
                 if_->equal(typeEq, v2->if_expr()) &&
                 else_->equal(typeEq, v2->else_expr()) &&
                 expr_mode() == v2->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> IfElse::find(RTL_EQUAL typeEq, RTL* v) {
   vector<RTL*> vList;
   if (equal(typeEq, v))
     vList.push_back(this);
   cmp_->find_helper(typeEq, v, vList);
   if_->find_helper(typeEq, v, vList);
   else_->find_helper(typeEq, v, vList);
   return vList;
}


Expr* IfElse::clone() {
   return new IfElse(expr_mode(), (Compare*)(cmp_->clone()),
                     if_->clone(), else_->clone());
}


array<BaseDomain*,domainCnt> IfElse::eval(const array<State*,domainCnt>& s) {
   /* conditional move is not supported yet */
   array<BaseDomain*,domainCnt> res;
   auto ifVec = if_->eval(s);
   auto elseVec = else_->eval(s);
   for (int k = 0; k < domainCnt; ++k) {
      res[k] = (ifVec[k]->ref() > 0)? ifVec[k]: ifVec[k]->clone();
      res[k] = res[k]->abs_union(elseVec[k]);
      if (res[k] != elseVec[k])
         BaseDomain::safe_delete(elseVec[k]);
   }
   return res;
}


bool IfElse::include(RTL* subExpr) const {
   return this == subExpr || cmp_->include(subExpr) ||
          if_->include(subExpr) || else_->include(subExpr);
}
// -------------------------------- Conversion ---------------------------------
Conversion::Conversion(OP typeOp, EXPR_MODE mode, Expr* expr):
Expr(EXPR_TYPE::CONVERSION, mode) {
   typeOp_ = typeOp;
   expr_ = expr;
   size_ = nullptr;
   pos_ = nullptr;
}


Conversion::Conversion(OP typeOp, EXPR_MODE modeExpr, Expr* expr,
Expr* size, Expr* pos): Expr(EXPR_TYPE::CONVERSION, modeExpr) {
   typeOp_ = typeOp;
   expr_ = expr;
   size_ = size;
   pos_ = pos;
}


Conversion::~Conversion() {
   if (typeOp_ == OP::ANY)
      return;
   delete expr_;
   if (size_ != nullptr)
      delete size_;
   if (pos_ != nullptr)
      delete pos_;
}


string Conversion::to_string() const {
   switch (typeOp_) {
      case OP::ANY:
         return string("");
      case OP::ZERO_EXTRACT:
      case OP::SIGN_EXTRACT:
         return string("(").append(Conversion::OP_STR[(int)typeOp_])
                .append(mode_string()).append(" ")
                .append(expr_->to_string()).append(" ")
                .append(size_->to_string()).append(" ")
                .append(pos_->to_string()).append(")");
      default:
         return string("(").append(Conversion::OP_STR[(int)typeOp_])
                .append(mode_string()).append(" ")
                .append(expr_->to_string()).append(")");
   }
}


bool Conversion::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (Conversion*)(*v);
   if (v2 == nullptr)
      return false;

   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return (typeOp_ == v2->conv_type() || typeOp_ == OP::ANY);
      case RTL_EQUAL::PARTIAL:
         return (typeOp_ == v2->conv_type() &&
                (expr_ == nullptr || expr_->equal(typeEq, v2->expr())) &&
                (size_ == nullptr || size_->equal(typeEq, v2->size())) &&
                (pos_  == nullptr || pos_->equal(typeEq, v2->pos())));
      case RTL_EQUAL::RELAXED:
         return (typeOp_ == v2->conv_type() &&
                 expr_->equal(typeEq, v2->expr()) &&
                 size_->equal(typeEq, v2->size()) &&
                 pos_->equal(typeEq, v2->pos()));
      case RTL_EQUAL::STRICT:
         return (typeOp_ == v2->conv_type() &&
                 expr_->equal(typeEq, v2->expr()) &&
                 size_->equal(typeEq, v2->size()) &&
                 pos_->equal(typeEq, v2->pos()) &&
                 expr_mode() == v2->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> Conversion::find(RTL_EQUAL typeEq, RTL* v) {
   vector<RTL*> vList;
   if (equal(typeEq, v))
      vList.push_back(this);
   expr_->find_helper(typeEq, v, vList);
   if (size_ != nullptr)
      size_->find_helper(typeEq, v, vList);
   if (pos_ != nullptr)
      pos_->find_helper(typeEq, v, vList);
   return vList;
}


Expr* Conversion::simplify() const {
   Conversion* v = (Conversion*)(*((RTL*)this));
   return (v==nullptr)? (Expr*)this: v->expr()->simplify();
}


Expr* Conversion::clone() {
   switch (typeOp_) {
      case OP::ANY:
         return nullptr;
      case OP::ZERO_EXTRACT:
      case OP::SIGN_EXTRACT:
         return new Conversion(typeOp_, expr_mode(), expr_->clone(),
                               size_->clone(), pos_->clone());
      default:
         return new Conversion(typeOp_, expr_mode(), expr_->clone());
   }
}


array<BaseDomain*,domainCnt> Conversion::eval(const array<State*,domainCnt>& s) {
   array<BaseDomain*,domainCnt> res;
   auto vec = simplify()->eval(s);
   cachedId_ = expr_->id();
   for (int k = 0; k < domainCnt; ++k)
      res[k] = vec[k]->mode(mode_size());
   return res;
}


bool Conversion::include(RTL* subExpr) const {
   return this == subExpr ||
          (expr_ != nullptr && expr_->include(subExpr)) ||
          (size_ != nullptr && size_->include(subExpr)) ||
          (pos_ != nullptr  && pos_->include(subExpr));
}
// ------------------------------ NoType --------------------------------
NoType::NoType(const string& s): Expr(EXPR_TYPE::NOTYPE,
EXPR_MODE::NONE) {
   s_ = s;
}


NoType::~NoType() {}


string NoType::to_string() const {
   return s_;
}


bool NoType::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (NoType*)(*v);
   if (v2 == nullptr)
      return false;

   return !s_.compare(v2->to_string());
}


vector<RTL*> NoType::find(RTL_EQUAL typeEq, RTL* v) {
   if (equal(typeEq, v))
      return vector<RTL*>{this};
   return vector<RTL*>{};
}


Expr* NoType::clone() {
   return new NoType(s_);
}


array<BaseDomain*,domainCnt> NoType::eval(const array<State*,domainCnt>& s) {
   array<BaseDomain*,domainCnt> res;
   if (!s_.compare("pc")) {
      auto pc = s[0]->loc().insn->next_offset();
      res[0] = BaseLH::create_instance(baseRegion(REGION::STATIC),Range(pc,pc));
      res[1] = BaseLH::create_instance(baseRegion(REGION::STATIC),Range(pc,pc));
      res[2] = InitDomain::create_instance(0);
   }
   else {
      for (int k = 0; k < domainCnt; ++k)
         res[k] = BaseDomain::TOP;
   }
   return res;
}