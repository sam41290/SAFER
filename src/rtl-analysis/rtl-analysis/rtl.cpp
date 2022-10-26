/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "rtl.h"
#include "function.h"
#include "state.h"
#include "domain.h"
#include "expr.h"
#include "arithmetic.h"
// ------------------------------------ RTL ------------------------------------
RTL::RTL(RTL_TYPE _typeRTL) {
   typeRTL_ = _typeRTL;
}

RTL::~RTL() {}

void RTL::find_helper(RTL_EQUAL typeEq, RTL* v, vector<RTL*>& vList) {
   auto t = find(typeEq, v);
   vList.insert(vList.end(), t.begin(), t.end());
}

RTL::operator Statement*() const {
   return typeRTL_==RTL_TYPE::STATEMENT ? (Statement*)this : nullptr;
}

RTL::operator Parallel*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::PARALLEL ?
          (Parallel*)this : nullptr;
}

RTL::operator Sequence*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::SEQUENCE ?
          (Sequence*)this : nullptr;
}

RTL::operator Assign*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::ASSIGN ?
          (Assign*)this : nullptr;
}

RTL::operator Call*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::CALL ?
          (Call*)this : nullptr;
}

RTL::operator Clobber*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::CLOBBER ?
          (Clobber*)this : nullptr;
}

RTL::operator Exit*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::EXIT ?
          (Exit*)this : nullptr;
}

RTL::operator Nop*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::NOP ?
          (Nop*)this : nullptr;
}

RTL::operator Expr*() const {
   return typeRTL_ == RTL_TYPE::EXPR ? (Expr*)this : nullptr;
}

RTL::operator Const*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::CONSTANT ? (Const*)this : nullptr;
}

RTL::operator Var*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::VAR ? (Var*)this : nullptr;
}

RTL::operator Mem*() const {
   auto t = (Var*)(*this);
   if (t == nullptr) return nullptr;
   return t->var_type()==Var::VAR_TYPE::MEM ? (Mem*)this : nullptr;
}

RTL::operator Reg*() const {
   auto t = (Var*)(*this);
   if (t == nullptr) return nullptr;
   return t->var_type()==Var::VAR_TYPE::REG ? (Reg*)this : nullptr;
}

RTL::operator Arithmetic*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::ARITHMETIC ?
          (Arithmetic*)this : nullptr;
}

RTL::operator Unary*() const {
   auto t = (Arithmetic*)(*this);
   if (t == nullptr) return nullptr;
   return t->arith_type()==Arithmetic::ARITH_TYPE::UNARY ?
          (Unary*)this : nullptr;
}

RTL::operator Binary*() const {
   auto t = (Arithmetic*)(*this);
   if (t == nullptr) return nullptr;
   return t->arith_type()==Arithmetic::ARITH_TYPE::BINARY ?
          (Binary*)this : nullptr;
}

RTL::operator Compare*() const {
   auto t = (Arithmetic*)(*this);
   if (t == nullptr) return nullptr;
   return t->arith_type()==Arithmetic::ARITH_TYPE::COMPARE ?
          (Compare*)this : nullptr;
}

RTL::operator SubReg*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::SUBREG ? (SubReg*)this : nullptr;
}

RTL::operator IfElse*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::IF_ELSE ? (IfElse*)this : nullptr;
}

RTL::operator Conversion*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::CONVERSION ?
          (Conversion*)this : nullptr;
}

RTL::operator NoType*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::NOTYPE ?
          (NoType*)this : nullptr;
}
// --------------------------------- Statement ---------------------------------
Statement::Statement(Statement::STATEMENT_TYPE type): RTL(RTL_TYPE::STATEMENT) {
   typeStatement_ = type;
}


array<BaseDomain*,domainCnt> Statement::eval(const array<State*,domainCnt>& s,
Expr* subExpr) const {
   return subExpr->eval(s);
}
// ---------------------------------- Parallel ---------------------------------
Parallel::Parallel(const vector<Statement*>& _stmts):
Statement(STATEMENT_TYPE::PARALLEL) {
   stmts_ = _stmts;
}


Parallel::~Parallel() {
   for (auto v: stmts_)
      delete v;
}


string Parallel::to_string() const {
   string s = string("(parallel [").append(stmts_.front()->to_string());
   for (auto it = std::next(stmts_.begin(),1); it != stmts_.end(); ++it)
      s.append(" ").append((*it)->to_string());
   return s.append("])");
}


bool Parallel::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (Parallel*)(*v);
   if (v2 == nullptr)
      return false;

   auto it = stmts_.begin();
   auto it2 = v2->stmts().begin();
   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         if (stmts_.size() != v2->stmts().size())
            return false;
         for (; it != stmts_.end(); ++it, ++it2)
            if (!(*it)->equal(typeEq, *it2))
               return false;
         return true;
      default:
         return false;
   }
}


vector<RTL*> Parallel::find(RTL_EQUAL typeEq, RTL* v) {
   vector<RTL*> vList;
   if (equal(typeEq, v))
      vList.push_back(this);
   for (auto s: stmts_)
      s->find_helper(typeEq, v, vList);
   return vList;
}


void Parallel::execute(const array<State*,domainCnt>& s) const {
   for (auto stmt: stmts_)
      if ((NoType*)(*((RTL*)stmt)) == nullptr)
         stmt->execute(s);
}


void Parallel::preset(const array<State*,domainCnt>& s) const {
   for (auto stmt: stmts_)
      if ((NoType*)(*((RTL*)stmt)) == nullptr)
         stmt->preset(s);
}


bool Parallel::include(RTL* subExpr) const {
   for (auto stmt: stmts_)
      if (stmt->include(subExpr))
         return true;
   return false;
}
// ---------------------------------- Parallel ---------------------------------
Sequence::Sequence(const vector<Statement*>& stmts):
Statement(STATEMENT_TYPE::SEQUENCE) {
   stmts_ = stmts;
}


Sequence::~Sequence() {
   for (auto stmt: stmts_)
      delete stmt;
}


string Sequence::to_string() const {
   string s = string("(sequence [").append(stmts_.front()->to_string());
   for (auto it = std::next(stmts_.begin(),1); it != stmts_.end(); ++it)
      s.append(" ").append((*it)->to_string());
   return s.append("])");
}


bool Sequence::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (Sequence*)(*v);
   if (v2 == nullptr)
      return false;

   auto it = stmts_.begin();
   auto it2 = v2->stmts().begin();
   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         if (stmts_.size() != v2->stmts().size())
            return false;
         for (; it != stmts_.end(); ++it, ++it2)
            if (!(*it)->equal(typeEq, *it2))
               return false;
         return true;
      default:
         return false;
   }
}


vector<RTL*> Sequence::find(RTL_EQUAL typeEq, RTL* v) {
   vector<RTL*> vList;
   if (equal(typeEq, v))
      vList.push_back(this);
   for (auto stmt: stmts_)
      stmt->find_helper(typeEq, v, vList);
   return vList;
}


void Sequence::execute(const array<State*,domainCnt>& s) const {
   for (auto stmt: stmts_)
      if ((NoType*)(*((RTL*)stmt)) == nullptr) {
         /* commit previous stmt, not commit at first stmt */
         /* last stmt will be committed outside */
         for (auto ss: s)
            ss->commit(CHANNEL::INSN);
         stmt->execute(s);
      }
}


void Sequence::preset(const array<State*,domainCnt>& s) const {
   for (auto stmt: stmts_)
      if ((NoType*)(*((RTL*)stmt)) == nullptr) {
         for (auto ss: s)
            ss->commit(CHANNEL::INSN);
         stmt->preset(s);
      }
}


array<BaseDomain*,domainCnt> Sequence::eval(const array<State*,domainCnt>& s,
Expr* subExpr) const {
   for (auto stmt: stmts_) {
      if (stmt->include(subExpr))
         return subExpr->eval(s);
      if ((NoType*)(*((RTL*)stmt)) == nullptr)
         stmt->execute(s);
   }
   return Statement::eval(s, subExpr);
}


bool Sequence::include(RTL* subExpr) const {
   for (auto stmt: stmts_)
      if (stmt->include(subExpr))
         return true;
   return false;
}
// ----------------------------------- Assign ----------------------------------
Assign::Assign(Expr* dst, Expr* src): Statement(STATEMENT_TYPE::ASSIGN) {
   dst_ = dst;
   src_ = src;
}


Assign::~Assign() {
   delete dst_;
   delete src_;
}


string Assign::to_string() const {
   return string("(set ").append(dst_->to_string()).append(" ")
                         .append(src_->to_string()).append(")");
}


bool Assign::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (Assign*)(*v);
   if (v2 == nullptr)
      return false;

   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return ((dst_ == nullptr || dst_->equal(typeEq, v2->dst())) &&
                 (src_ == nullptr || src_->equal(typeEq, v2->src())));
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         return (dst_->equal(typeEq, v2->dst()) &&
                 src_->equal(typeEq, v2->src()));
      default:
         return false;
   }
}


vector<RTL*> Assign::find(RTL_EQUAL typeEq, RTL* v) {
   vector<RTL*> vList;
   if (equal(typeEq, v))
      vList.push_back(this);
   dst_->find_helper(typeEq, v, vList);
   src_->find_helper(typeEq, v, vList);
   return vList;
}


void Assign::execute(const array<State*,domainCnt>& s) const {
   auto dst = dst_->simplify();
   auto dstMode = dst->mode_size();

   /* evaluate src */
   auto srcValue = src_->eval(s);
   for (int k = 0; k < domainCnt; ++k)
      srcValue[k] = srcValue[k]->mode(dstMode);
   auto srcExpr = src_->eval_expr();

   /* dst is register */
   auto r = (Reg*)(*dst);
   if (r != nullptr) {
      /* ----------- 0x4: uninit critical data  ---------- */
      if (!InitDomain::valid(srcValue[2], src_->mode_size()) && ARCH::critical(r->reg())) {
         s[2]->loc().func->uninit(0x4);
         LOG(3, "uninitialized value at critical data ("
                << ARCH::to_string(r->reg()) << ")");
      }
      /* ------------------------------------------------- */
      auto dstId = UnitId(r->reg());
      for (int k = 0; k < domainCnt; ++k) {
         s[k]->update_unit(dstId, srcValue[k], srcExpr);
         BaseDomain::safe_delete(srcValue[k]);
      }
      return;
   }

   /* dst is memory */
   auto m = (Mem*)(*dst);
   if (m != nullptr) {
      auto addrVec = m->addr()->eval(s);
      /* ------------ 0x1: uninit mem address ------------ */
      if (!InitDomain::valid(addrVec[2], m->addr()->mode_size())) {
         s[2]->loc().func->uninit(0x1);
         LOG(3, "uninitialized value at memory address");
      }
      /* ------------------------------------------------- */
      if (addrVec[0]->top()) {
         for (int k = 0; k < domainCnt; ++k) {
            s[k]->clobber(REGION::STACK);
            s[k]->clobber(REGION::STATIC);
         }
      }
      else if (BaseLH::notlocal(addrVec[0])) {
         for (int k = 0; k < domainCnt; ++k)
            s[k]->clobber(REGION::STATIC);
      }
      else if (!addrVec[0]->bot()) {
         auto addr = (BaseLH*)(addrVec[0]);
         auto b = addr->base();
         /* ----------- 0x4: uninit critical data  ---------- */
         if (b == stackSym && addr->range() == Range::ZERO &&
         !InitDomain::valid(srcValue[2], src_->mode_size())) {
            s[2]->loc().func->uninit(0x4);
            LOG(3, "uninitialized value at critical data (retaddr)");
         }
         /* ------------------------------------------------- */
         if (b == stackSym || b == staticSym) {
            /* dst is mem:BLK - need improvements later */
            if (m->mode_string().find(":BLK") != string::npos) {
               auto blkSize = dst_->mode_size();
               auto CX = (BaseLH*)(s[0]->value_unit(UnitId(ARCH::REG::CX)));
               auto loCX = CX->range().lo();
               auto DI = (BaseLH*)(s[0]->value_unit(UnitId(ARCH::REG::DI)));
               auto rDI = (DI->base() == stackSym)? REGION::STACK: REGION::STATIC;
               auto loDI = DI->range().lo();

               /* src is mem:BLK */
               if ((Mem*)(*src_) != nullptr
               && src_->mode_string().find(":BLK") != string::npos) {
                  auto SI = (BaseLH*)(s[0]->value_unit(UnitId(ARCH::REG::SI)));
                  auto rSI = (SI->base() == stackSym)? REGION::STACK: REGION::STATIC;
                  auto loSI = SI->range().lo();

                  /* unsound: when DF is unknown, must perform weak update */
                  for (int i = -loCX*blkSize; i < loCX*blkSize; ++i)
                  for (int k = 0; k < domainCnt; ++k) {
                     auto v = s[k]->value_unit(UnitId(rSI,loSI+i));
                     s[k]->update_unit(UnitId(rDI, loDI+i), v, CompareArgsId::EMPTY);
                     BaseDomain::safe_delete(v);
                  }

                  BaseDomain::safe_delete(SI);
               }

               /* src is register or normal mem range */
               else {
                  for (int i = -loCX*blkSize; i < loCX*blkSize; ++i)
                  for (int k = 0; k < domainCnt; ++k)
                     s[k]->update_unit(UnitId(rDI,loDI+i), srcValue[k], srcExpr);
               }

               BaseDomain::safe_delete(DI);
               BaseDomain::safe_delete(CX);
            }
            /* normal memory range */
            else {
               auto r = (b == stackSym)? REGION::STACK: REGION::STATIC;
               auto lo = UnitId(r, addr->range().lo());
               auto hi = UnitId(r, addr->range().hi());
               for (int k = 0; k < domainCnt; ++k)
                  s[k]->update_range(lo, hi, srcValue[k], srcExpr);
               /* fill out other bytes within the range as TOP */
               if (lo == hi) {
                  for (int i = 1; i < dstMode; ++i) {
                     auto id = UnitId(r, lo.i() + i);
                     if (!id.bounds_check())
                        break;
                     s[0]->update_unit(id,BaseDomain::TOP,CompareArgsId::EMPTY);
                     s[1]->update_unit(id,BaseDomain::TOP,CompareArgsId::EMPTY);
                     s[2]->update_unit(id,srcValue[2],srcExpr);
                  }
               }
            }
         }
      }
      /* ------------------------------------------------- */
      for (int k = 0; k < domainCnt; ++k) {
         BaseDomain::safe_delete(addrVec[k]);
         BaseDomain::safe_delete(srcValue[k]);
      }
      return;
   }

   /* dst is pc */
   NoType* nt = (NoType*)(*dst);
   if (nt != nullptr && nt->to_string().compare("pc") == 0) {
      /* ----------- 0x2: uninit control target ----------- */
      if (!InitDomain::valid(srcValue[2], src_->mode_size())) {
         s[2]->loc().func->uninit(0x2);
         LOG(3, "uninitialized value at control target");
      }
      /* ---------- update condition expression ----------- */
      auto ifel = (IfElse*)(*src_);
      if (ifel != nullptr) {
         auto ctrlVec = ifel->cmp()->expr()->eval(s);
         for (int k = 0; k < domainCnt; ++k)
            if (s[k]->cstr_mode()) {
               ctrlVec[k] = ctrlVec[k]->mode(dstMode);
               s[k]->update_unit(UnitId::CF_FLAGS, ctrlVec[k], srcExpr);
            }
         for (int k = 0; k < domainCnt; ++k)
            BaseDomain::safe_delete(ctrlVec[k]);
      }
      for (int k = 0; k < domainCnt; ++k)
         BaseDomain::safe_delete(srcValue[k]);
      return;
   }
}


void Assign::preset(const array<State*,domainCnt>& s) const {
   auto dst = dst_->simplify();
   auto reg = (Reg*)(*dst);
   if (reg != nullptr) {
      auto id = UnitId(reg->reg());
      if (!id.is_flags())
      for (int k = 0; k < domainCnt; ++k)
         if (!s[k]->fixpoint())
            s[k]->preset(id);
   }
}


bool Assign::include(RTL* subExpr) const {
   return src_->include(subExpr);
}
// ----------------------------------- Call ------------------------------------
Call::~Call() {
   delete target_;
}


string Call::to_string() const {
   return string("(call ").append(target_->to_string())
                          .append(" (const_int 0))");
}


bool Call::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (Call*)(*v);
   if (v2 == nullptr)
      return false;

   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return (target_ == nullptr || target_->equal(typeEq, v2->target()));
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         return (target_->equal(typeEq, v2->target()));
      default:
         return false;
   }
}


vector<RTL*> Call::find(RTL_EQUAL typeEq, RTL* v) {
   vector<RTL*> vList;
   if (equal(typeEq, v))
      vList.push_back(this);
   target_->find_helper(typeEq, v, vList);
   return vList;
}


void Call::execute(const array<State*,domainCnt>& s) const {
   auto needCheck = false;
   for (int k = 0; k < domainCnt; ++k) {
      for (auto r: ARCH::callReturnValueReg)
         s[k]->clobber(UnitId(r));
      needCheck |= s[k]->callee_effect();
   }

   /* ptr X is passed to another function, clobber content at X and above */
   if (needCheck) {
      array<int64_t,3> low{oo, oo, oo};
      vector<UnitId> potential_args;

      LOG(3, "checking argument registers ... ");
      for (auto reg: ARCH::argsReg)
         potential_args.push_back(UnitId(reg));

      LOG(3, "checking argument stack ... ");
      auto curr_sp = (BaseLH*)(s[0]->value_unit(UnitId(ARCH::stackPtr)));
      if (!curr_sp->top() && !curr_sp->bot() && !BaseLH::notlocal(curr_sp) &&
      curr_sp->base() == stackSym) {
         auto range = curr_sp->range();
         auto dist = range.hi() - range.lo();
         for (int i = 0; i < dist + boundRange(REGION::STACK,1); ++i)
            potential_args.push_back(UnitId(REGION::STACK, i + range.lo()));
         BaseDomain::safe_delete(curr_sp);
      }

      for (auto& id: potential_args) {
         auto addr = (BaseLH*)(s[0]->value_unit(id));
         if (!addr->top() && !addr->bot() && !BaseLH::notlocal(addr)) {
            auto b = addr->base();
            if (b == stackSym || b == staticSym || b == 0) {
               auto r = (b == stackSym)? REGION::STACK: REGION::STATIC;
               auto l = addr->range().lo();
               if (l <= boundRange(r,1))
                  low[(int)r] = std::min(low[(int)r],std::max(boundRange(r,0),l));
            }
         }
         BaseDomain::safe_delete(addr);
      }

      /* only consider stack and static region */
      for (int rr = 1; rr <= 2; ++rr)
      if (low[rr] != oo) {
         auto r = (REGION)rr;
         LOG(3, "passing data ptr to callee "
            << (r==REGION::STACK? "(stack) ...": "(static) ..."));
         for (int k = 0; k < domainCnt; ++k)
         if (s[k]->callee_effect())
            for (int i=low[rr]; i<=boundRange(r,1); ++i) {
               auto id = UnitId(r,i);
               s[k]->update_unit(id, BaseDomain::TOP, CompareArgsId::EMPTY);
            }
      }
   }
}


void Call::preset(const array<State*,domainCnt>& s) const {
   for (int k = 0; k < domainCnt; ++k)
      if (!s[k]->fixpoint()) {
         for (auto r: ARCH::callReturnValueReg)
            s[k]->preset(UnitId(r));
      }
}


bool Call::include(RTL* subExpr) const {
   return target_->include(subExpr);
}
// ----------------------------------- Clobber ---------------------------------
Clobber::~Clobber() {
   delete expr_;
}


string Clobber::to_string() const {
   return string("(clobber ").append(expr_->to_string()).append(")");
}


bool Clobber::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (Clobber*)(*v);
   if (v2 == nullptr)
      return false;

   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return (expr_ == nullptr || expr_->equal(typeEq, v2->expr()));
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         return (expr_->equal(typeEq, v2->expr()));
      default:
         return false;
   }
}


vector<RTL*> Clobber::find(RTL_EQUAL typeEq, RTL* v) {
   vector<RTL*> vList;
   if (equal(typeEq, v))
      vList.push_back(this);
   expr_->find_helper(typeEq, v, vList);
   return vList;
}


void Clobber::execute(const array<State*,domainCnt>& s) const {
   Reg* r = (Reg*)(*expr_);
   if (r != nullptr) {
      auto id = UnitId(r->reg());
      for (int k = 0; k < domainCnt; ++k)
         s[k]->clobber(id);
   }
}


void Clobber::preset(const array<State*,domainCnt>& s) const {
   Reg* r = (Reg*)(*expr_);
   if (r != nullptr) {
      auto id = UnitId(r->reg());
      if (!id.is_flags())
      for (int k = 0; k < domainCnt; ++k)
         if (!s[k]->fixpoint())
            s[k]->preset(id);
   }
}
// ------------------------------------ Exit -----------------------------------
string Exit::to_string() const {
   switch (typeExit_) {
      case EXIT_TYPE::RET:
         return string("(simple_return)");
      case EXIT_TYPE::HALT:
         return string("(halt)");
      default:
         return string("");
   }
}


bool Exit::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (Exit*)(*v);
   if (v2 == nullptr)
      return false;

   return true;
}


vector<RTL*> Exit::find(RTL_EQUAL typeEq, RTL* v) {
   if (equal(typeEq, v))
      return(vector<RTL*>{this});
   return vector<RTL*>{};
}
/* ----------------------------------- Nop ---------------------------------- */
bool Nop::equal(RTL_EQUAL typeEq, RTL* v) const {
   if (v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v2 = (Nop*)(*v);
   if (v2 == nullptr)
      return false;

   return true;
}


vector<RTL*> Nop::find(RTL_EQUAL typeEq, RTL* v) {
   if (equal(typeEq, v))
      return(vector<RTL*>{this});
   return vector<RTL*>{};
}