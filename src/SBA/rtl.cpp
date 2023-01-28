/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "rtl.h"
#include "function.h"
#include "insn.h"
#include "state.h"
#include "domain.h"
#include "expr.h"
#include "arithmetic.h"

using namespace SBA;
// ------------------------------------ RTL ------------------------------------
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
   return t->expr_type()==Expr::EXPR_TYPE::IFELSE ? (IfElse*)this : nullptr;
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


Value Statement::eval(const array<AbsState*,DOMAIN_NUM>& s,Expr* subExpr) const {
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


void Parallel::execute(const array<AbsState*,DOMAIN_NUM>& s) const {
   for (auto stmt: stmts_)
      if ((NoType*)(*((RTL*)stmt)) == nullptr)
         stmt->execute(s);
}


void Parallel::preset_list(unordered_set<ARCH::REG>& rList) const {
   for (auto stmt: stmts_)
      if ((NoType*)(*((RTL*)stmt)) == nullptr)
         stmt->preset_list(rList);
}


bool Parallel::contains(RTL* subExpr) const {
   if (this == subExpr)
      return true;
   for (auto stmt: stmts_)
      if (stmt->contains(subExpr))
         return true;
   return false;
}


RTL* Parallel::find_container(RTL* subExpr, const function<bool(const RTL*)>&
select) const {
   if (select(this) && contains(subExpr))
      return (RTL*)this;
   for (auto stmt: stmts_) {
      auto v = stmt->find_container(subExpr, select);
      if (v != nullptr)
         return v;
   }
   return nullptr;
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


void Sequence::execute(const array<AbsState*,DOMAIN_NUM>& s) const {
   for (auto stmt: stmts_)
      if ((NoType*)(*((RTL*)stmt)) == nullptr) {
         /* commit previous stmt, not commit at first stmt */
         /* last stmt will be committed outside */
         FOR_STATE(s, k, true, {
            s[k]->commit(CHANNEL::INSN);
         });
         stmt->execute(s);
      }
}


void Sequence::preset_list(unordered_set<ARCH::REG>& rList) const {
   for (auto stmt: stmts_)
      if ((NoType*)(*((RTL*)stmt)) == nullptr)
         stmt->preset_list(rList);
}


Value Sequence::eval(const array<AbsState*,DOMAIN_NUM>& s, Expr* subExpr) const {
   for (auto stmt: stmts_) {
      if (stmt->contains(subExpr))
         return subExpr->eval(s);
      if ((NoType*)(*((RTL*)stmt)) == nullptr)
         stmt->execute(s);
   }
   return Statement::eval(s, subExpr);
}


bool Sequence::contains(RTL* subExpr) const {
   if (this == subExpr)
      return true;
   for (auto stmt: stmts_)
      if (stmt->contains(subExpr))
         return true;
   return false;
}


RTL* Sequence::find_container(RTL* subExpr, const function<bool(const RTL*)>&
select) const {
   if (select(this) && contains(subExpr))
      return (RTL*)this;
   for (auto stmt: stmts_) {
      auto v = stmt->find_container(subExpr, select);
      if (v != nullptr)
         return v;
   }
   return nullptr;
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


void Assign::execute(const array<AbsState*,DOMAIN_NUM>& s) const {
   EXECUTE_ASSIGN(s);
}


void Assign::preset_list(unordered_set<ARCH::REG>& rList) const {
   IF_RTL_TYPE(Reg, dst_->simplify(), reg, {
      rList.insert(reg->reg());
   }, {});
}


bool Assign::contains(RTL* subExpr) const {
   return this == subExpr || dst_->contains(subExpr) || src_->contains(subExpr);
}


RTL* Assign::find_container(RTL* subExpr, const function<bool(const RTL*)>&
select) const {
   if (select(this) && contains(subExpr))
      return (RTL*)this;
   auto v = dst_->find_container(subExpr, select);
   if (v == nullptr)
      v = src_->find_container(subExpr, select);
   return v;
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


void Call::execute(const array<AbsState*,DOMAIN_NUM>& s) const {
   EXECUTE_CALL(s);
}


void Call::preset_list(unordered_set<ARCH::REG>& rList) const {
   for (auto r: ARCH::return_value)
      rList.insert(r);
}


bool Call::contains(RTL* subExpr) const {
   return this == subExpr || target_->contains(subExpr);
}


RTL* Call::find_container(RTL* subExpr, const function<bool(const RTL*)>&
select) const {
   if (select(this) && contains(subExpr))
      return (RTL*)this;
   return target_->find_container(subExpr, select);
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


void Clobber::execute(const array<AbsState*,DOMAIN_NUM>& s) const {
   IF_RTL_TYPE(Reg, expr_, reg, {
      auto const& id = get_id(reg->reg());
      FOR_STATE(s, k, true, {
         s[k]->clobber(id);
      });
   }, {});
}


void Clobber::preset_list(unordered_set<ARCH::REG>& rList) const {
   IF_RTL_TYPE(Reg, expr_, reg, {
      auto r = reg->reg();
      if (r != ARCH::flags)
         rList.insert(r);
   }, {});
}


bool Clobber::contains(RTL* subExpr) const {
   return this == subExpr || expr_->contains(subExpr);
}


RTL* Clobber::find_container(RTL* subExpr, const function<bool(const RTL*)>&
select) const {
   if (select(this) && contains(subExpr))
      return (RTL*)this;
   return expr_->find_container(subExpr, select);
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


RTL* Exit::find_container(RTL* subExpr, const function<bool(const RTL*)>&
select) const {
   return select(this) && contains(subExpr)? (RTL*)this: nullptr;
}


void Exit::execute(const array<AbsState*,DOMAIN_NUM>& s) const {
   EXECUTE_EXIT(s);
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


RTL* Nop::find_container(RTL* subExpr, const function<bool(const RTL*)>&
select) const {
   return select(this) && contains(subExpr)? (RTL*)this: nullptr;
}
