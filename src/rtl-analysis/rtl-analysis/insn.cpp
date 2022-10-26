/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "insn.h"
#include "state.h"
#include "rtl.h"
#include "expr.h"
#include "arithmetic.h"
// ---------------------------------- Insn -------------------------------------
Insn::Insn(int64_t offset, RTL* rtl, int size) {
   offset_ = offset;
   size_ = size;
   stmt_ = (Statement*)rtl;
   type_ = EDGE_TYPE::NONE;
   op_ = EDGE_OP::NONE;
   indirectTarget_ = nullptr;
   directTargets_.first = -1;
   directTargets_.second = -1;
   cond_.first = COMPARE::NONE;
   cond_.second = COMPARE::NONE;
   process_transfer();
}


Insn::~Insn() {
   // if (!empty())
   //    delete stmt_;
}


string Insn::to_string() const {
   return empty() ? string("") : stmt_->to_string();
}


void Insn::process_transfer() {
   if (!empty()) {
      RTL* tmp;
      vector<RTL*> vec;

      /* (call (mem (reg ..)) */
      /* (call (mem (mem ..))) */
      /* (call (mem (const_int ..))) */
      tmp = new Call(nullptr);
      vec = stmt_->find(RTL_EQUAL::OPCODE, tmp);
      delete tmp;
      if (vec.size() != 0) {
         tmp = vec.front();
         auto target = ((Mem*)(((Call*)tmp)->target()))->addr();
         switch (target->expr_type()) {
            /* direct transfer */
            case Expr::EXPR_TYPE::CONSTANT:
               type_ = EDGE_TYPE::DIRECT;
               directTargets_.first = ((Const*)(*target))->to_int();
               directTargets_.second = next_offset();
               cond_.first = COMPARE::NONE;
               cond_.second = COMPARE::NONE;
               break;
            /* indirect transfer */
            default:
               type_ = EDGE_TYPE::INDIRECT;
               indirectTarget_ = target;
               directTargets_.first = next_offset();
               cond_.first = COMPARE::NONE;
               break;
         }
         op_ = EDGE_OP::CALL;
         return;
      }
      vec.clear();

      /* (set pc ..) */
      tmp = new Assign(new NoType("pc"), nullptr);
      vec = stmt_->find(RTL_EQUAL::PARTIAL, tmp);
      delete tmp;
      if (vec.size() != 0) {
         tmp = vec.front();
         auto target = ((Assign*)tmp)->src();
         switch (target->expr_type()) {
            /* direct transfer */
            /* --> (set pc (const_int ..)) */
            case Expr::EXPR_TYPE::CONSTANT: {
               type_ = EDGE_TYPE::DIRECT;
               directTargets_.first = ((Const*)(*target))->to_int();
               cond_.first = COMPARE::NONE;
               break;
            }
            /* --> (set pc (if_then_else (cond) (..) (..))) */
            case Expr::EXPR_TYPE::IF_ELSE: {
               type_ = EDGE_TYPE::DIRECT;
               auto ifel = (IfElse*)target;
               /* retrieve comparison operator */
               switch (ifel->cmp()->op()) {
                  case Compare::OP::EQ:
                     cond_.first = COMPARE::EQ;
                     cond_.second = COMPARE::NE;
                     break;
                  case Compare::OP::NE:
                     cond_.first = COMPARE::NE;
                     cond_.second = COMPARE::EQ;
                     break;
                  case Compare::OP::GT:
                  case Compare::OP::GTU:
                     cond_.first = COMPARE::GT;
                     cond_.second = COMPARE::LE;
                     break;
                  case Compare::OP::GE:
                  case Compare::OP::GEU:
                     cond_.first = COMPARE::GE;
                     cond_.second = COMPARE::LT;
                     break;
                  case Compare::OP::LT:
                  case Compare::OP::LTU:
                     cond_.first = COMPARE::LT;
                     cond_.second = COMPARE::GE;
                     break;
                  case Compare::OP::LE:
                  case Compare::OP::LEU:
                     cond_.first = COMPARE::LE;
                     cond_.second = COMPARE::GT;
                     break;
                  default:
                     cond_.first = COMPARE::OTHER;
                     cond_.second = COMPARE::OTHER;
                     break;
               }
               /* retrieve two targets in order */
               auto branch = vector<Expr*>{ifel->if_expr(),ifel->else_expr()};
               directTargets_.first = (branch[0]->to_string().compare("pc")==0)?
                                 next_offset(): ((Const*)branch[0])->to_int();
               directTargets_.second = (branch[1]->to_string().compare("pc")==0)?
                                 next_offset(): ((Const*)branch[1])->to_int();
               break;
            }
            /* indirect transfer */
            /* --> (set pc (reg ..)) */
            /* --> (set pc (mem ..)) */
            case Expr::EXPR_TYPE::VAR: {
               type_ = EDGE_TYPE::INDIRECT;
               indirectTarget_ = target;
               break;   
            }
            default:
               break;
        }
        op_ = EDGE_OP::JUMP;
        return;
      }
      vec.clear();

      /* exit instruction */
      auto exit = (Exit*)(*stmt_);
      if (exit != nullptr) {
         switch (exit->exit_type()) {
            case Exit::EXIT_TYPE::RET:
               type_ = EDGE_TYPE::INDIRECT;
               op_ = EDGE_OP::RET;
               break;
            case Exit::EXIT_TYPE::HALT:
               type_ = EDGE_TYPE::EXIT;
               op_ = EDGE_OP::HALT;
               break;
            default:
               break;
         }
      }
   }
}


void Insn::execute(const array<State*,domainCnt>& s) const {
   if (!empty()) {
      LOG(3, "------------ insn " << offset_ << " ------------");
      LOG(4, stmt_->to_string());
      /* set location */
      for (auto ss: s)
         ss->loc().insn = (Insn*)this;
      /* execute insn */
      stmt_->execute(s);
      /* commit insn channel to block channel */
      for (auto ss: s)
         ss->commit(CHANNEL::INSN);
   }
}


void Insn::preset(const array<State*,domainCnt>& s) const {
   if (!empty()) {
      for (auto ss: s)
         ss->loc().insn = (Insn*)this;
      stmt_->preset(s);
      for (auto ss: s)
         ss->commit(CHANNEL::INSN);
   }
}