/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "insn.h"
#include "state.h"
#include "rtl.h"
#include "expr.h"
#include "arithmetic.h"

using namespace SBA;
// ---------------------------------- Insn -------------------------------------
Insn::Insn(IMM offset, RTL* rtl, uint8_t size) {
   offset_ = offset;
   size_ = size;
   stmt_ = (Statement*)rtl;
   transfer_ = nullptr;
   process_transfer();
}


Insn::~Insn() {
   if (!empty())
      delete stmt_;
   if (transfer_ != nullptr)
      delete transfer_;
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
      if (!vec.empty()) {
         tmp = vec.front();
         auto target = ((Mem*)(((Call*)tmp)->target()))->addr();
         switch (target->expr_type()) {
            /* direct transfer */
            case Expr::EXPR_TYPE::CONSTANT:
               transfer_ = new TransferInfo {
                               EDGE_OP::CALL,
                               nullptr,
                               {((Const*)target)->to_int(), next_offset()},
                               {COMPARE::NONE, COMPARE::NONE}
                           };
               break;
            /* indirect transfer */
            default:
               transfer_ = new TransferInfo {
                               EDGE_OP::CALL,
                               target,
                               {next_offset(), -1},
                               {COMPARE::NONE, COMPARE::NONE}
                           };
               break;
         }
         return;
      }

      /* (set pc ..) */
      tmp = new Assign(new NoType("pc"), nullptr);
      vec = stmt_->find(RTL_EQUAL::PARTIAL, tmp);
      delete tmp;
      if (!vec.empty()) {
         tmp = vec.front();
         auto target = ((Assign*)tmp)->src();
         switch (target->expr_type()) {
            /* direct transfer */
            /* --> (set pc (const_int ..)) */
            case Expr::EXPR_TYPE::CONSTANT:
               transfer_ = new TransferInfo {
                               EDGE_OP::JUMP,
                               nullptr,
                               {((Const*)target)->to_int(), -1},
                               {COMPARE::NONE, COMPARE::NONE}
                           };
               break;
            /* --> (set pc (if_then_else (cond) (..) (..))) */
            case Expr::EXPR_TYPE::IFELSE: {
               auto ifel = (IfElse*)target;
               pair<COMPARE,COMPARE> cond;
               switch (ifel->cmp()->op()) {
                  case Compare::OP::EQ:
                     cond = {COMPARE::EQ, COMPARE::NE};
                     break;
                  case Compare::OP::NE:
                     cond = {COMPARE::NE, COMPARE::EQ};
                     break;
                  case Compare::OP::GT:
                  case Compare::OP::GTU:
                     cond = {COMPARE::GT, COMPARE::LE};
                     break;
                  case Compare::OP::GE:
                  case Compare::OP::GEU:
                     cond = {COMPARE::GE, COMPARE::LT};
                     break;
                  case Compare::OP::LT:
                  case Compare::OP::LTU:
                     cond = {COMPARE::LT, COMPARE::GE};
                     break;
                  case Compare::OP::LE:
                  case Compare::OP::LEU:
                     cond = {COMPARE::LE, COMPARE::GT};
                     break;
                  default:
                     cond = {COMPARE::OTHER, COMPARE::OTHER};
                     break;
               }
               auto a = ifel->if_expr();
               auto b = ifel->else_expr();
               auto t = (a->to_string().compare("pc") == 0)?
                        pair<IMM,IMM>{next_offset(), ((Const*)b)->to_int()}:
                        pair<IMM,IMM>{((Const*)a)->to_int(), next_offset()};
               transfer_ = new TransferInfo {
                               EDGE_OP::JUMP,
                               nullptr,
                               t,
                               cond
                           };
               break;
            }
            /* indirect transfer */
            /* --> (set pc (reg ..)) */
            /* --> (set pc (mem ..)) */
            case Expr::EXPR_TYPE::VAR: {
               transfer_ = new TransferInfo {
                               EDGE_OP::JUMP,
                               target,
                               {-1, -1},
                               {COMPARE::NONE, COMPARE::NONE}
                           };
               break;   
            }
            default:
               break;
        }
        return;
      }

      /* exit instruction */
      if (stmt_->stmt_type() == Statement::STATEMENT_TYPE::EXIT) {
         auto e = (Exit*)stmt_;
         transfer_ = new TransferInfo {
                         e->exit_type()==Exit::EXIT_TYPE::RET? EDGE_OP::RET:
                                                               EDGE_OP::HALT,
                         nullptr,
                         {-1, -1},
                         {COMPARE::NONE, COMPARE::NONE}
                     };
      }
   }
}


void Insn::execute(const array<AbsState*,DOMAIN_NUM>& s) const {
   if (!empty()) {
      LOG3("------------------------ insn " << offset_
          << " ------------------------");
      LOG4(stmt_->to_string());
      /* set location */
      FOR_STATE(s, k, true, {
         s[k]->loc.insn = (Insn*)this;
      });
      /* execute insn */
      stmt_->execute(s);
      /* commit insn channel to block channel */
      FOR_STATE(s, k, true, {
         s[k]->commit(CHANNEL::INSN);
      });
   }
}
