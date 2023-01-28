/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef INSN_H
#define INSN_H

#include "utility.h"

namespace SBA {
   /* Forward declaration */
   class AbsState;
   class RTL;
   class Statement;
   class Expr;
   /* --------------------------------- Insn -------------------------------- */
   class Insn {
    private:
      IMM offset_;
      uint8_t size_;
      Statement* stmt_;

    private:
      enum class EDGE_OP: char {JUMP, CALL, RET, HALT};
      struct TransferInfo {
         EDGE_OP op_;
         Expr* indirectTarget_;
         pair<IMM,IMM> directTargets_;
         pair<COMPARE,COMPARE> cond_;
      };
      TransferInfo* transfer_;

    public:
      Insn(IMM offset, RTL* rtl, uint8_t size);
      ~Insn();

      /* Read accessors */
      bool empty() const {return stmt_ == nullptr;};
      IMM offset() const {return offset_;};
      IMM next_offset() const {return offset_ + (IMM)size_;};
      Statement* stmt() const {return stmt_;};
      Expr* indirect_target() const {return transfer_->indirectTarget_;};
      pair<IMM,IMM> direct_target() const {return transfer_->directTargets_;};
      pair<COMPARE,COMPARE> cond() const {return transfer_->cond_;};
      string to_string() const;

      /* Methods related to transfer check */
      bool jump() const {
         return transfer_ != nullptr && transfer_->op_ == EDGE_OP::JUMP;
      };
      bool call() const {
         return transfer_ != nullptr && transfer_->op_ == EDGE_OP::CALL;
      };
      bool ret() const {
         return transfer_ != nullptr && transfer_->op_ == EDGE_OP::RET;
      };
      bool halt() const {
         return transfer_ != nullptr && transfer_->op_ == EDGE_OP::HALT;
      };
      bool transfer() const {
         return transfer_ != nullptr && transfer_->op_ != EDGE_OP::HALT;
      };
      bool direct() const {
         return (jump() || call()) && transfer_->indirectTarget_ == nullptr;
      };
      bool indirect() const {
         return (jump() || call()) && transfer_->indirectTarget_ != nullptr;
      };
      bool cond_jump() const {
         return transfer_ != nullptr && transfer_->cond_.first != COMPARE::NONE;
      };

      /* Methods related to static analysis */
      void execute(const array<AbsState*,DOMAIN_NUM>& s) const;
      void preset(const array<AbsState*,DOMAIN_NUM>& s) const;

    private:
      /* Methods related to CFG construction */
      void process_transfer();
   };

}

#endif
