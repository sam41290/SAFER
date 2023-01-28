/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef RTL_H
#define RTL_H

#include "utility.h"

namespace SBA {
   /* Forward declaration */
   class AbsState;
   class BaseDomain;
   class Statement;
   class Parallel;
   class Sequence;
   class Assign;
   class Call;
   class Clobber;
   class Exit;
   class Nop;
   class Expr;
   class Const;
   class Var;
   class Mem;
   class Reg;
   class Arithmetic;
   class Unary;
   class Binary;
   class SubReg;
   class IfElse;
   class Conversion;
   class Compare;
   class NoType;
   enum class RTL_TYPE: char {STATEMENT, EXPR};
   enum class RTL_EQUAL: char {STRICT, RELAXED, PARTIAL, OPCODE};
   /* --------------------------------- RTL --------------------------------- */
   class RTL {
    private:
      RTL_TYPE typeRTL_;

    public:
      RTL(RTL_TYPE typeRTL) {typeRTL_ = typeRTL;};
      virtual ~RTL() {};

      // (a) STRICT:  identical
      // (b) RELAXED: same as (a), but ignore mode
      // (c) PARTIAL: same as (b), but allow some parts to be arbitrary
      // (d) OPCODE:  either identical opcode, or v opcode is ANY
      virtual bool equal(RTL_EQUAL typeEq, RTL* v) const = 0;
      virtual string to_string() const = 0;
      virtual vector<RTL*> find(RTL_EQUAL typeEq, RTL* v) = 0;
      void find_helper(RTL_EQUAL typeEq, RTL* v, vector<RTL*>& vList) {
         auto t = find(typeEq, v);
         vList.insert(vList.end(), t.begin(), t.end());
      };
      virtual bool contains(RTL* subExpr) const {return this == subExpr;};
      virtual RTL* find_container(RTL* subExpr,
              const function<bool(const RTL*)>& select) const {return nullptr;};
      RTL_TYPE rtl_type() const {return this->typeRTL_;};

      /* typecast */
      operator Statement*() const;
      operator Parallel*() const;
      operator Sequence*() const;
      operator Assign*() const;
      operator Call*() const;
      operator Clobber*() const;
      operator Exit*() const;
      operator Nop*() const;
      operator Expr*() const;
      operator Const*() const;
      operator Var*() const;
      operator Mem*() const;
      operator Reg*() const;
      operator Arithmetic*() const;
      operator Unary*() const;
      operator Binary*() const;
      operator Compare*() const;
      operator SubReg*() const;
      operator IfElse*() const;
      operator Conversion*() const;
      operator NoType*() const;
   };
   /* ------------------------------ Statement ------------------------------ */
   class Statement: public RTL {
    public:
      enum class STATEMENT_TYPE: char {ASSIGN, CALL, SEQUENCE, PARALLEL,
                                       CLOBBER, EXIT, NOP};

    private:
      Statement::STATEMENT_TYPE typeStatement_;

    public:
      Statement(STATEMENT_TYPE type);
      virtual ~Statement() {};

      /* Read accessors */
      STATEMENT_TYPE stmt_type() const {return typeStatement_;};

      /* Methods related to static analysis */
      virtual void execute(const array<AbsState*,DOMAIN_NUM>& s) const {};
      virtual void preset_list(unordered_set<ARCH::REG>& rList) const {};
      virtual Value eval(const array<AbsState*,DOMAIN_NUM>& s,
                         Expr* subExpr) const;
   };
   /* ------------------------------ Parallel ------------------------------- */
   class Parallel: public Statement {
    private:
      vector<Statement*> stmts_;

    public:
      Parallel(const vector<Statement*>& _stmts);
      ~Parallel();

      /* Read accessors */
      string to_string() const;
      bool equal(RTL_EQUAL typeEq, RTL* v) const;
      vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);
      const vector<Statement*>& stmts() const {return stmts_;};

      /* Methods related to static analysis */
      void execute(const array<AbsState*,DOMAIN_NUM>& s) const;
      void preset_list(unordered_set<ARCH::REG>& rList) const;

      /* Methods related to helper methods */
      bool contains(RTL* subExpr) const override;
      RTL* find_container(RTL* subExpr, const function<bool(const RTL*)>&
                          select) const override;
   };
   /* ------------------------------ Sequence ------------------------------- */
   class Sequence: public Statement {
    private:
      vector<Statement*> stmts_;

    public:
      Sequence(const vector<Statement*>& stmts);
      ~Sequence();

      /* Read accessors */
      string to_string() const;
      bool equal(RTL_EQUAL typeEq, RTL* v) const;
      vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);
      const vector<Statement*>& stmts() const {return stmts_;};

      /* Methods related to static analysis */
      void execute(const array<AbsState*,DOMAIN_NUM>& s) const;
      void preset_list(unordered_set<ARCH::REG>& rList) const;
      Value eval(const array<AbsState*,DOMAIN_NUM>& s, Expr* subExpr) const;

      /* Methods related to helper methods */
      bool contains(RTL* subExpr) const override;
      RTL* find_container(RTL* subExpr, const function<bool(const RTL*)>&
                          select) const override;
   };
   /* ------------------------------- Assign -------------------------------- */
   class Assign: public Statement {
    private:
      Expr* dst_;
      Expr* src_;

    public:
      Assign(Expr* dst, Expr* src);
      ~Assign();

      /* Read accessors */
      string to_string() const;
      bool equal(RTL_EQUAL typeEq, RTL* v) const;
      vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);
      Expr* dst() const {return dst_;};
      Expr* src() const {return src_;};

      /* Methods related to static analysis */
      void execute(const array<AbsState*,DOMAIN_NUM>& s) const;
      void preset_list(unordered_set<ARCH::REG>& rList) const;

      /* Methods related to helper methods */
      bool contains(RTL* subExpr) const override;
      RTL* find_container(RTL* subExpr, const function<bool(const RTL*)>&
                          select) const override;
   };
   /* -------------------------------- Call --------------------------------- */
   class Call: public Statement {
    private:
      Mem* target_;

    public:
      Call(Mem* target): Statement(STATEMENT_TYPE::CALL) {target_ = target;};
      ~Call();

      /* Read accessors */
      string to_string() const;
      bool equal(RTL_EQUAL typeEq, RTL* v) const;
      vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);
      Mem* target() const {return target_;};

      /* Methods related to static analysis */
      void execute(const array<AbsState*,DOMAIN_NUM>& s) const;
      void preset_list(unordered_set<ARCH::REG>& rList) const;

      /* Methods related to helper methods */
      bool contains(RTL* subExpr) const override;
      RTL* find_container(RTL* subExpr, const function<bool(const RTL*)>&
                          select) const override;
   };
   /* ------------------------------- Clobber ------------------------------- */
   class Clobber: public Statement {
    private:
      Expr* expr_;

    public:
      Clobber(Expr* expr): Statement(STATEMENT_TYPE::CLOBBER) {expr_ = expr;};
      ~Clobber();
 
      /* Read accessors */
      string to_string() const;
      bool equal(RTL_EQUAL typeEq, RTL* v) const;
      vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);
      Expr* expr() const {return expr_;};

      /* Methods related to static analysis */
      void execute(const array<AbsState*,DOMAIN_NUM>& s) const;
      void preset_list(unordered_set<ARCH::REG>& rList) const;

      /* Methods related to helper methods */
      bool contains(RTL* subExpr) const override;
      RTL* find_container(RTL* subExpr, const function<bool(const RTL*)>&
                          select) const override;
   };
   /* -------------------------------- Exit --------------------------------- */
   class Exit: public Statement {
    public:
      enum class EXIT_TYPE: char {RET, HALT};

    private:
      EXIT_TYPE typeExit_;

    public:
      Exit(EXIT_TYPE type): Statement(STATEMENT_TYPE::EXIT) {typeExit_ = type;};
      ~Exit() {};

      /* Read accessors */
      string to_string() const;
      bool equal(RTL_EQUAL typeEq, RTL* v) const;
      vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);
      EXIT_TYPE exit_type() {return typeExit_;};

      /* Methods related to static analysis */
      void execute(const array<AbsState*,DOMAIN_NUM>& s) const;

      /* Methods related to helper methods */
      bool contains(RTL* subExpr) const override {return this == subExpr;};
      RTL* find_container(RTL* subExpr, const function<bool(const RTL*)>&
                          select) const override;
   };
   /* --------------------------------- Nop --------------------------------- */
   class Nop: public Statement {
    public:
      Nop(): Statement(STATEMENT_TYPE::NOP) {};
      ~Nop() {};

      /* Read accessors */
      string to_string() const {return string("nop");};
      bool equal(RTL_EQUAL typeEq, RTL* v) const;
      vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);

      /* Methods related to helper methods */
      bool contains(RTL* subExpr) const override {return this == subExpr;};
      RTL* find_container(RTL* subExpr, const function<bool(const RTL*)>&
                          select) const override;
   };

}

#endif
