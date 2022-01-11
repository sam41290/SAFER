/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef BASICBLOCK_H
#define BASICBLOCK_H

#include "expr.h"
#include <map>

using namespace std;

class Insn {
    public:
        int64 offset;
        Expr* expr;
        Insn* prevInsn;
        Insn* nextInsn;
        char transferType;
        char isInvalidInsn;
        vector<int64> directTargets;
        vector<MathExpr*> indirectTargets;
        void get_transfer_target(char checkType);
        vector<string> get_regs_to_track(const vector<string> &_regs);
        vector<vector<MathExpr*>> update_val_of_regs(const vector<string> &_regs,
                vector<string> &fromRegs, vector<vector<MathExpr*>> &fromVals);
        void apply_side_effect(const vector<string> &regs, vector<vector<MathExpr*>> &vals);
        void supply_reg_ip(vector<string> &regs, vector<vector<MathExpr*>> &vals);
        void print();
        Insn(int64 _offset, Expr* _expr);
        ~Insn();
    private:
};

class BasicBlock {
    public:
        int64 offset;
        map<int64,Insn*> offset_insn;
        void add_insn(Insn* v);
        Insn* get_insn(int64 offset);
        BasicBlock();
    private:
        Insn* tmp;
};

#endif