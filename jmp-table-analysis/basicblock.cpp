/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include "basicblock.h"

using namespace std;
// ---------------------------------- Insn ------------------------------------
Insn::Insn(int64 _offset, Expr* _expr) {
    offset = _offset;
    expr = _expr;
    prevInsn = NULL;
    nextInsn = NULL;
    this->isInvalidInsn = expr->isInvalidExpr;
    // update transferType only, not get targets
    // because transfer insns using "pc" requires nextInsn (not always available)
    if (!this->isInvalidInsn)
        get_transfer_target(CHECK_TRANSFER_TYPE);
}

Insn::~Insn() {
    // adjust prevInsn and nextInsn
    if (prevInsn != NULL)
        prevInsn->nextInsn = NULL;
    if (nextInsn != NULL)
        nextInsn->prevInsn = NULL;
    // clear object
    delete expr;
    // clear vector
    MathExpr::clear(indirectTargets);
}
// ----------- find what set of regs to be tracked to determine _regs -----------
vector<string> Insn::get_regs_to_track(const vector<string> &_regs) {
    // if insn is empty
    if (!this->isInvalidInsn) {
        vector<string> regs;
        set<string> t = expr->get_regs_to_track(_regs);
        regs.assign(t.begin(), t.end());
        return regs;
    }
    // if insn is empty, track _regs
    else
        return _regs;
}

// -------------- update val of _regs using fromVals of fromRegs ----------------
vector<vector<MathExpr*>> Insn::update_val_of_regs(const vector<string> &_regs,
vector<string> &fromRegs, vector<vector<MathExpr*>> &fromVals) {
    // if insn is not empty, apply vals of regs into _regs
    if (!this->isInvalidInsn) {
        // after recursive call, handle special register: instruction pointer
        supply_reg_ip(fromRegs, fromVals);
        // substitution-oriented assignment
        return expr->update_val_of_regs(_regs, fromRegs, fromVals);
    }
    // if insn is empty, result = vals because regs = _regs
    else
        return MathExpr::clone(fromVals);
}

// ------------------------ apply side effect to regs ---------------------------
void Insn::apply_side_effect(const vector<string> &regs, vector<vector<MathExpr*>> &vals) {
    // ignore if insn is empty
    if (this->isInvalidInsn)
        return;

    string r;
    int rSize;
    set<string> regSet(regs.begin(), regs.end());

    vector<string>::iterator it1;
    vector<Expr*>::iterator it2;
    vector<string>::const_iterator it3;
    vector<vector<MathExpr*>>::iterator it4;
    vector<MathExpr*>::iterator it5;
    // for each side-effect opcode
    for (it1 = MathExpr::sideEffectOpList.begin(); it1 != MathExpr::sideEffectOpList.end(); ++it1) {
        // t cannot be deleted because it points to the actual object, not a copy
        vector<Expr*> t = expr->find_opcode_all(*it1);
        // for each side-effect with that operator
        for (it2 = t.begin(); it2 != t.end(); ++it2) {
            MathExpr* v = (*it2)->estimate_val();
            // extract opSize
            // NOTE: currently non-integer modes are out of support
            if (MathExpr::modeLenMap.find((*it2)->mode) == MathExpr::modeLenMap.end())
                continue;
            string opSize = MathExpr::modeLenMap[(*it2)->mode];
            // extract information, only ext-op between side-effect-op and reg
            list<string>::iterator mIt = v->mathExpr.begin();
            v->find_non_ext_op(mIt);    // return 0, mIt points to reg
            MathExpr::extract_reg(*mIt, r, rSize);
            if (regSet.find(r) == regSet.end())
                continue;

            list<string> mexpr;
            // --- two cases when applying side-effect
            // --- 1. pre/post_inc/dec with 1 operand {reg}
            //        replace into an interpreted mathExpr:
            //                   ++i, i++ becomes i + opSize
            //                   --i, i-- becomes i - opSize
            if ((*it1).find("_modify") == string::npos) {
                // --- a. add op_size
                if ((*it1).find("_inc") != string::npos)
                    mexpr.push_back("+_" + opSize);
                else
                    mexpr.push_back("-_" + opSize);
                // --- b. add reg_size
                mexpr.push_back(*mIt);
                // --- c. add offset
                mexpr.push_back(opSize);
            }
            // --- 2. pre/post_modify with 2 operands {reg, mathExpr}
            //        replace into mathExpr
            //        choose opSize = min(mathExprOpSize, sideEffectOpSize)
            else {
                ++mIt;
                list<string>::iterator mIt2 = v->next_element(mIt);
                // add op_size
                ++mIt;
                string rr;
                int rrSize;
                int opSizeInt = stoi(opSize);
                MathExpr::extract_op(*mIt, rr, rrSize);
                if (rrSize < opSizeInt)
                    mexpr.push_back(*mIt);
                else
                    mexpr.push_back(rr + "_" + opSize);
                // add other operands
                ++mIt;
                for (; mIt != mIt2; ++mIt)
                    mexpr.push_back(*mIt);
            }
            // v can be deleted because it is generated only to compute mexpr
            delete v;
            // --- apply to each available value for reg "r"
            MathExpr* v2 = new MathExpr(mexpr);
            for (it3 = regs.begin(); it3 != regs.end(); ++it3, ++it4)
                if ((*it3).compare(r) == 0) {
                    for (it5 = (*it4).begin(); it5 != (*it4).end(); ++it5)
                        *it5 = v2->substitute(r, *it5);
                    break;
                }
            // v2 can be deleted since *it5 takes (v2->substitute) which is a copy of v2
            delete v2;
        }
    }
}

// ------------------ find and categorize all transfer targets ------------------
void Insn::get_transfer_target(char checkType) {
    Expr *t, *tt, *ttt;
    transferType = NO_TRANSFER;
    // (call (mem (mem ..)))
    // (call (mem (symbol_ref ..)))
    t = expr->find_opcode("call");
    if (t != NULL && t->get_expr(0)->type == V_MEM) {
        t = t->get_expr(0);
        transferType = ((Mem*)t)->accessType;
        if (checkType == CHECK_TRANSFER_TYPE) return;
        switch (transferType) {
            case INDIRECT_TARGET:
                indirectTargets.push_back(((Mem*)t)->indirectTarget);
                break;
            case DIRECT_TARGET:
                directTargets.push_back(((Mem*)t)->directTarget);
                break;
            default:
                break;
        }
    }
    // (set pc ..)
    t = expr->find_opcode("set");
    if (t != NULL) {
        tt = t->get_expr(0);
        if (tt->type == V_GENERALTYPE && tt->s.compare("pc") == 0) {
            tt = t->get_expr(1);
            switch (tt->type) {
                // direct transfer:
                // (set pc (label_ref ..))
                // (set pc (if_then_else (cond) (..) pc) --> only direct for now
                case V_REF:
                    transferType = DIRECT_TARGET;
                    if (checkType == CHECK_TRANSFER_TYPE)
                        return;
                    directTargets.push_back(((Ref*)tt)->offset);
                    break;
                case V_IF_ELSE:
                    transferType = DIRECT_TARGET;
                    if (checkType == CHECK_TRANSFER_TYPE)
                        return;
                    // target_if
                    ttt = ((IfElse*)tt)->target_if;
                    if (ttt->type == V_REF)
                        directTargets.push_back(((Ref*)ttt)->offset);
                    // target_else
                    ttt = ((IfElse*)tt)->target_else;
                    if (ttt->type == V_GENERALTYPE && ttt->s.compare("pc") == 0)
                        directTargets.push_back(this->nextInsn->offset);
                    break;
                // indirect transfer:
                // (set pc (reg ..)) --> only reg, no in-place math for now
                case V_REG:
                    transferType = INDIRECT_TARGET;
                    if (checkType == CHECK_TRANSFER_TYPE)
                        return;
                    indirectTargets.push_back(new MathExpr(tt));
                    break;
                default:
                    break;
            }
        }
    }
    // indirect transfer
    // (simple_return) -> target = M[rsp]
    if (expr->s.find("simple_return") != string::npos) {
        transferType = INDIRECT_TARGET;
        if (checkType == CHECK_TRANSFER_TYPE)
            return;
        Expr* tttt = new Expr("(mem (reg sp mode:DI) mode:DI)");
        indirectTargets.push_back(new MathExpr(tttt));
        delete tttt;
    }
    // t, tt, ttt cannot be deleted, it's part of expr that will be deleted in destructor
}

// -------------------------- tools for other purposes --------------------------
void Insn::supply_reg_ip(vector<string> &regs, vector<vector<MathExpr*>> &vals) {
    // no symbolic means "ip" in mathExpr equivalent to "%rip"
    if (nextInsn != NULL && expr->s.find("ip") != string::npos) {
        vector<MathExpr*> t;
        Const* tt = new Const(nextInsn->offset);
        t.push_back(tt->estimate_val());
        regs.push_back("ip_64");
        vals.push_back(t);
        // clear tt
        delete tt;
    }
}

void Insn::print() {
    expr->print();
}

// ------------------------------------------------------------------------------
// -------------------------------- Basic Block ---------------------------------
// ------------------------------------------------------------------------------
BasicBlock::BasicBlock() {
    offset = -1;
    tmp = NULL;
}

void BasicBlock::add_insn(Insn* v) {
    // block offset = first insn offset
    if (offset == -1)
        offset = v->offset;
    // link to previous instruction
    if (tmp != NULL) {
        v->prevInsn = tmp;
        tmp->nextInsn = v;
    }
    tmp = v;
    // add insn to map
    offset_insn.insert(pair<int64,Insn*>(v->offset, v));
}

Insn* BasicBlock::get_insn(int64 _offset) {
    map<int64,Insn*>::iterator it = offset_insn.find(_offset);
    if (it != offset_insn.end())
        return it->second;
    return NULL;
}