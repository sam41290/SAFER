/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include "expr.h"

using namespace std;

// --------------------------------- Expression ---------------------------------
Expr::Expr(const string& x) {
    if (x.compare("") == 0) {
        this->isInvalidExpr = 1;
        return;
    }

    this->isInvalidExpr = 0;
    s = x;
    type = Expr::get_type(s);
    if (type != V_GENERALTYPE) {
        if (type != V_PARALLEL) {
            op = Expr::get_opcode(s);
            mode = Expr::get_mode(s);
        }
        Expr::extract_operands();
    }
}

Expr::~Expr() {
    // delete subExpr
    vector<Expr*>::iterator it = subExpr.begin();
    for (; it != subExpr.end(); ++it)
        delete (*it);
}

// -------------------------- parse all sub-expressions -------------------------
void Expr::extract_operands() {
    size_t pos, pos2, t1, t2;
    int bracket;

    pos = s.find(' ') + 1;
    while (1) {
        // " GeneralType " or " GeneralType)"
        //   | <- pos           | <- pos
        if (s.at(pos) != '(') {
            t1 = s.find(' ', pos+1);
            t2 = s.find(')', pos+1);
            add_expr(s.substr(pos, min(t1,t2) - pos));
            if (this->isInvalidExpr)
                return;
            if (t2 < t1) return;
            pos = t1 + 1;
        }
        // " (...)"
        //   | <- pos
        else {
            pos2 = pos;
            bracket = 1;
            while (pos2 != string::npos) {
                t1 = s.find('(', pos2+1);
                t2 = s.find(')', pos2+1);
                pos2 = min(t1, t2);
                if (t1 < t2)
                    ++bracket;
                else {
                    --bracket;
                    if (bracket == 0) {
                        add_expr(s.substr(pos, pos2-pos+1));
                        if (this->isInvalidExpr)
                            return;
                        break;
                    }
                }
            }
            // " (...))"
            //       | <- pos2
            if (pos2 == s.length()-2)
                return;
            // " (...) ..."
            //       | <- pos2
            pos = pos2 + 2;
        }
    }
}

// --------------------------- get/add a sub-expression -------------------------
void Expr::add_expr(const string& x) {
    Expr* expr = NULL;
    switch (Expr::get_type(x)) {
        case V_EXPR:
            expr = new Expr(x);
            break;
        case V_REG:
            expr = new Reg(x);
            break;
        case V_SUBREG:
            expr = new SubReg(x);
            break;
        case V_REF:
            expr = new Ref(x);
            break;
        case V_MEM:
            expr = new Mem(x);
            break;
        case V_CONST:
            expr = new Const(x);
            break;
        case V_IF_ELSE:
            expr = new IfElse(x);
            break;
        case V_PARALLEL:
            expr = new Parallel(x);
            break;
        case V_EXTRACT:
            expr = new Extract(x);
            break;
        case V_STRICT_LOW_PART:
            expr = new StrictLowPart(x);
            break;
        case V_GENERALTYPE:
            // mode is handled separately
            if (x.substr(0,5).compare("mode:") != 0)
                expr = new GeneralType(x);
            break;
        default:
            break;
    }

    if (expr != NULL) {
        this->isInvalidExpr |= expr->isInvalidExpr;
        subExpr.push_back(expr);
    }
}

Expr* Expr::get_expr(int index) {
    if (index < subExpr.size()) {
        vector<Expr*>::iterator it = subExpr.begin();
        for (int i = 0; i < index; ++i, ++it);
        return *(it);
    }
    return NULL;
}

// ------------------- get expr type/opcode/mode from string --------------------
string Expr::get_opcode(const string& x) {
    size_t pos = x.find(' ');
    return x.substr(1, pos-1);
}

string Expr::get_mode(const string& x) {
    size_t pos = x.find_last_of(' ') + 1;
    if (x.substr(pos, 5).compare("mode:") == 0 && x.at(x.length()-2) != ')')
        return x.substr(pos+5, x.length()-6-pos);
    return "";
}

char Expr::get_type(const string& x) {
    // x = a string with no space (e.g. "UNSPEC_NTPOFF", "(symbol_ref)", "43" ..)
    if (x.find(' ') == string::npos)
        return V_GENERALTYPE;
    else {
        string tmp = Expr::get_opcode(x);
        // x = (LBRACK_RBRACK ..)
        if (tmp.compare("LBRACK_RBRACK") == 0)
            return V_PARALLEL;
        // x = (reg ..)
        if (tmp.compare("reg") == 0)
            return V_REG;
        // x = (subreg ..)
        if (tmp.compare("subreg") == 0)
            return V_SUBREG;
        // x = (label_ref ..) or (symbol_ref ..)
        if (tmp.compare("label_ref") == 0 || tmp.compare("symbol_ref") == 0)
            return V_REF;
        // x = (mem ..)
        else if (tmp.compare("mem") == 0)
            return V_MEM;
        // x = (const_int ..) or (const_double ..)
        else if (tmp.compare("const_int") == 0 || tmp.compare("const_double") == 0)
            return V_CONST;
        // x = (if_then_else ..)
        else if (tmp.compare("if_then_else") == 0)
            return V_IF_ELSE;
        else if (tmp.compare("strict_low_part") == 0)
            return V_STRICT_LOW_PART;
        else if (tmp.compare("zero_extract") == 0 || tmp.compare("sign_extract") == 0)
            return V_EXTRACT;
        // x is none of the above cases
        else
            return V_EXPR;
    }
}

// ------------------------------- find opcode ---------------------------------
Expr* Expr::find_opcode(const string& _op) {
    // if opcode matches
    if (op.compare(_op) == 0)
        return this;
    // otherwise, check all subExpr
    Expr* result = NULL;
    int n = subExpr.size();
    for (int i = 0; i < n; ++i) {
        result = get_expr(i)->find_opcode(_op);
        if (result != NULL)
            return result;
    }
    return NULL;
}

Expr* Expr::find_opcode(const string& _op, Expr* argv, int argId) {
    // if opcode and argv match
    if (op.compare(_op) == 0 && get_expr(argId)->equivalent(argv))
        return this;
    // otherwise, check all subExpr
    Expr* result = NULL;
    int n = subExpr.size();
    for (int i = 0; i < n; ++i) {
        result = get_expr(i)->find_opcode(_op, argv, argId);
        if (result != NULL)
            return result;
    }
    return NULL;
}

Expr* Expr::find_opcode_2(const string& _op1, const string& _op2, Expr* argv,
int argId1, int argId2) {
    // if opcode 1 matches
    if (op.compare(_op1) == 0 && get_expr(argId1)->find_opcode(_op2, argv, argId2) != NULL)
        return this;
    // otherwise, check all subExpr
    Expr* result = NULL;
    int n = subExpr.size();
    for (int i = 0; i < n; ++i) {
        result = get_expr(i)->find_opcode_2(_op1, _op2, argv, argId1, argId2);
        if (result != NULL)
            return result;
    }
    return NULL;
}

vector<Expr*> Expr::find_opcode_all(const string& _op) {
    vector<Expr*> result;
    int n = subExpr.size();
    result.clear();
    // if opcode matches
    if (op.compare(_op) == 0)
        result.push_back(this);
    // otherwise, check all subExpr
    for (int i = 0; i < n; ++i) {
        vector<Expr*> t = get_expr(i)->find_opcode_all(_op);
        if (t.size() != 0)
            result.insert(result.end(), t.begin(), t.end());
    }
    return result;
}

// ---------------------------- get regs to track -------------------------------
set<string> Expr::get_regs_to_track(const string& _reg) {
    set<string> regs;
    if (isInvalidExpr)
        return regs;

    // if r is assigned, add its dependent regs
    // NOT possible to have 2 assignments to the same reg
    string s = "(reg " + _reg + " mode:DI)";
    // ------- try every way of changing value of _reg -------
    // 1. (set (reg ax mode:DI) (..))
    Expr* v = find_opcode("set", new Expr(s), 0);
    // 2. (set (strict_low_part(reg ax mode:DI)) (..))
    if (v == NULL)
        v = find_opcode_2("set", "strict_low_part", new Expr(s), 0, 0);
    // 3. (set (zero_extract(reg ax mode:DI)(..)(..)) (..))
    if (v == NULL)
        v = find_opcode_2("set", "zero_extract", new Expr(s), 0, 0);
    // -----------------------------------------------------
    if (v != NULL) {
        MathExpr* v2 = v->get_expr(1)->estimate_val();
        // continue to track r if assignment of non-math-expr
        if (!v2->isMathExpr)
            regs.insert(_reg);
        // otherwise, find all regs in the mathExpr
        else {
            string r;
            int rSize;
            for (list<string>::iterator it = v2->mathExpr.begin(); it != v2->mathExpr.end(); ++it)
                if (MathExpr::extract_reg(*it, r, rSize))
                    regs.insert(r);
        }
    }
    // continue to track r if isn't assigned
    else
        regs.insert(_reg);

    return regs;
}

set<string> Expr::get_regs_to_track(const vector<string> &_regs) {
    set<string> regs;
    if (this->isInvalidExpr)
        return regs;

    // append dependent regs of each element in r
    for (vector<string>::const_iterator it = _regs.begin(); it != _regs.end(); ++it) {
        set<string> v = get_regs_to_track(*it);
        regs.insert(v.begin(), v.end());
    }

    return regs;
}

// --------------- update value of registers using given input ------------------
vector<MathExpr*> Expr::update_val_of_regs(const string& _reg,
const vector<string> &fromRegs, const vector<vector<MathExpr*>> &fromVals) {
    if (this->isInvalidExpr)
        return vector<MathExpr*>();

    // if _reg is assigned, use fromRegs and fromVals
    string s = "(reg " + _reg + " mode:DI)";
    Expr* t = new Expr(s);
    // ------- try every way of changing value of _reg -------
    // 1. (set (reg ax mode:DI) (..))
    Expr* v = find_opcode("set", t, 0);
    // 2. (set (strict_low_part(reg ax mode:DI)) (..))
    if (v == NULL)
        v = find_opcode_2("set", "strict_low_part", t, 0, 0);
    // 3. (set (zero_extract(reg ax mode:DI)(..)(..)) (..))
    if (v == NULL)
        v = find_opcode_2("set", "zero_extract", t, 0, 0);
    // clear t
    delete t;
    // -----------------------------------------------------
    vector<string>::const_iterator it1 = fromRegs.begin();
    vector<vector<MathExpr*>>::const_iterator it2 = fromVals.begin();
    vector<MathExpr*> oldVal, newVal;
    for (; it1 != fromRegs.end(); ++it1, ++it2)
        if ((*it1).compare(_reg) == 0) {
            // strictly not use same object
            oldVal = MathExpr::clone(*it2);
            break;
        }

    if (v != NULL) {
        MathExpr* v2 = v->get_expr(1)->estimate_val();
        // keep value as default if non-math-expr
        if (!v2->isMathExpr)
            return oldVal;
        // else make substitution
        else {
            // consider strict_low_part/zero_extract in destination operand
            newVal = v2->substitute(fromRegs, fromVals);
            get_expr(0)->adjust_assigned_value(oldVal, newVal);
            // oldVal is not used, clear it!
            MathExpr::clear(oldVal);
            return newVal;
        }
    }
    // keep value as default if _reg is untouched
    else
        return oldVal;
}

vector<vector<MathExpr*>> Expr::update_val_of_regs(const vector<string> &_regs,
const vector<string> &fromRegs, const vector<vector<MathExpr*>> &fromVals) {
    vector<vector<MathExpr*>> vals;
    if (this->isInvalidExpr)
        return vals;

    for (vector<string>::const_iterator it = _regs.begin(); it != _regs.end(); ++it)
        vals.push_back(update_val_of_regs(*it, fromRegs, fromVals));

    return vals;
}
// -------------------------- tools for other purposes --------------------------
void Expr::adjust_assigned_value(const vector<MathExpr*> &oldVal, vector<MathExpr*> &newVal) {
    // 1. handle concrete values for strict_low_part, zero_extract, ... separately
}

char Expr::equivalent(Expr* v) {
    switch (type) {
        case V_REG:
            return ((Reg*)this)->equivalent(v);
        default:
            return v->s.compare(this->s) == 0;
    }
}

MathExpr* Expr::estimate_val() {
    return new MathExpr(this);
}

void Expr::print() {
    cout << s;
}

// use [3, 2, 1] to print the 1st-arg of 2nd-arg of 3rd-arg of this expr
void Expr::print(vector<int> pos) {
    if (pos.empty())
        cout << s;
    else {
        Expr* t = this;
        for (vector<int>::iterator it = pos.begin(); it != pos.end(); ++it)
            t = t->get_expr(*it);
        cout << t->s;
    }
}

// ------------------------------------------------------------------------------
// ------------------------------------ Reg -------------------------------------
// ------------------------------------------------------------------------------
Reg::Reg(const string& x) : Expr(x) {
    reg = get_expr(0)->s;
}

char Reg::equivalent(Expr* v) {
    return v->type == V_REG && this->reg.compare((new Reg(v->s))->reg) == 0;
}
// ------------------------------------------------------------------------------
// ---------------------------------- SubReg ------------------------------------
// ------------------------------------------------------------------------------
SubReg::SubReg(const string& x) : Expr(x) {
    byteNum = stoi(get_expr(1)->s);
}

void SubReg::adjust_assigned_value(const vector<MathExpr*> &oldVal, vector<MathExpr*> &newVal) {
    // similar to zero_extract
    // (set (subreg:mode (..) byteNum)) = (set (zero_extract:any_mode (..) (mode-to-bit) (8*byteNum)))
    // there are two cases:
    // 1. subreg's mode > its child's mode => paradoxical: byteNum always 0, discard other bytes
    // 2. subreg's mode < its child's mode => replace other bytes with oldVal

    Expr* child = get_expr(0);
    if (MathExpr::modeLenMap.find(mode) == MathExpr::modeLenMap.end() ||
        MathExpr::modeLenMap.find(child->mode) == MathExpr::modeLenMap.end())
            return;

    int size = stoi(MathExpr::modeLenMap[mode]);
    int pos = byteNum << 3;
    char isParadoxical = 0;
    if (stoi(MathExpr::modeLenMap[child->mode]) < size)
        isParadoxical = 1;


    string s1, s2;
    int64 v1, v2;
    uint64 t = MathExpr::fill_set_bit(size);
    vector<MathExpr*>::const_iterator it1 = oldVal.begin();
    vector<MathExpr*>::iterator it2 = newVal.begin();
    
    if (!isParadoxical) {
        for (; it1 != oldVal.end(); ++it1, ++it2) {
            s1 = *((*it1)->mathExpr.begin());
            s2 = *((*it2)->mathExpr.begin());
            if (MathExpr::str_to_int64(s1, v1) && MathExpr::str_to_int64(s2, v2)) {
                v1 = (int64) ((uint64)v1 - ((t << pos) & (uint64)v1));
                v2 = (int64) ((t << pos) & (uint64)v2);
                v2 = (int64) ((uint64)v2 + (uint64)v1);
                *((*it2)->mathExpr.begin()) = to_string(v2);
            }
        }
    }
    else {
        for (; it2 != newVal.end(); ++it2) {
            s2 = *((*it2)->mathExpr.begin());
            if (MathExpr::str_to_int64(s2, v2)) {
                v2 = (int64) ((t << pos) & (uint64)v2);
                *((*it2)->mathExpr.begin()) = to_string(v2);
            }
        }
    }
}
// ------------------------------------------------------------------------------
// ----------------------------- Strict Low Part --------------------------------
// ------------------------------------------------------------------------------
StrictLowPart::StrictLowPart(const string& x) : Expr(x) {
    mode = get_expr(0)->mode;
}

void StrictLowPart::adjust_assigned_value(const vector<MathExpr*> &oldVal, vector<MathExpr*> &newVal) {
    if (MathExpr::modeLenMap.find(mode) == MathExpr::modeLenMap.end())
        return;

    // replace outside bits of newVal with that of oldVal
    string s1, s2;
    int64 v1, v2;
    int bitPreserve = stoi(MathExpr::modeLenMap[mode]);
    uint64 t = MathExpr::fill_set_bit(bitPreserve);
    vector<MathExpr*>::const_iterator it1 = oldVal.begin();
    vector<MathExpr*>::iterator it2 = newVal.begin();

    for (; it1 != oldVal.end(); ++it1, ++it2) {
        s1 = *((*it1)->mathExpr.begin());
        s2 = *((*it2)->mathExpr.begin());
        if (MathExpr::str_to_int64(s1, v1) && MathExpr::str_to_int64(s2, v2)) {
            v1 = (int64) ((uint64)v1 >> bitPreserve);
            v1 = (int64) ((uint64)v1 << bitPreserve);
            v2 = (int64) (((uint64)v2 & t) + v1);
            *((*it2)->mathExpr.begin()) = to_string(v2);
        }
    }
}
// ------------------------------------------------------------------------------
// ---------------------------------- Extract -----------------------------------
// ------------------------------------------------------------------------------
Extract::Extract(const string& x) : Expr(x) {
    isSignExtract = 0;
    if (op.compare("sign_extract") == 0)
        isSignExtract = 1;
    // simple assumption: "size" and "pos" are constant int
    size = ((Const*)get_expr(1))->val;
    pos = ((Const*)get_expr(2))->val;
}

void Extract::adjust_assigned_value(const vector<MathExpr*> &oldVal, vector<MathExpr*> &newVal) {
    // when using with "set" opcode, mode of zero_extract/sign_extract doesn't matter
    // replace outside bits of newVal with that of oldVal
    string s1, s2;
    int64 v1, v2;
    uint64 t = MathExpr::fill_set_bit(size);
    vector<MathExpr*>::const_iterator it1 = oldVal.begin();
    vector<MathExpr*>::iterator it2 = newVal.begin();
    
    for (; it1 != oldVal.end(); ++it1, ++it2) {
        s1 = *((*it1)->mathExpr.begin());
        s2 = *((*it2)->mathExpr.begin());
        if (MathExpr::str_to_int64(s1, v1) && MathExpr::str_to_int64(s2, v2)) {
            v1 = (int64) ((uint64)v1 - ((t << pos) & (uint64)v1));
            v2 = (int64) ((t << pos) & (uint64)v2);
            v2 = (int64) ((uint64)v2 + (uint64)v1);
            *((*it2)->mathExpr.begin()) = to_string(v2);
        }
    }
}
// ------------------------------------------------------------------------------
// ------------------------------------ Ref -------------------------------------
// ------------------------------------------------------------------------------
Ref::Ref(const string& x) : Expr(x) {
    string t = ((GeneralType*)get_expr(0))->val;
    // remove prefix ".L"
    if (t.substr(0,2) == ".L")
        t.erase(0,2);
    // handle both hexadecimal and decimal offset
    try {
        if (t.substr(0,2) == "0x")
            offset = stoll(t, nullptr, 16);
        else
            offset = stoll(t, nullptr, 10);
    }
    catch (invalid_argument &e) {
        this->isInvalidExpr = 1;
        cerr << "Exception: " << x << endl;
    }
}
// ------------------------------------------------------------------------------
// ------------------------------------ Mem -------------------------------------
// ------------------------------------------------------------------------------
Mem::Mem(const string& x) : Expr(x) {
    Expr* t = get_expr(0);
    if (t->type == V_REF) {
        accessType = DIRECT_TARGET;
        directTarget = ((Ref*)t)->offset;
    }
    else {
        accessType = INDIRECT_TARGET;
        indirectTarget = t->estimate_val();
    }
}

Mem::~Mem() {
    delete indirectTarget;
}
// ------------------------------------------------------------------------------
// ----------------------------------- Const ------------------------------------
// ------------------------------------------------------------------------------
Const::Const(const string& x) : Expr(x) {
    if (s.find("const_int") != string::npos) {
        string t = get_expr(0)->s;
        // handle both hexadecimal and decimal offset
        try {
            if (t.substr(0,2) == "0x")
                val = stoll(t, nullptr, 16);
            else
                val = stoll(t, nullptr, 10);
        }
        catch (invalid_argument &e) {
            this->isInvalidExpr = 1;
            cerr << "Exception: " << x << endl;
        }
        // update constType
        constType = INT_TYPE;
    }
    else {
        doubleVal = get_expr(0)->s;
        constType = DOUBLE_TYPE;
    }
}

Const::Const(int64 x) : Const("(const_int " + to_string(x) + ")") {}
// ------------------------------------------------------------------------------
// ----------------------------------- IfElse -----------------------------------
// ------------------------------------------------------------------------------
IfElse::IfElse(const string& x) : Expr(x) {
    target_if = get_expr(1);
    target_else = get_expr(2);
}

// ------------------------------------------------------------------------------
// ---------------------------------- Parallel ----------------------------------
// ------------------------------------------------------------------------------
Parallel::Parallel(const string& x) : Expr(x) {}

set<string> Parallel::get_regs_to_track(const string& _reg) {
    set<string> regs;
    for (int i = 0; i < subExpr.size(); ++i) {
        set<string> v = get_expr(i)->get_regs_to_track(_reg);
        regs.insert(v.begin(), v.end());
    }
    return regs;
}

vector<MathExpr*> Parallel::update_val_of_regs(const string& _reg,
const vector<string> &fromRegs, const vector<vector<MathExpr*>> &fromVals) {
    vector<MathExpr*> vals;
    for (int i = 0; i < subExpr.size(); ++i) {
        vector<MathExpr*> v = get_expr(i)->update_val_of_regs(_reg, fromRegs, fromVals);
        vals.insert(vals.end(), v.begin(), v.end());
    }
    return vals;
}
// ------------------------------------------------------------------------------
// ------------------------------- General Type ---------------------------------
// ------------------------------------------------------------------------------
GeneralType::GeneralType(const string& x) : Expr(x) {
    val = s;
    // clear '(' and ')' in (symbol_ref)
    if (s.front() == '(' && s.back() == ')') {
        val.erase(0, 1);
        val.erase(val.length()-1, 1);
    }
}