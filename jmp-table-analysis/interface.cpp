/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include "interface.h"
#include <sstream>
#include <fstream>
#include <algorithm>
#include <set>
#include <cstdio>
#include <unistd.h>
#include <caml/mlvalues.h>
#include <caml/callback.h>

#include <iostream>
#include <chrono>
#include <ctime>

using namespace std;

int Interface::fileNum;
int Interface::pid;

Interface::Interface() {
    // initialize argv
    char** argv = (char**)malloc(4*sizeof(char*));
    Interface::pid = getpid();
    char t0[] = "interface";
    char t1[] = "-itf";
    char t2[] = "on";
    argv[0] = (char*)malloc(sizeof(char*));   argv[0] = t0;
    argv[1] = (char*)malloc(sizeof(char*));   argv[1] = t1;
    argv[2] = (char*)malloc(sizeof(char*));   argv[2] = t2;
    argv[3] = NULL;
    // start ocaml code and train imaps
    caml_main(argv);
    Interface::fileNum = 0;
}

Interface::~Interface() {
    //caml_shutdown();
    //cout << "ocaml stopped successfully" << endl;
    clear();
}


void Interface::print_ptr(vector<vector<MathExpr*>> &v) {
    vector<vector<MathExpr*>>::iterator it = v.begin();
    for (; it != v.end(); ++it) {
        vector<MathExpr*>::iterator it2 = (*it).begin();
        for (; it2 != (*it).end(); ++it2)
            if ((*it2) != NULL)
                cout << *it2 << " ";
            else
                cout << "NULL ";
    }
    cout << endl;
}

void Interface::clear() {
    // clear all Insn objects in insnList
    // clear an Insn object means clearing itself and its indirectTargets
    // no need to clear offset_insn and indirectTargets element;
    vector<Insn*>::iterator it = insnList.begin();
    for (; it != insnList.end(); ++it)
        delete (*it);
    insnList.clear();
    offset_insn.clear();
    indirectTargets.clear();
    // clear all BasicBlock objects in offset_bb
    map<int,BasicBlock*>::iterator it2 = offset_bb.begin();
    for (; it2 != offset_bb.end(); ++it2)
        delete (it2->second);
    offset_bb.clear();
    // clear vector of object
    transferOffset.clear();
    directTargets.clear();
}

void Interface::analyze(const string &asmFile) {
    // start fresh!
    clear();
    // lifting into RTLs
    string asmFile2, rtlFile;
    asmFile2 = asmFile;
    Interface::ocaml_lift_asm(asmFile2, rtlFile);
    // loading insnList
    int64 offset;
    Expr* tmpE;
    Insn* tmpI = NULL;
    Insn* tmpI2 = NULL;
    string asmLn, rtlLn;
    fstream asmStream(asmFile2, fstream::in);
    fstream rtlStream(rtlFile, fstream::in);

    while (getline(asmStream, asmLn) && getline(rtlStream, rtlLn)) {
        // extract offset from asmStream
        stringstream ss;
        ss << asmLn;
        ss >> asmLn;
        asmLn.erase(0,2);
        MathExpr::str_to_int64(asmLn, offset);
        // process insn
        tmpI2 = tmpI;
        tmpE = new Expr(rtlLn);
        tmpI = new Insn(offset, tmpE);
        tmpI->prevInsn = tmpI2;
        if (tmpI2 != NULL)
            tmpI2->nextInsn = tmpI;
        insnList.push_back(tmpI);
        // update mapping offset_insn
        offset_insn[offset] = tmpI;
    }

    asmStream.close();
    rtlStream.close();
}

void Interface::check_transfer_insn() {
    // get list of direct/indirect targets
    // get offset of transfer insns
    vector<Insn*>::iterator it;
    vector<int64>::iterator it2;
    vector<MathExpr*>::iterator it3;
    Insn* insn;
    for (it = insnList.begin(); it != insnList.end(); ++it) {
        insn = *it;
        // empty insn: (cannot lifted) or (part of a translated consecutive sequence)
        if (insn->isInvalidInsn)
            continue;
        // otherwise, collect transfer targets
        insn->get_transfer_target(CHECK_TRANSFER_FULL);
        switch (insn->transferType) {
            case DIRECT_TARGET:
                transferOffset.push_back(insn->offset);
                for (it2 = insn->directTargets.begin(); it2 != insn->directTargets.end(); ++it2)
                    directTargets.push_back(*it2);
                break;
            case INDIRECT_TARGET:
                transferOffset.push_back(insn->offset);
                for (it3 = insn->indirectTargets.begin(); it3 != insn->indirectTargets.end(); ++it3)
                    indirectTargets.push_back(*it3);
                break;
            default:
                break;
        }
    }
    // remove duplicate in directTargets
    std::sort(directTargets.begin(), directTargets.end());
    directTargets.erase(std::unique(directTargets.begin(), directTargets.end()), directTargets.end());
}

vector<pair<pair<int64,int64>,int>> Interface::get_jump_table_target_base_entrysize(int windowSize, char trackType) {
    //auto start = std::chrono::system_clock::now();
    int64 base, jmptbl;
    int entrySize;
    vector<pair<pair<int64,int64>,int>> result;
    vector<MathExpr*>::iterator it;
    vector<MathExpr*> v = get_jump_table_target(windowSize, trackType);

    for (it = v.begin(); it != v.end(); ++it) {
        Interface::is_jump_table_target(*it, base, jmptbl, entrySize);
        result.push_back(make_pair(make_pair(base, jmptbl), entrySize));
    }
    // only return base and entrysize, so clean up v
    MathExpr::clear(v);
    //auto end = std::chrono::system_clock::now();
    //std::chrono::duration<double> elapsed_seconds = end-start;
    //std::time_t end_time = std::chrono::system_clock::to_time_t(end);

    return result;
}

vector<MathExpr*> Interface::get_jump_table_target(int windowSize, char trackType) {
    int64 base, jmptbl;
    int entrySize;
    vector<MathExpr*> result;
    vector<int64>::iterator it;
    vector<MathExpr*>::iterator it2, it3;

    if (trackType == TRACK_TYPE_ENTIRE) {
        check_transfer_insn();

        for (it = transferOffset.begin(); it != transferOffset.end(); ++it) {
            Insn* insn = offset_insn[*it];
            if (insn->transferType == INDIRECT_TARGET && insn->expr->s.compare("simple_return") != 0)
                for (it2 = insn->indirectTargets.begin(); it2 != insn->indirectTargets.end(); ++it2) {
                    vector<MathExpr*> v = Interface::track_value(*it2, insn, windowSize);
                    // keep jump table target only
                    for (it3 = v.begin(); it3 != v.end(); ++it3)
                        if (Interface::is_jump_table_target(*it3, base, jmptbl, entrySize))
                            result.push_back(*it3);
                        else
                            // clear because (*it3) will never be used
                            delete (*it3);
                }
        }
    }
    else if (trackType == TRACK_TYPE_LAST) {
        // assume that the last insn is indirect transfer other than "ret"
        Insn* insn = insnList.back();
        insn->get_transfer_target(CHECK_TRANSFER_FULL);

        for (it2 = insn->indirectTargets.begin(); it2 != insn->indirectTargets.end(); ++it2) {
            vector<MathExpr*> v = Interface::track_value(*it2, insn, windowSize);
            // keep jump table target only
            for (it3 = v.begin(); it3 != v.end(); ++it3) {
                if (Interface::is_jump_table_target(*it3, base, jmptbl, entrySize))
                    result.push_back(*it3);
                else
                    // clear because (*it3) will never be used
                    delete (*it3);
            }
        }
    }

    return result;
}

vector<MathExpr*> Interface::track_value(MathExpr* v, Insn* insn, int windowSize) {
    // ignore until a non-empty insn is found
    while (insn != NULL && insn->isInvalidInsn && insn->prevInsn != NULL) {
        insn = insn->prevInsn;
        --windowSize;
    }
    // if no non-empty insn in windowSize range
    if (insn->prevInsn == NULL)
        return vector<MathExpr*>();
    // track all regs
    vector<string> regs = v->get_all_regs();
    vector<vector<MathExpr*>> vals = Interface::track_value(regs, insn->prevInsn, windowSize-1);
    // after recursive call, handle special register: instruction pointer
    insn->supply_reg_ip(regs, vals);
    // substitute, get list of possible values in MathExpr
    vector<MathExpr*> result = v->substitute(regs, vals);
    // clear stuffs
    regs.clear();
    MathExpr::clear(vals);

    return result;
}

vector<vector<MathExpr*>> Interface::track_value(const vector<string> &_regs, Insn* insn, int windowSize) {
    // stop if insn is NULL or insn is a transfer instruction
    // return an empty vector with same elements as in _regs
    if (windowSize == 0 || _regs.empty() || insn == NULL) {
        vector<MathExpr*> t;
        vector<vector<MathExpr*>> result;
        for (int i = 0; i < _regs.size(); ++i)
            result.push_back(t);
        return result;
    }

    // otherwise, continue to track _regs
    vector<string> regs = insn->get_regs_to_track(_regs);
    vector<vector<MathExpr*>> vals = Interface::track_value(regs, insn->prevInsn, windowSize-1);
    vector<vector<MathExpr*>> result = insn->update_val_of_regs(_regs, regs, vals);
    insn->apply_side_effect(_regs, result);
    // clear stuffs
    regs.clear();
    MathExpr::clear(vals);

    return result;
}

char Interface::is_jump_table_target(MathExpr* v, int64 &base, int64 &jmptbl, int &entrySize) {
    list<string>::iterator it = v->mathExpr.begin();
    list<string>::iterator it2;
    string op;
    int opSize;
    // skip _extract/_extend insns, check if the 1st element is + or -
    if (!v->find_non_ext_op(it))
        return 0;
    MathExpr::extract_op(*it, op, opSize);
    if (op.compare("+") != 0 && op.compare("-") != 0)
        return 0;

    ++it;
    // simply ignore id, id could be: mult(x, k); x; ...
    // 1: "+ base M + base id"
    it2 = it;
    ++it2;
    // --- check: "+ base M .."
    if (MathExpr::extract_offset(*it, base) && v->find_non_ext_op(it2) &&
        MathExpr::extract_op(*it2, op, opSize) && op.compare("M") == 0) {
        ++it2;
        entrySize = opSize;
        // --- check: "M + base .." OR "M + .. base"
        if (v->find_non_ext_op(it2) && MathExpr::extract_op(*it2, op, opSize) &&
           (op.compare("+") == 0 || op.compare("-") == 0)) {
            // --- check: "base .."
            ++it2;
            if (MathExpr::extract_offset(*it2, jmptbl))
                return 1;
            // --- check: ".. base"
            it2 = v->next_element(it2);
            if (MathExpr::extract_offset(*it2, jmptbl))
                return 1;
        }
    }
    // 2: "+ M + base id base"
    it2 = v->next_element(it);
    // --- check: "+ M .. base"
    if (v->find_non_ext_op(it) && MathExpr::extract_op(*it, op, opSize) &&
        op.compare("M") == 0 && MathExpr::extract_offset(*it2, base)) {
        ++it;
        entrySize = opSize;
        // --- check: "M + base .." OR "M + .. base"
        if (v->find_non_ext_op(it) && MathExpr::extract_op(*it, op, opSize) &&
           (op.compare("+") == 0 || op.compare("-") == 0)) {
            // -- check: "base .."
            ++it;
            if (MathExpr::extract_offset(*it, jmptbl))
                return 1;
            // -- check: ".. base"
            it = v->next_element(it);
            if (MathExpr::extract_offset(*it, jmptbl))
                return 1;
        }
    }

    return 0;
}

void Interface::prepare_file(const string& fileName, int id) {
    string s = "/tmp/" + to_string(Interface::pid) + "_tmp_" + to_string(id);
    remove(s.c_str());
    symlink(fileName.c_str(), s.c_str());
}

void Interface::ocaml_train_imap(const string& imapFile1, const string& imapFile2) {
    if (imapFile2.compare("") == 0) {
        Interface::prepare_file(imapFile1, Interface::fileNum+1);
        static value * closure_f = NULL;
        if (closure_f == NULL)
            closure_f = caml_named_value("Train1 callback");
        caml_callback2(*closure_f,Val_int(Interface::pid), Val_int(Interface::fileNum+1));
        ++Interface::fileNum;
    }
    else {
        Interface::prepare_file(imapFile1, Interface::fileNum+1);
        Interface::prepare_file(imapFile2, Interface::fileNum+2);
        static value * closure_f = NULL;
        if (closure_f == NULL)
            closure_f = caml_named_value("Train2 callback");
        caml_callback3(*closure_f,Val_int(Interface::pid), Val_int(Interface::fileNum+1), Val_int(Interface::fileNum+2));
        Interface::fileNum += 2;
    }
}

void Interface::ocaml_load_auto(const string& autoFile) {
    Interface::prepare_file(autoFile, Interface::fileNum+1);
    static value * closure_f = NULL;
    if (closure_f == NULL)
        closure_f = caml_named_value("Load callback");
    caml_callback2(*closure_f,Val_int(Interface::pid), Val_int(Interface::fileNum+1));
    ++Interface::fileNum;
}

void Interface::ocaml_lift_asm(string& asmFile, string& rtlFile) {
    // refine asmFile using script "asm_format", prepare asmFile and rtlFile for lift-code
    string originAsm = asmFile;
    asmFile = "/tmp/" + to_string(Interface::pid) + "_tmp_" + to_string(Interface::fileNum+1);
    rtlFile = "/tmp/" + to_string(Interface::pid) + "_tmp_" + to_string(Interface::fileNum+2);
    remove(asmFile.c_str());
    remove(rtlFile.c_str());
    string cmd = "~/asm_format.sh " + originAsm + " " + asmFile;
    system(cmd.c_str());

    static value * closure_f = NULL;
    if (closure_f == NULL)
        closure_f = caml_named_value("Lift callback");
    caml_callback3(*closure_f,Val_int(Interface::pid),  Val_int(Interface::fileNum+1), Val_int(Interface::fileNum+2));
}
