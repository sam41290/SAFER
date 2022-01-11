/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef FORMAT_RTL_H
#define FORMAT_RTL_H

#include "custom_type.h"
using namespace std;

class format_rtl {
  private:
    STR_LIST keywordList;
    STR_LIST underlineList;
    /* RTL Tools */
    void clear_space(string& rtl);
    void filter_bracket(string& rtl);
    void filter_detail(string& rtl);
    void filter_mode(string &rtl);
  public:
    /* Functions for RTL */
    void clean_up(string& rtl);
    bool is_line_keyword(const string& rtl);
    void standard_format(string& rtl);
    /* Initialization */
    void auto_setup();
};

#endif