/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include "format_rtl.h"
using namespace std;

/* ------------------------- RTL Tools ------------------------- */
void format_rtl::clear_space(string& rtl) {
  // replace double space by single space
  size_t pos = rtl.find("  ");
  while (pos != string::npos) {
    rtl.erase(pos, 1);
    pos = rtl.find("  ");
  }
  // if last character is space then remove it
  if (rtl[rtl.length()-1] == ' ')
    rtl.erase(rtl.length()-1, 1);
}

void format_rtl::filter_bracket(string& rtl) {
  size_t pos, pos1, pos2;
  int bracketState;
  STR_LIST::iterator t;
  // remove line keyword
  pos = rtl.find('(', 1);
  rtl.erase(0, pos);
  pos = rtl.find_last_of(')', rtl.length());
  rtl.erase(pos, string::npos);
  // remove (nil)
  pos = rtl.find("(nil)");
  while (pos != string::npos) {
    rtl.erase(pos, 5);
    pos = rtl.find("(nil)");
  }
  // remove <..>
  pos = rtl.find("<");
  pos2 = rtl.find(">", pos);
  while (pos != string::npos && pos2 != string::npos) {
    rtl.erase(pos, pos2-pos+1);
    pos = rtl.find("<");
    pos2 = rtl.find(">", pos);
  }
  // remove (expr_list ...) (int_list ...), (insn_list ...)
  // expr_list is not useful because it is flow-sensitive
  for (t = underlineList.begin(); t != underlineList.end(); ++t) {
    pos = rtl.find(*t);
    while (pos != string::npos) {
      pos2 = pos + 1;
      bracketState = 1;
      while (pos2 < rtl.length()) {
        size_t t1 = min(rtl.find('(', pos2), rtl.find('[', pos2));
        size_t t2 = min(rtl.find(')', pos2), rtl.find(']', pos2));
        if (t1 < t2)
          ++bracketState;
        else {
          --bracketState;
          if (bracketState == 0) {
            pos2 = min(t1, t2);
            break;
          }
        }
        pos2 = min(t1, t2) + 1;
      }
      rtl.erase(pos, pos2-pos+1);
      pos = rtl.find(*t, pos);
    }
  }
  // remove all outside of first-level parenthesis
  pos = rtl.find('(');
  bracketState = 1;
  while (pos != string::npos) {
    size_t t1 = rtl.find('(', pos + 1);
    size_t t2 = rtl.find(')', pos + 1);
    if (t2 < t1)
      --bracketState;
    else if (t1 < t2) {
      if (bracketState == 0) {
        rtl.erase(pos+2, t1-pos-2);
        t1 = pos + 2;
      }
      ++bracketState;
    }
    pos = min(t1, t2);
  }
  pos = rtl.find_last_of(')');
  if (pos < rtl.length() - 1)
    rtl.erase(pos+1, string::npos);
  // remove [..] other than parallel [..] with respect to nested brackets
  string tmpStr;
  size_t temp;
  // ---- find first valid '['
  pos = rtl.find('[', 0);
  while (pos != string::npos && 
      ((pos >= 9 && rtl.substr(pos-9, 10).compare("parallel [") == 0)
   || (pos >= 12 && rtl.substr(pos-12, 13).compare("parallel:SC [") == 0)
   || (pos >= 12 && rtl.substr(pos-12, 13).compare("parallel:DC [") == 0)))
        pos = rtl.find('[', pos + 1);
  pos1 = pos;
  // ---- find and remove the deepest bracket: '[' at pos1 and ']' at pos2
  while (pos1 != string::npos) {
    temp = rtl.find('[', pos1);
    pos2 = rtl.find(']', pos1);
    while (temp != string::npos && temp < pos2) {
      pos1 = temp;
      temp = rtl.find('[', temp+1);
    }
    // ---- in some cases, we skip the deepest brackets on the left side
    tmpStr = rtl.substr(pos1, pos2-pos1+1);
    if (tmpStr.find("(reg") != string::npos ||
        tmpStr.find("(mem") != string::npos ||
        tmpStr.find("(const_int") != string::npos ||
        tmpStr.find("(const_double") != string::npos ||
        tmpStr.find("(symbol_ref") != string::npos ||
        tmpStr.find("(label_ref") != string::npos)
      pos = pos2+1;
    else
      rtl.erase(pos1, pos2-pos1+1);
    // ---- find first valid '['
    pos = rtl.find('[', pos);
    while (pos != string::npos && 
        ((pos >= 9 && rtl.substr(pos-9, 10).compare("parallel [") == 0)
     || (pos >= 12 && rtl.substr(pos-12, 13).compare("parallel:SC [") == 0)
     || (pos >= 12 && rtl.substr(pos-12, 13).compare("parallel:DC [") == 0)))
          pos = rtl.find('[', pos + 1);
    pos1 = pos;
  }
}

void format_rtl::filter_detail(string &rtl) {
  size_t pos, pos1, pos2;
  // remove redundancy: reg/v:SI => reg:SI
  pos = rtl.find('/');
  while (pos != string::npos) {
    rtl.erase(pos, 2);
    pos = rtl.find('/');
  }
  // remove number before register name:
  pos = rtl.find("reg:");
  while (pos != string::npos) {
    pos1 = rtl.find(' ', pos+4);
    pos2 = rtl.find(' ', pos1+1);
    rtl.erase(pos1, pos2-pos1);
    pos = rtl.find("reg:", pos+1);
    while(pos != string::npos && rtl.substr(pos-3, 6).compare("subreg") == 0)
      pos = rtl.find("reg:", pos+1);
  }
  // remove '*' in symbol_ref:DI ("*.L43")
  pos = rtl.find("(\"*");
  while (pos != string::npos) {
    rtl.erase(pos+2, 1);
    pos = rtl.find("(\"*", pos);
  }
  // remove double space
  clear_space(rtl);
  // replace st(0) to st0, ..., st(7) to st7
  for (int i = 0; i < 8; ++i) {
    string tmpStr1 = "st(" + to_string(i) + ")";
    string tmpStr2 = "st" + to_string(i);
    pos = rtl.find(tmpStr1);
    while (pos != string::npos) {
      rtl.replace(pos, 5, tmpStr2);
      pos = rtl.find(tmpStr1);
    }
  }
}

void format_rtl::filter_mode(string &rtl) {
  size_t pos, pos2;
  string mode;
  // remove mode from "label_ref"
  pos = rtl.find("label_ref:");
  while (pos != string::npos) {
    rtl.erase(pos+9, 3);
    pos = rtl.find("label_ref:", pos+1);
  }
}
/* --------------------- Functions for RTL --------------------- */
void format_rtl::clean_up(string &rtl) {
  filter_bracket(rtl);
  filter_detail(rtl);
  filter_mode(rtl);
}

bool format_rtl::is_line_keyword(const string& rtl) {
  STR_LIST::iterator t;
  // check if rtl begins with a keyword in keywordList
  for (t = keywordList.begin(); t != keywordList.end(); ++t)
    if (rtl.compare(0, (*t).length(), *t) == 0)
      return true;
  return false;
}

void format_rtl::standard_format(string &rtl) {
  size_t pos;
  // remove space before ')' and ']'
  string closeBracket[2] = {")", "]"};
  for (int i = 0; i < 2; ++i) {
    pos = rtl.find(" " + closeBracket[i]);
    while (pos != string::npos) {
      rtl.erase(pos, 1);
      pos = rtl.find(" " + closeBracket[i]);
    }
  }
  // remove space between '(' and '['
  string openBracket[2] = {"(", "["};
  for (int i = 0; i < 2; ++i)
    for (int j = 0; j < 2; ++j) {
      pos = rtl.find(openBracket[i] + " " + openBracket[j]);
      while (pos != string::npos) {
        rtl.erase(pos+1, 1);
        pos = rtl.find(openBracket[i] + " " + openBracket[j]);
      }
    }
}

/* ----------------------- Initialization ---------------------- */
void format_rtl::auto_setup() {
  // initialize keywordList
  string keyword[3] = {"(insn", "(call_insn", "(jump_insn"};
  for (int i = 0; i < 3; ++i)
    keywordList.push_back(keyword[i]);
  // initialize underlineList
  string underline[3] = {"(expr_list", "(insn_list", "(int_list"};
  for (int i = 0; i < 3; ++i)
    underlineList.push_back(underline[i]);
}