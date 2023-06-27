/*--------------------------------------------------------------------
 *
 *
 *LOGGER Ref: https://stackoverflow.com/questions/19415845/a-better-log-macro-using-template-metaprogramming
 *
 * --------------------------------------------------------------------*/


#ifndef UTILS_H
#define UTILS_H
#include <cmath>
#include<stdio.h>
#include<string>
#include <vector>
#include "elf_class.h"
//#include "globals.h"
#include <stdio.h>
#include <ctype.h>


/* This file contains template and macro definitions.
 *
 * This file also contains a class definition - utils.
 * utils class defines several static member functions that are to be used
 * through out the program.
 */

namespace SBI {
enum code_type {
  CODE,
  DATA,
  GAP,
  UNKNOWN
};
}

enum class SymBind {
  BIND,
  NOBIND,
  FORCEBIND
};

struct None {};

template <typename First, typename Second> struct Pair {
  First first;
  Second second;
};

template <typename List> struct LogData {
  List list;
};

template <typename Begin, typename Value>
  LogData <Pair <Begin, const Value &>>
operator<<(LogData <Begin> begin, const Value & value) {
  return { 
    { begin.list, value }
  };
}

template <typename Begin, size_t n> LogData <Pair <Begin, const char *>>
operator<<(LogData <Begin> begin, const char(&value)[n]) {
  return {
    { begin.list, value }
  };
}

inline void
printList(std::ostream & os, None) {}


template <typename Begin, typename Last> void
printList(std::ostream & os, const Pair <Begin, Last> &data) {
  printList(os, data.first);
  os <<data.second;
}

template <typename List> void
log(const char *file, int line, const LogData <List> &data) {
  std::cout <<file <<"(" <<dec<<line <<"): ";
  printList(std::cout, data.list);
  std::cout <<"\n";
}

template <typename List> void
eh_log(const LogData <List> &data) {
  //cout <<file <<"(" <<line <<"): ";
  printList(std::cout, data.list);
}


//#define DEBUG 0


#ifdef DEBUG
#define LOG(x)(log(__FILE__,__LINE__,LogData<None>() <<x))
#define EH_LOG(x)(eh_log(LogData<None>() <<x))
#else
#define LOG(x)
#define EH_LOG(x)
#endif

#define DEF_LOG(x)(log(__FILE__,__LINE__,LogData<None>() <<x))

template <typename T1, typename T2>
  bool if_exists(T1 arg1, map <T1, T2> &arg2) {
  if(arg2.find(arg1) != arg2.end())
    return true;
  else
    return false;
}

template <typename T1, typename T2>
  typename map <T1, T2>::iterator is_within(T1 arg1, map <T1, T2> &arg2) {
  if(arg2.size() == 0)
    return arg2.end();
  typename map <T1, T2>::iterator it;
  it = arg2.lower_bound(arg1);
  if(it == arg2.end() || it->first != arg1)
    it = prev(it);
  return it;
}

template <typename T1, typename T2>
  typename map <T1, T2>::iterator next_iterator(T1 arg1, map <T1,
						   T2> &arg2) {
  typename map <T1, T2>::iterator it;
  it = arg2.lower_bound(arg1);
  if(it != arg2.end() && it->first == arg1)
    it++;
  return it;
}

template <typename T> void
read_from_map(vector <T> &arg1, map <uint64_t, T> &arg2, uint64_t start,
	       uint64_t end, int limit) {
  auto it = arg2.find(start);
  int ctr = 0;
  while(it != arg2.end() && it->first <end && ctr < limit) {
    // LOG("entry found : "<<hex<<it->first);
    arg1.push_back(it->second);
    it++;
    ctr++;
  }
}

template <typename T> bool
addToMap(T x,map <uint64_t, T> &mp,uint64_t addrs) {
  if(if_exists(addrs,mp))
    return false;
  else {
    mp[addrs] = x;
  }
  return true;
}

using namespace std;
class utils {

public:

  static bool checkHex(string & s)
  {
  
      int n = s.length();
  
      for(int i = 0; i < n; i++)
      {
          char ch = s[i];
  
          if ((ch < '0' || ch > '9') &&
              (ch < 'A' || ch > 'F') &&
              (ch < 'a' || ch < 'f'))
          {
              return false;
          }
      }
  
      return true;
  }

  static void WRITE_TO_FILE(string bname, void *ptr, uint64_t offset,
			     uint64_t sz) {
    FILE *f_out = fopen(bname.c_str(), "rb+");
    if(f_out == NULL) {
	  LOG("file couldn't be opened: " <<bname);
	  exit(0);
    }
    fseek(f_out, offset, SEEK_SET);
    fwrite((void *) ptr, sz, 1, f_out);
    fclose(f_out);
  }

  static void READ_FROM_FILE(string fname, void *ptr, uint64_t offset,
			      uint64_t sz) {
    FILE *f_in = fopen(fname.c_str(), "r");
    if(f_in == NULL) {
	  LOG("file couldn't be opened: " <<fname);
	  exit(0);
    }
    fseek(f_in, offset, SEEK_SET);
    if(fread((void *) ptr, sz, 1, f_in) == 0)
      LOG("Read failed: file: "<<fname<<" offset: "<<hex<<offset);;
    fclose(f_in);
  }

  static void
  append_files(string inp_file, string out_file) {
    ofstream ofile;
    ofile.open(out_file, ofstream::out | ofstream::app);
  
    ifstream ifile;
    ifile.open(inp_file);
    string str;
    while(getline(ifile, str))
      ofile <<str <<endl;
    ifile.close();
    ofile.close();
  
  }

  static map<string, ExeManager *> exeMap;

  static uint64_t GET_ADDRESS(string bname, uint64_t offset) {

    /* Given a file offset, the function returns the corresponding memory
     * offset.
     */

    if(offset == 0)
      return 0;

    if(if_exists(bname, exeMap))
      return exeMap[bname]->memAddrs(offset);
    else {
      ExeManager * exe = new binary_class(bname);
      exeMap[bname] = exe;
      return exe->memAddrs(offset);
    }

    return 0;

  }

  static uint64_t GET_OFFSET(string bname, uint64_t addrs) {

    /* Given a file offset, the function returns the corresponding memory
     * offset.
     */

    if(addrs == 0)
      return 0;

    if(if_exists(bname, exeMap))
      return exeMap[bname]->fileOfft(addrs);
    else {
      ExeManager * exe = new binary_class(bname);
      exeMap[bname] = exe;
      return exe->fileOfft(addrs);
    }

    return 0;

  }

  static string decToHexa(int n) {
    // char array to store hexadecimal number
    char hexaDeciNum[100];

    string hex = "";
    // counter for hexadecimal number array
    int i = 0;
    if(n == 0) {
	  hex = "00";
	  return hex;
    }
    while(n != 0) {
	  // temporary variable to store remainder
	  int temp = 0;

	  // storing remainder in temp variable.
	  temp = n % 16;

	  // check if temp <10
	  if(temp <10) {
	    hexaDeciNum[i] = temp + 48;
	    i++;
	  }
	  else {
	    hexaDeciNum[i] = temp + 55;
	    i++;
	  }

	  n = n / 16;
    }

    // printing hexadecimal number array in reverse order
    if((i % 2) != 0)
      hex.push_back('0');
    for(int j = i - 1; j>= 0; j--) {
	  hex.push_back(hexaDeciNum[j]);
    }
    return hex;
  }

  static vector <uint8_t> decToByteArray(uint64_t n, int padding) {
    LOG("converted decimal to byte array: " <<n);

    vector <uint8_t> byte_array;
    int count = 0;
    while(count <padding) {
	  uint8_t byte = n & 0xff;
	  byte_array.push_back(byte);
	  n = n>> 8;
	  count++;
    }
    //cout<<"converted decimal to byte array: "<<n<<endl;
    return byte_array;
  }

  static std::vector<std::string> split_string(std::string& s, const char *delimiter)
  {
     std::vector<std::string> tokens;

     std::string word;

	 std::istringstream iss(s);
	 while (std::getline(iss, word, delimiter[0])) {
       tokens.push_back(word);
	 }
     //char *token = strtok(const_cast<char*>(s.c_str()), delimiter);
     //while (token != nullptr)
     //{
     //    tokens.push_back(std::string(token));
     //    token = strtok(nullptr, delimiter);
     //}

     return tokens;
  }

  static vector <string> split_string(const char *data) {
    string str(data);
    //return split_string(str," ");
    vector <string> results;
    string word = "";

    for(int i = 0; data[i] != '\0'; i++) {
	  if(data[i] != ' ' && data[i] != '\t' && data[i] != '\n')
	    word += data[i];
	  else if(word.length()> 0) {
	    results.push_back(word);
	    word = "";
	  }
    }
    if(word.length()> 0) {
	  results.push_back(word);
    }
    return results;
  }


  static bool is_string(uint64_t sec_start, uint64_t sec_end, uint64_t addrs, string file) {

    uint64_t start = addrs - 6;
    if(start < sec_start)
      start = sec_start;

    uint64_t file_offt = utils::GET_OFFSET(file,start);

    int size = sec_end - start;
    LOG("checking if value at "<<hex<<addrs<<" is string");
    LOG("Section: "<<hex<<sec_start<<" buffer start: "<<hex<<start<<" file offt: "<<hex<<file_offt);
    char *c = (char *)malloc(size);
    utils::READ_FROM_FILE(file,c,file_offt,size);

    //Checking if addrs is part of a preceding string

    int sz = addrs - start + 4;

    int strlen = 0;

    for(int i = 0; i < sz; i++) {
      if(c[i] == '\0') {
        if((start + i) >= addrs) {
          if(strlen > 4) {
            LOG("Part of a preceding string of length > 4");
            free(c);
            return true;
          }
          else
            break;
        }
        else
          strlen = 0;
      }
      else if(isprint((int)(c[i])) == false)
        strlen = 0;
      else
        strlen++;
    }

    int ctr = 0;
    for(int i = (addrs - start); i < size; i++,ctr++) {
      if(c[i] == '\0' && ctr > 4) {
        LOG("Its a string!!!");
        free(c);
        return true;
      }
      else if(c[i] == '\0') {
        LOG("Encountered null character before 4 bytes");
        free(c);
        return false;
      }
      else if(isprint((int)(c[i])) == false) {
        LOG("Encountered non-printable character: "<<c[i]);
        free(c);
        return false;
      }
    }
    LOG("Didnt find string termination");
    free(c);
    return true;
  }

  static bool file_exists(string fname) {
    ifstream ifile;
    ifile.open(fname);
    if(ifile) {
      ifile.close();
      return true;
    } else {
      return false;
    }
    ifile.close();
    return false;
  }

  static vector <uint8_t> hook(uint64_t old, uint64_t new_addr) {
    
    int32_t offset = 0;

    vector <uint8_t> opcode;
    bool short_jmp = false;

    offset = new_addr - (old + 2);
    if(abs(offset) <= 255) {
      opcode.push_back(0xeb);
      short_jmp = true;
    }
    else {
      opcode.push_back(0xe9);
      offset = new_addr - (old + 5);
    }

    cout<<"creating jump instruction: "<<hex<<old<<"->"<<hex<<new_addr<<endl;

    cout<<"offset: "<<offset<<endl;

    uint8_t next_byte = offset & 0x00000000000000ff;
    opcode.push_back(next_byte);

    if(short_jmp)
      return opcode;
    offset=offset >> 8;
    next_byte = offset & 0x00000000000000ff;
    opcode.push_back(next_byte);
    offset=offset >> 8;
    next_byte = offset & 0x00000000000000ff;
    opcode.push_back(next_byte);
    offset=offset >> 8;
    next_byte = offset & 0x00000000000000ff;
    opcode.push_back(next_byte);
    return opcode;
  }
  static set <string> cf_ins_set;
  static set <string> get_cf_ins_set() {
    return cf_ins_set;
  }

  static set <string> uncond_cf_ins_set;
  static set <string> get_uncond_cf_ins_set()
  {
    return uncond_cf_ins_set;
  }
  static unordered_map <uint8_t,string> prefixes;
  static unordered_set <string> prefix_ops;
  static bool is_equivalent(string ins1, string ins2) {
    set <string> jmp_ins = utils::get_cf_ins_set();
    set <string> uncond_jmp_ins = utils::get_uncond_cf_ins_set();
    if((ins1.find("sal") == 0 && ins2.find("shl") == 0) ||
       (ins1.find("shl") == 0 && ins2.find("sal") == 0) ||
       (ins1.find("sar") == 0 && ins2.find("shr") == 0) ||
       (ins1.find("shr") == 0 && ins2.find("sar") == 0) ||
       (ins1.find(ins2) != string::npos || ins2.find(ins1) != string::npos) ||
       (jmp_ins.find(ins1) != jmp_ins.end() && jmp_ins.find(ins2) != jmp_ins.end()
        && uncond_jmp_ins.find(ins1) == uncond_jmp_ins.end() &&
        uncond_jmp_ins.find(ins2) == uncond_jmp_ins.end()))
      return true;

    return false;

  }

  static unordered_set <string> ctrl_regs;
  static unordered_set <string> debug_reg;
  static unordered_set <string> priviledge_ins;
  static bool is_debug_reg(string op) {
    if(op.find("%cr") != string::npos)
      return true;
    return false;
  }
  static bool is_ctrl_reg(string op) {
    if(op.find("%dr") != string::npos)
      return true;
    return false;
  }
  static bool is_priviledged_ins(string ins) {
    vector <string> words = utils::split_string(ins," ");
    bool mov_found = false;
    for(auto & s : words)
      if(priviledge_ins.find(s) != priviledge_ins.end())
        return true;
      else if(s.find("mov") != string::npos)
        mov_found = true;
      else if(mov_found && (is_debug_reg(s) ||
              is_ctrl_reg(s)))
        return true;
/*
    for(auto & p : priviledge_ins)
      if(mne == p)
        return true;
    if(mne.find("mov") != string::npos &&
      (op.find("%dr") != string::npos || op.find("%cr") != string::npos)) {
      return true;
    }
    */
    return false;
  }

  static bool is_prefix(uint8_t op) {
    if(prefixes.find(op) != prefixes.end())
      return true;
    return false;
  }
  static bool is_prefix(string op) {
    if(prefix_ops.find(op) != prefix_ops.end())
      return true;
    return false;
  }

  static unordered_set <string> invalid_prefixes;

  static unordered_map <uint64_t, string> sym_bindings;

  static void bind(uint64_t addr, string label, SymBind b) {
    if(b == SymBind::FORCEBIND)
      sym_bindings[addr] = label;
    else if(b == SymBind::BIND) 
      if(sym_bindings.find(addr) == sym_bindings.end())
        sym_bindings[addr] = label;
  }

  static string symbolizeRltvAccess(string op,string label, 
                                    uint64_t addr, SymBind b) {
    //DEF_LOG("Symbolizing rltv access: "<<op<<" label: "<<label);
    if(b == SymBind::FORCEBIND)
      sym_bindings[addr] = label;
    else if(b == SymBind::BIND) { 
      if(sym_bindings.find(addr) != sym_bindings.end())
        label = sym_bindings[addr];
      else
        sym_bindings[addr] = label;
    }

    int pos = op.find("(%rip)");
    int offset_pos = op.rfind(".", pos);
    op = op.replace(offset_pos, pos
             - offset_pos, "("
             + label + ")");
    //DEF_LOG("Symbolizing rltv access: "<<op<<" label: "<<label);
    return op;
  }

  static void printAsm(string asmbly, uint64_t addr, string label, 
                       SymBind b, string file_name) {
    if(b == SymBind::FORCEBIND)
      sym_bindings[addr] = label;
    else if(b == SymBind::BIND) { 
      if(sym_bindings.find(addr) != sym_bindings.end())
        label = sym_bindings[addr];
      else
        sym_bindings[addr] = label;
    }

    ofstream ofile;
    ofile.open(file_name, ofstream::out | ofstream::app);
    if(label.length() > 0)
      ofile<<label<<":\n";
    ofile<<asmbly<<endl;
    ofile.close();
  }

  static string getLabel(uint64_t addrs) {
    //DEF_LOG("getting label: "<<hex<<addrs);
    if(sym_bindings.find(addrs) != sym_bindings.end()) {
      string label = sym_bindings[addrs];
      DEF_LOG("bound label: "<<label);
      return label;
    }
    string label = "." + to_string(addrs);
    //DEF_LOG("Returning default label: "<<label);
    return label;
  }

  static void bindLabel(uint64_t addrs, string label) {
    //DEF_LOG("Binding label: "<<hex<<addrs<<label);
    sym_bindings[addrs] = label;
  }

  static void printLbl(string label, string file_name) {
    if(label.length() > 0) {
      ofstream ofile;
      ofile.open(file_name, ofstream::out | ofstream::app);
      ofile<<label<<":\n";
      ofile.close();
    }
  }

  static void printSkp(uint64_t cnt, string file_name) {
    ofstream ofile;
    ofile.open(file_name, ofstream::out | ofstream::app);
    ofile<<".skip "<<cnt<<endl;
    ofile.close();
  }
  static void printAlgn(uint64_t cnt, string file_name) {
    ofstream ofile;
    ofile.open(file_name, ofstream::out | ofstream::app);
    ofile<<".align "<<cnt<<endl;
    ofile.close();
  }
  static set <uint8_t> all_jmp_opcodes;
  static set <uint8_t> unconditional_jmp_opcodes;
  static set <uint8_t> conditional_jmp_opcodes;
  static set <uint8_t> conditional_long_jmp_opcodes;

  static bool isConditionalLongJmp(uint8_t *byte, uint64_t ins_size) {
    if(ins_size >= 6) {
      if(*(byte) == 0x0f && conditional_long_jmp_opcodes.find(*(byte + 1)) != conditional_long_jmp_opcodes.end())
        return true;
    }
    return false;
  }

  static bool isConditionalShortJmp(uint8_t *byte, uint64_t ins_size) {
    if(ins_size >= 2 && conditional_jmp_opcodes.find(*(byte)) != conditional_jmp_opcodes.end())
      return true;
    return false;
  }

  static bool isUnconditionalShortJmp(uint8_t *byte, uint64_t ins_size) {
    if(ins_size >= 2 && *(byte) == 0xeb)
      return true;
    return false;
  }
  static bool isUnconditionalJmp(uint8_t *byte, uint64_t ins_size) {
    if(ins_size >= 2 && *(byte) == 0xeb)
      return true;
    else if(ins_size >= 5 && *(byte) == 0xe9)
      return true;
    return false;
  }

};


#endif
