#include <iostream>
#include <fstream>
#include <unistd.h>
#include <caml/mlvalues.h>
#include <caml/callback.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include "config.h"
#include "rtl_config.h"
#include "common.h"
#include "parser.h"
#include "analysishandler.h"
#include "state.h"
#include "domain.h"
#include "sba_function.h"
#include "scc.h"
#include "block.h"
#include "insn.h"

using namespace std;
using namespace SBI;

function<void(const UnitId&, AbsVal&)> init = [](const UnitId& id, AbsVal& out)
-> void {
   /* BaseLH */
   ABSVAL(BaseLH,out) = !bounded(id.r(),id.i())? BaseLH(BaseLH::T::TOP):
                                                 BaseLH(get_sym(id));
    /* BaseStride */
   if (id.r()==REGION::REGISTER && ARCH::call_args.contains((ARCH::REG)(id.i())))
      ABSVAL(BaseStride,out) = BaseStride(BaseStride::T::DYNAMIC);
   else
      ABSVAL(BaseStride,out) = BaseStride(BaseStride::T::TOP);

   // /* Taint */
   /*
   if ((id.r() == REGION::REGISTER &&
         (ARCH::call_args.contains((ARCH::REG)(id.i())) ||
         (ARCH::REG)(id.i()) == ARCH::stack_ptr ||
         (ARCH::REG)(id.i()) == ARCH::frame_ptr))
   || (id.r() == REGION::STATIC ||
      (id.r() == REGION::STACK && id.i() >= 0)))
      ABSVAL(Taint,out) = Taint(0x0);
   else
      ABSVAL(Taint,out) = Taint(0xffffffff);
      */
};



uint8_t thread_id = 0;
int session_id;
static string asmFile = "";
static string objFile = "";
static string errFile = "";
static string errFile2 = "";
static string tmp_1 = "";
static string tmp_2 = "";
static string tmp_3 = "";
static string tmp_4 = "";

#define WORKING_DIR  "/tmp/sbr2/"

//AnalysisHandler *p = nullptr;
//SBAFunction* f = nullptr;
unordered_map<int64_t,int64_t> lifted_insnSize;
unordered_map<IMM,unordered_set<IMM>> lifted_jtables;

namespace SBI {
static void ocaml_load(const string& auto_path) {
   static const value * closure_f = nullptr;
   std::remove(tmp_1.c_str());
   std::filesystem::create_symlink(auto_path, tmp_1);
   if (closure_f == nullptr)
      closure_f = caml_named_value("Load callback");
   caml_callback2(*closure_f, Val_int((int)thread_id),
                              Val_int(session_id));
}


//static void ocaml_lift() {
//   static const value* closure_f = nullptr;
//   if (closure_f == nullptr)
//      closure_f = caml_named_value("Lift callback");
//   caml_callback2(*closure_f, Val_int((int)thread_id),
//                              Val_int(session_id));
//}

static void refine_itc(string& itc) {
   size_t p;

   /* (0) xor  eax,DWORD PTR [r13+r15*1+0x0] */
   /* --> xor  eax,DWORD PTR [r13+r15]       */
   static array<string,4> rm_pattern = {"*1]", "*1-", "*1+", "+0x0]"};
   for (auto const& x: rm_pattern)
      while (true) {
         p = itc.find(x);
         if (p != string::npos)
            itc.erase(p, x.length()-1);
         else
            break;
      }

   /* (1) (a) loop  c   */
   /*     --> loop  0xc */
   static array<string,3> op_add_0x = {"loop", "loope", "loopne"};
   for (auto const& x: op_add_0x)
      if (itc.find(x) != string::npos) {
         p = itc.find_last_of(" ");
         itc.insert(p+1, string("0x"));
      }
   /*     (b) rol rdx,1   */
   /*     --> rol rdx,0x1 */
   if (itc.substr(itc.length()-2,2).compare(",1") == 0)
      itc.insert(itc.length()-1, string("0x"));

   /* (2) cs nop WORD PTR [rax+rax] --> nop WORD PTR cs:[rax+rax] */
   if (itc.compare("cs nop WORD PTR [rax+rax]") == 0)
      itc = string("nop WORD PTR cs:[rax+rax]");
}

void lifter_config(const string& auto_path, uint8_t t_id) {
   /* filename */
   session_id = getpid();
   thread_id = t_id;
   auto session_dir = WORKING_DIR + std::to_string(thread_id)
                    + "/lift/" + std::to_string(session_id) + "/";
   std::filesystem::create_directories(session_dir);
   tmp_1 = session_dir + string("tmp_1");
   tmp_2 = session_dir + string("tmp_2");
   tmp_3 = session_dir + string("tmp_3");
   tmp_4 = session_dir + string("tmp_4");

   
   asmFile = session_dir + string("proc.s");
   objFile = session_dir + string("proc.o");
   errFile = session_dir + string("err.log");
   errFile2 = session_dir + string("err.log.tmp");
   fstream f_out(tmp_3, fstream::out);
   f_out.close();

   /* lifter */
   #if ENABLE_LIFT_ENGINE
      //TIME_START(start_t);
      char** argv = (char**)malloc(5*sizeof(char*));
      char t0[] = "interface";
      char t1[] = "-c";
      char t2[] = "on";
      char t3[] = "-p";
      argv[0] = t0;
      argv[1] = t1;
      argv[2] = t2;
      argv[3] = t3;
      argv[4] = nullptr;
      caml_startup(argv);
      ocaml_load(auto_path);
      //TIME_STOP(Framework::t_lift, start_t);
   #endif
}
static void format_asm(const string& attFile, const string& itcFile, unordered_map<int64_t,int64_t>& insnSize) {
   std::filesystem::remove(asmFile);
   std::filesystem::remove(objFile);
   std::filesystem::remove(errFile);
   std::filesystem::remove(errFile2);

   string s;
   vector<string> label;
   static unordered_set<string> branch = {
         "jo","jno", "js", "jns", "je", "jne", "jz", "jnz", "jb", "jnb",
         "jae", "jnae", "jc", "jnc", "jbe", "jnbe", "ja", "jna", "jl", "jnl",
         "jge", "jnge", "jg", "jng", "jle", "jnle", "jp", "jnp", "jpe", "jpo",
         "jcxz", "jecxz", "jrcxz", "jmp", "jmpq", "call", "callq"
   };
   static array<string,9> rm_prefix = {"bnd", "lock", "notrack", "data16",
                                       "rex.W", "rex.X", "rep", "repz", "repnz"};
   static array<string,6> to_nop = {"data16 addb", "addr32",
                                    "loopq", "loop", "loope", "loopne"};
   static array<string,3> to_hlt = {"int1", "int3", "icebp"};

   /* handle direct transfer instructions separately */
   {
      fstream fatt(attFile, fstream::in);
      fstream fasm(asmFile, fstream::out);
      while (getline(fatt, s)) {
         /* replace with nop */
         for (auto const& x: to_nop) {
            auto it = s.find(x);
            if (it != string::npos)
               s.replace(s.find(":")+2, string::npos, "nop");
         }
         /* replace with hlt */
         for (auto const& x: to_hlt) {
            auto it = s.find(x);
            if (it != string::npos)
               s.replace(s.find(":")+2, string::npos, "hlt");
         }
         /* remove prefixes */
         for (auto const& x: rm_prefix) {
            while (true) {
               auto it = s.find(x);
               if (it != string::npos)
                  s.erase(it, x.length()+1);
               else
                  break;
            }
         }

         auto p1 = s.find(":");                                                                                     
         auto p2 = p1 + 2;                                                                                          
         auto p3 = s.find_first_of("*%.($0123456789", p2);                                                          
         if (p3 != string::npos && s[p3-1] != ' ')
            p3 = s.find_last_of(" ", p3);
         else if (p3 == string::npos)
            p3 = s.find(" ", p2) - 1;
         auto offset = s.substr(1, p1-1);                                                                           
         auto opcode = s.substr(p2, p3-p2-1);                                                                       
         if (opcode[opcode.length() - 1] == ' ') {                                                                  
            int i;                                                                                                  
            for (i = opcode.length() - 1; i > 0; --i)                                                               
               if (opcode[i] != ' ') break;                                                                         
            opcode.erase(i+1, string::npos);                                                                        
         }   

         /* .1234: callq .3485 --> .L1234 call 3485 */
         if (branch.contains(opcode) && s[p3] == '.') {
            auto p4 = s.find(" + 1");                                                                               
            if (p4 != string::npos)                                                                                 
               s.erase(p4, string::npos);
            fasm << s << "\n";
            s.erase(p3, 1);
            if (opcode.compare("callq") == 0)
               s.replace(p2, 5, string("call"));
            else if (opcode.compare("jmpq") == 0)
               s.replace(p2, 4, string("jmp"));
            s.erase(p1, 1);
            label.push_back(string(".L").append(s.substr(1,string::npos)));
         }
         /* malformed direct targets: jmpq ffffffffab1234cd */
         else if (branch.contains(opcode) && s.find_first_of("*%.($,", p3) == string::npos) {
            fasm << "." << offset << ": nop\n";
            label.push_back(string(".L").append(offset));
         }
         /* .1234: addb %al, (%rax) --> .L1234 add BYTE PTR [rax],al */
         else if (opcode.compare("addb") == 0) {
            auto p4 = s.find("%al,");
            if (p4 != string::npos) {
               auto p5 = s.find("(%rax)",p4);
               if (p5 != string::npos) {
                  fasm << "." << offset << ": nop\n";
                  label.push_back(string(".L").append(offset)
                                 .append(" add BYTE PTR [rax],al"));
               }
               else {
                  fasm << s << "\n";
                  label.push_back(string(".L").append(offset));
               }
            }
            else {
               fasm << s << "\n";
               label.push_back(string(".L").append(offset));
            }
         }
         /* .10: leaq .40(%rip), %r8 --> .L10 lea r8, QWORD PTR[rip+25] */
         /* .10: jmpq *.40(%rip)     --> .L10 jmp QWORD PTR [rip+25]    */
         /* .10: callq *.40(%rip)    --> .L10 call QWORD PTR [rip+25]   */
         else if (s.find("(%rip") != string::npos) {
            auto ioffset = Util::to_int(offset);
            auto pc = ioffset + (int64_t)(insnSize.at(ioffset));
            auto p5 = s.find("(%rip", p3);
            auto p4 = s.rfind('.',p5);
            if (p4 != 0) {                                                                                          
               auto target = s.substr(p4+1, p5-p4-1);                                                               
               if (target.length() < 15) {                                                                          
                  auto itarget = Util::to_int(target);                                                              
                  auto repl = std::to_string(itarget - pc);                                                         
                  s.replace(p4, p5-p4, repl);                                                                       
                  fasm << s << "\n";                                                                                
               }                                                                                                    
               else                                                                                                 
                  fasm << "." << offset << ": nop\n";                                                               
            }                                                                                                       
            else                                                                                                    
               fasm << s << "\n";                                                                                   
            label.push_back(string(".L").append(offset));  
         }
         /* .1234: movq %eax, %ebx --> .L1234 */
         else {
            fasm << s << "\n";
            label.push_back(string(".L").append(offset));
         }
      }
      fatt.close();
      fasm.close();
   }

   if (label.empty())
      return;

   /* convert AT&T syntax to Intel syntax */
   {
      /* assemble to object file */
      auto cmd = string("as ").append(asmFile).append(" -o ").append(objFile)
                .append(" 2> ").append(errFile2)
                .append(" ; grep \": Error:\" ").append(errFile2)
                .append(" > ").append(errFile);
      (void)!system(cmd.c_str());

      /* check if failed to assemble */
      vector<int64_t> line_skip;
      fstream ferr(errFile, fstream::in);
      while (getline(ferr, s)) {
         auto p1 = s.find("proc.s")+7;
         line_skip.push_back(Util::to_int(s.substr(p1, s.find(":",p1)-p1)));
      }

      /* replace errornous lines with nop, assemble again */
      if (!line_skip.empty()) {
         auto tmpFile = asmFile + ".tmp";
         std::filesystem::copy(asmFile, tmpFile,
                          std::filesystem::copy_options::overwrite_existing);

         auto it = line_skip.begin();
         fstream ftmp(tmpFile, fstream::in);
         fstream fasm(asmFile, fstream::out);
         for (int i = 1; i <= (int)(label.size()); ++i) {
            getline(ftmp, s);
            if (it != line_skip.end() && i == *it) {
               ++it;
               auto p1 = s.find(" ");
               s.replace(p1+1, string::npos, "nop");
            }
            fasm << s << "\n";
         }
         ftmp.close();
         fasm.close();

         cmd = string("as ").append(asmFile).append(" -o ").append(objFile);
         (void)!system(cmd.c_str());
      }

      /* disassemble to intel syntax */
      cmd = string("objdump -d ").append(objFile).append(" -M intel")
           .append(" | cut -d\'\t\' -f3-")
           .append(" | grep \"^\\s*[a-z]\"")
           .append(" | cut -d\'#\' -f1 > ")
           .append(asmFile);
      if (!WIFEXITED(system(cmd.c_str()))) {
         LOG1("error: failed to translate AT&T syntax to Intel syntax");
      }
   }

   /* generate itcFile */
   {
      fstream fasm(asmFile, fstream::in);
      fstream fitc(itcFile, fstream::out | fstream::trunc);
      for (auto const& l: label) {
         getline(fasm, s);
         /* special insn: label already store complete intel syntax */
         if (l.find(' ') != string::npos)
            fitc << l << "\n";
         /* normal insn: label contains only label */
         else {
            if (!s.empty()) refine_itc(s);
            fitc << l << " " << s << "\n";
         }
      }
      fasm.close();
      fitc.close();
   }
}

void ocaml_lift_2(const string& attFile, unordered_map<int64_t,int64_t>& insnSize) {
   string auto_path = TOOL_PATH"/auto/output.auto";
   lifter_config(auto_path, 1);
   static const value* closure_f = nullptr;
   format_asm(attFile, tmp_2, insnSize);
   if (closure_f == nullptr)
      closure_f = caml_named_value("Lift callback");
   caml_callback2(*closure_f, Val_int((int)thread_id),
                              Val_int(session_id));
}

vector<tuple<IMM,RTL*,vector<uint8_t>>> load_2(const string& attFile, unordered_map<int64_t, int64_t>& insnSize) {
   string att, rtl;
   vector<tuple<IMM,RTL*,vector<uint8_t>>> offset_rtl_raw;

   ocaml_lift_2(attFile, insnSize);

   fstream fatt(attFile, fstream::in);
   fstream frtl(tmp_3, fstream::in);
   while (getline(fatt, att)) {
      IMM offset = Util::to_int(att.substr(1, att.find(':')-1));
      getline(frtl,rtl);
      RTL* object = Parser::process(rtl);
      offset_rtl_raw.push_back({offset,object,vector<uint8_t>(insnSize.at(offset),0)});
      if (object == nullptr) {
         LOG1("error: failed to lift at " << offset << ":" <<
               att.substr(att.find(':')+1, string::npos));
      }
   }

   fatt.close();
   frtl.close();
   return offset_rtl_raw;
}

AnalysisHandler* create_handler_2(
const vector<tuple<IMM,RTL*,vector<uint8_t>>>& offset_rtl_raw,
const vector<IMM>& fptr_list, const unordered_map<IMM,unordered_set<IMM>>& icfs) {
   if (offset_rtl_raw.empty())
      return nullptr;
   else {
      auto p = new AnalysisHandler(offset_rtl_raw, fptr_list, icfs);
      if (!p->faulty)
         return p;
      else {
         delete p;
         return nullptr;
      }
   }
}

AnalysisHandler* create_handler(const string& attFile,
unordered_map<int64_t,int64_t>& insnSize,
const vector<IMM>& fptr_list,
const unordered_map<IMM,unordered_set<IMM>>& icfs) {
   auto offset_rtl_raw = load_2(attFile, insnSize);
   return create_handler_2(offset_rtl_raw, fptr_list, icfs);
}

AnalysisHandler * load(vector<IMM> entry, const string& attFile, const string& sizeFile, const string& jtableFile) {
   //if (p != nullptr)
   //   delete p;
   string s;
   /* insn size */
   lifted_insnSize.clear();
   fstream f1(sizeFile, fstream::in);
   while (getline(f1, s)) {
      auto p = s.find(' ');
      auto offset = (int64_t)(Util::to_int(s.substr(0,p)));
      auto sz = (int64_t)(Util::to_int(s.substr(p+1,string::npos)));
      lifted_insnSize[offset] = sz;
   }
   f1.close();
   /* jump table */
   lifted_jtables.clear();
   fstream f2(jtableFile, fstream::in);
   while (getline(f2, s)) {
      auto p = s.find(':');
      auto offset = (int64_t)(Util::to_int(s.substr(0,p)));
      auto p2 = p+1;
      unordered_set<IMM> vec;
      while (true) {
         p = p2+1;
         p2 = s.find(' ', p);
         vec.insert((IMM)(Util::to_int(s.substr(p,p2-p))));
         if (p2 == s.length() - 1)
            break;
      }
      lifted_jtables[offset] = vec;
   }
   f2.close();
   auto p = create_handler(attFile, lifted_insnSize, entry, lifted_jtables);
   return p;
}

SBAFunction * analyze_function(AnalysisHandler *p, int64_t fptr) {
   auto f = p->func(fptr);
   //p->build_func(fptr, p->icfs());
   if(f == NULL) {
      std::cout<<"[SBA] Could not find or create function: "<<std::hex<<fptr<<std::endl;
      return NULL;
   }
   State::StateConfig config{true, true, true, 1, &init};
   f->analyse(config);
   return f;
}
}
