#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <unordered_map>
using namespace std;

#define IMM uint64_t
#define hex_to_int(s) stoull(s, nullptr, 16)
#define dec_to_int(s) stoull(s, nullptr, 10)

/* note that if there are many patterns for same indirection, it report only */
/* one of them, and this could by chance be a wrong pattern                  */
struct TargetExpr {
   IMM base;
   IMM stride;
   IMM entry_size;
   IMM table_size;
   unordered_set<IMM> targets;
};

bool hex_mode = false;
string dir = "";
string prev_dir = "";
unordered_map<IMM,TargetExpr> gt;
unordered_map<IMM,TargetExpr> sba;
unordered_map<IMM,TargetExpr> angr;
unordered_map<IMM,TargetExpr> dyninst;
unordered_map<IMM,TargetExpr> ghidra;
unordered_map<IMM,TargetExpr> ddisasm;
unordered_set<IMM> indirect_jumps;
unordered_map<IMM,IMM> jump_block;
unordered_map<IMM,unordered_set<IMM>> gt_base_jump;
unordered_map<IMM,unordered_set<IMM>> sba_base_targets;

bool verify_jumps(IMM jump_loc, const unordered_set<IMM>& targets_m) {
   if (!indirect_jumps.contains(jump_loc))
      return false;
   auto it = gt.find(jump_loc);
   if (it == gt.end())
      return !targets_m.empty();
   IMM cnt = 0;
   auto const& targets_gt = it->second.targets;
   for (auto t: targets_gt)
      cnt += targets_m.contains(t)? 1: 0;
   // return ((double)cnt/(double)(targets_gt.size()) >= 0.5);
   // return cnt == targets_gt.size();
   return cnt != 0;
   // return !targets_m.empty();
}

void scan_jumps() {
   string s;
   fstream f(dir + "obj.s", fstream::in);
   while (getline(f,s)) {
      size_t p = 0;
      size_t p1 = 0;
      size_t p2 = 0;
      IMM d = 0;
      do {
         p2 = s.find(">",p1);
         p1 = s.find("<",p1);
         if (p1 < p2) {
            ++d;
            if (d == 1)
               p = p1;
            p1 = p1+1;
         }
         else if (p2 < p1) {
            --d;
            p1 = p2+1;
            if (d == 0) {
               s.erase(p, p2-p+1);
               p1 = 0;
            }
         }
         else
            break;
      }
      while (true);
      p = s.find("jmp");
      if (p != string::npos && s.find("*",p) != string::npos
      && s.find("%rip") == string::npos) {
         p = s.find_first_not_of("0");
         indirect_jumps.insert(hex_to_int("0x" + s.substr(p,s.find(" ")-p)));
      }
   }
   f.close();
}


void load_gt() {
   string s;
   fstream f(dir + "log.gt", fstream::in);
   IMM jump_loc = 0;
   IMM table_size = 0;
   IMM base = 0;
   IMM entry_size = 0;
   IMM block = 0;
   unordered_set<IMM> targets;
   while (getline(f,s)) {
      if (s.find("entry number is") != string::npos) {
         auto p = s.find("entry number is") + 16;
         auto p2 = s.find(",", p);
         table_size = dec_to_int(s.substr(p, p2-p));
         block = hex_to_int(s.substr(p2+16, string::npos));
      }
      else if (s.find("INFO:Jump table base is") != string::npos)
         base = hex_to_int(s.substr(24, string::npos));
      else if (s.find("INFO:[indirect instruction]") != string::npos) {
         auto p = s.find(":", 28);
         jump_loc = hex_to_int(s.substr(28, p-28));
      }
      else if (s.find("INFO:entry size is ") != string::npos)
         entry_size = hex_to_int(s.substr(19, string::npos));
      else if (s.find("INFO:Entry#") != string::npos) {
         auto p = s.find(" ", s.find(" ",11)+1)+1;
         targets.insert(dec_to_int(s.substr(p, string::npos)));
      }
      if (jump_loc != 0 && indirect_jumps.contains(jump_loc)
      && s.find("INFO:JMPTBL entry") != string::npos) {
         gt_base_jump[base].insert(jump_loc);
         gt[jump_loc] = TargetExpr{base, entry_size, entry_size, table_size, targets};
         jump_block[jump_loc] = block;
         block = -1;
         jump_loc = -1;
         base = 0;
         entry_size = 0;
         targets.clear();
      }
   }
   f.close();
}


void load_sba() {
   string s;
   IMM t = 0;
   IMM jump_loc = 0;
   IMM base = 0;
   unordered_set<IMM> targets;

   fstream f_icf(dir + "sba.icf", fstream::in);
   while (getline(f_icf,s)) {
      stringstream ss;
      ss << s;
      ss >> jump_loc;
      targets.clear();
      while (ss >> t)
         targets.insert(t);
      if (verify_jumps(jump_loc, targets))
         sba[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
   }
   f_icf.close();

   fstream f_jtable(dir + "sba.jtable", fstream::in);
   while (getline(f_jtable,s)) {
      stringstream ss;
      ss << s;
      ss >> base;
      targets.clear();
      while (ss >> t)
         targets.insert(t);
      sba_base_targets[base] = targets;
   }
   f_jtable.close();
}


void load_angr() {
   string s;
   IMM b = 0;
   IMM jump_loc = -1;
   unordered_set<IMM> targets;
   fstream f(dir + "log.angr", fstream::in);
   while (getline(f,s)) {
      auto p = s.find("instruction:");
      if (p != string::npos) {
         if (verify_jumps(jump_loc, targets)) {
            angr[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
            jump_loc = -1;
         }
         auto s2 = s.substr(13, string::npos);
         if (s2.length() < 10)
            jump_loc = dec_to_int(s2);
         targets.clear();
         continue;
      }
      p = s.find("Edge");
      if (p != string::npos) {
         p = s.find("->") + 3;
         auto s2 = s.substr(p, string::npos);
         if (s2.length() < 10)
            targets.insert(dec_to_int(s.substr(p, string::npos)));
         continue;
      }
   }
   f.close();
}


void load_dyninst() {
   string s;
   IMM jump_loc = -1;
   unordered_set<IMM> targets;
   fstream f(dir + "log.dyninst", fstream::in);
   while (getline(f,s)) {
      auto p = s.find("Get instruction Addr:");
      if (p != string::npos) {
         jump_loc = dec_to_int(s.substr(p+22,string::npos));
         targets.clear();
         continue;
      }
      p = s.find("Get edge:");
      if (p != string::npos) {
         p = s.find("->", p) + 3;
         auto s2 = s.substr(p,string::npos);
         if (s2.compare("18446744073709551615") != 0) {
            auto t = dec_to_int(s2);
            targets.insert(t);
            continue;
         }
      }
      if (verify_jumps(jump_loc, targets)) {
         dyninst[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
         jump_loc = -1;
         targets.clear();
      }
   }
   if (verify_jumps(jump_loc, targets))
      dyninst[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
   f.close();
}


void load_ghidra() {
   string s;
   IMM jump_loc = 0;
   unordered_set<IMM> targets;
   fstream f(dir + "log.ghidra", fstream::in);
   while (getline(f,s)) {
      auto p = s.find("Basic block address:");
      if (p != string::npos) {
         if (verify_jumps(jump_loc, targets))
            ghidra[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
         jump_loc = dec_to_int(s.substr(p+21,string::npos));
         targets.clear();
         continue;
      }
      p = s.find("Instruction address:");
      if (p != string::npos) {
         if (verify_jumps(jump_loc, targets))
            ghidra[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
         jump_loc = dec_to_int(s.substr(p+21,string::npos));
         targets.clear();
         continue;
      }
      p = s.find("Successor:");
      if (p != string::npos) {
         targets.insert(dec_to_int(s.substr(p+11,string::npos)));
         continue;
      }
   }
   f.close();
}


void load_ddisasm() {
   string s = "";
   unordered_map<IMM,unordered_set<IMM>> ddisasm_info;
   fstream f(dir + "log.ddisasm", fstream::in);
   while (getline(f,s)) {
      auto p = s.find(" ");
      auto src = dec_to_int(s.substr(0, p));
      auto dst = dec_to_int(s.substr(p+1,string::npos));
      ddisasm_info[src].insert(dst);
   }
   f.close();

   for (auto const& [jump_loc, expr]: gt) {
      auto src = jump_block[jump_loc];
      if (ddisasm_info.contains(src)) {
         auto const& targets = ddisasm_info.at(src);
         if (verify_jumps(jump_loc, targets))
            ddisasm[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
      }
   }
}


void eval(const string& s, const unordered_map<IMM,TargetExpr>& m,
const string& outfile) {
   fstream f(outfile, fstream::out);
   IMM jtentry = 0;
   IMM jtentry_correct = 0;
   IMM jtentry_over = 0;
   IMM jtentry_under = 0;
   unordered_map<IMM, unordered_set<IMM>> gt_base_targets;
   unordered_map<IMM, unordered_set<IMM>> m_base_targets;

   for (auto const& [base, jumps]: gt_base_jump) {
      for (auto jump: jumps) {
         gt_base_targets[base].insert(gt.at(jump).targets.begin(), gt.at(jump).targets.end());
         if (m.contains(jump))
            m_base_targets[base].insert(m.at(jump).targets.begin(), m.at(jump).targets.end());
      }
      if (&m == &sba && sba_base_targets.contains(base))
         m_base_targets[base].insert(sba_base_targets.at(base).begin(),sba_base_targets.at(base).end());
   }

   f << "Evaluate " << s << " ... \n";
   f << "-----------------------------------\n";
   f << "        jtable_entry_under         \n";
   f << "-----------------------------------\n";
   for (auto const& [base, gt_targets]: gt_base_targets) {
      auto& m_targets = m_base_targets[base];
      IMM correct = 0;
      IMM under = 0;
      IMM over = 0;
      for (auto x: gt_targets)
         if (!m_targets.contains(x))
            ++under;
         else
            ++correct;
      for (auto x: m_targets)
         if (!gt_targets.contains(x))
            ++over;
      if (under > 0) {
         f << "base\t\ttotal\tcorrect\tover\tunder\n";
         if (hex_mode)
            f << std::hex << base << std::dec << "\t\t" << gt_targets.size() << "\t\t" << correct << "\t\t" << over << "\t\t" << under << "\n";
         else
            f << std::dec << base << std::dec << "\t\t" << gt_targets.size() << "\t\t" << correct << "\t\t" << over << "\t\t" << under << "\n";
         f << "jumps\n";
         for (auto jump: gt_base_jump.at(base))
            if (hex_mode)
               f << std::hex << jump << " ";
            else
               f << std::dec << jump << " ";
         f << "\n";
         f << "-----------------------------------\n";
      }
      jtentry += gt_targets.size();
      jtentry_under += under;
      jtentry_correct += correct;
   }
   f << "\n\n";
   f << "-----------------------------------\n";
   f << "        jtable_entry_over          \n";
   f << "-----------------------------------\n";
   for (auto const& [base, gt_targets]: gt_base_targets) {
      auto& m_targets = m_base_targets[base];
      IMM correct = 0;
      IMM under = 0;
      IMM over = 0;
      for (auto x: gt_targets)
         if (!m_targets.contains(x))
            ++under;
         else
            ++correct;
      for (auto x: m_targets)
         if (!gt_targets.contains(x))
            ++over;
      if (over > 0) {
         f << "base\t\ttotal\tcorrect\tover\tunder\n";
         if (hex_mode)
            f << std::hex << base << std::dec << "\t\t" << gt_targets.size() << "\t\t" << correct << "\t\t" << over << "\t\t" << under << "\n";
         else
            f << std::dec << base << std::dec << "\t\t" << gt_targets.size() << "\t\t" << correct << "\t\t" << over << "\t\t" << under << "\n";
         f << "jumps\n";
         for (auto jump: gt_base_jump.at(base))
            if (hex_mode)
               f << std::hex << jump << " ";
            else
               f << std::dec << jump << " ";
         f << "\n";
         f << "-----------------------------------\n";
      }
      jtentry_over += over;
   }
   f << "\n\n";
   f << "-----------------------------------\n";
   f << "              summary              \n";
   f << "-----------------------------------\n";
   f << "#jtentry_gt: " << std::dec << jtentry << "\n";
   f << "#jtentry_correct_" << std::dec << s << ": " << jtentry_correct << "\n";
   f << "#jtentry_over_" << std::dec << s << ": " << jtentry_over << "\n";
   f << "#jtentry_under_" << std::dec << s << ": " << jtentry_under << "\n";
   f.close();
}


// void eval(const string& s, const unordered_map<IMM,TargetExpr>& m,
// const string& outfile, bool classify_jump) {
//    fstream f(outfile, fstream::out);
//    IMM extra = 0;
//    IMM miss = 0;
//    IMM nodetect = 0;
//    IMM dynamic = 0;
//    IMM jtentry = 0;
//    IMM jtentry_correct = 0;
//    IMM jtentry_over = 0;
//    IMM jtentry_under = 0;
// 
//    f << "Evaluate " << s << " ... \n";
//    f << "-----------------------------------\n";
//    f << "             jtable_miss           \n";
//    f << "-----------------------------------\n";
//    f << "jump_loc\n";
//    for (auto const& [jump_loc, expr]: gt)
//       if (!m.contains(jump_loc) || m.at(jump_loc).targets.size() == 0) {
//          ++miss;
//          if (hex_mode)
//             f << std::hex << jump_loc << "\n";
//          else
//             f << std::dec << jump_loc << "\n";
//       }
// 
//    f << "-----------------------------------\n";
//    f << "            jtable_entry           \n";
//    f << "-----------------------------------\n";
//    f << "jump_loc\ttotal\tcorrect\tover\tunder\n";
//    for (auto const& [jump_loc, expr]: gt) {
//       IMM under = 0;
//       IMM over = 0;
//       IMM correct = 0;
//       if (!m.contains(jump_loc))
//          under += expr.targets.size();
//       else {
//          auto const& m_targets = m.at(jump_loc).targets;
//          for (auto t: expr.targets)
//             if (!m_targets.contains(t))
//                ++under;
//             else
//                ++correct;
//          for (auto t: m_targets)
//             if (!expr.targets.contains(t))
//                ++over;
//       }
//       jtentry += expr.targets.size();
//       jtentry_correct += correct;
//       jtentry_over += over;
//       jtentry_under += under;
//       if (hex_mode)
//          f << std::hex << jump_loc << std::dec << "\t\t" << expr.targets.size() << "\t\t" << correct << "\t\t" << over << "\t\t" << under << "\n";
//       else
//          f << std::dec << jump_loc << std::dec << "\t\t" << expr.targets.size() << "\t\t" << correct << "\t\t" << over << "\t\t" << under << "\n";
//    }
// //   f << "-----------------------------------\n";
// //   f << "             jump_extra            \n";
// //   f << "-----------------------------------\n";
// //   f << "jump_loc\n";
//    for (auto const& [jump_loc, expr]: m)
//       if (!gt.contains(jump_loc)) {
//          ++extra;
// //         if (hex_mode)
// //            f << std::hex << jump_loc << "\n";
// //         else
// //            f << std::dec << jump_loc << "\n";
//       }
// //   f << "-----------------------------------\n";
// //   f << "          jump_undetected          \n";
// //   f << "-----------------------------------\n";
// //   f << "jump_loc\n";
//    for (auto const& jump_loc: indirect_jumps) {
//       if (!m.contains(jump_loc)) {
//          ++nodetect;
// //         if (hex_mode)
// //            f << std::hex << jump_loc << "\n";
// //         else
// //            f << std::dec << jump_loc << "\n";
//       }
//    }
//    f << "-----------------------------------\n";
//    f << "#jtable_gt: " << std::dec << gt.size() << "\n";
//    f << "#jtable_miss_" << std::dec << s << ": " << miss << "\n";
//    f << "#jtable_common_" << std::dec << s << ": " << (gt.size() - miss) << "\n";
//    f << "#jtentry_gt: " << std::dec << jtentry << "\n";
//    f << "#jtentry_correct_" << std::dec << s << ": " << jtentry_correct << "\n";
//    f << "#jtentry_over_" << std::dec << s << ": " << jtentry_over << "\n";
//    f << "#jtentry_under_" << std::dec << s << ": " << jtentry_under << "\n";
//    f << "#jump: " << indirect_jumps.size() << "\n";
//    f << "#jump_undetected_" << std::dec << s << ": " << nodetect << "\n";
//    f << "#jump_detected_" << std::dec << s << ": " << m.size() << "\n";
//    f.close();
// }


int main(int argc, char** argv) {
   dir = string(argv[1]) + "/";
   hex_mode = (argc > 2 && string(argv[2]).compare("hex") == 0);
   scan_jumps();
   load_gt();
   load_sba();
   load_angr();
   load_dyninst();
   load_ghidra();
   load_ddisasm();
   eval("sba", sba, dir + "eval.sba");
   eval("angr", angr, dir + "eval.angr");
   eval("dyninst", dyninst, dir + "eval.dyninst");
   eval("ghidra", ghidra, dir + "eval.ghidra");
   eval("ddisasm", ddisasm, dir + "eval.ddisasm");
   return 0;
}
