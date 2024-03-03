#ifndef LIBANALYSIS_NEW_H
#define LIBANALYSIS_NEW_H

#include <string>
#include <vector>
#include <tuple>
#include <utility>
#include <unordered_map>

namespace analysis_new {
   struct JTableBase {
      int64_t val;
   };
   struct JTableRange {
      uint8_t stride;
   };
   struct JTableAddr {
      struct JTableBase base;
      struct JTableRange range;
   };
   struct JTableMem {
      struct JTableAddr addr;
   };
   struct JTableOffsetMem {
      struct JTableBase offset;
      struct JTableMem mem;
   };
   struct JTable {
    private:
       std::vector<std::pair<int64_t,struct JTableOffsetMem>> t1;
       std::vector<std::pair<int64_t,struct JTableAddr>> t2;
       std::vector<std::pair<int64_t,struct JTableMem>> t3;
    public:
      void add(int64_t jumpLoc, const struct JTableOffsetMem& v) {t1.push_back({jumpLoc,v});};
      void add(int64_t jumpLoc, const struct JTableAddr& v) {t2.push_back({jumpLoc,v});};
      void add(int64_t jumpLoc, const struct JTableMem& v) {t3.push_back({jumpLoc,v});};
      const std::vector<std::pair<int64_t,JTableOffsetMem>>& type1() {return t1;};
      const std::vector<std::pair<int64_t,JTableAddr>>&      type2() {return t2;};
      const std::vector<std::pair<int64_t,JTableMem>>&       type3() {return t3;};
   };

   void start(int32_t thr, const std::string& autoFile);
   void load(int32_t entry, const std::string& attFile, const std::string& sizeFile, const std::string& jtableFile);
   void analyse();
   int uninit();
   bool preserved(const std::vector<std::string>& regs);
   std::unordered_map<int32_t,int32_t> stack_height();

   // std::vector<std::tuple<int32_t,int32_t,int32_t,int32_t,int32_t,int32_t>> jump_table();
   JTable jump_table();
   void stop();
}

#endif

