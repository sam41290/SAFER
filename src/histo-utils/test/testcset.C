#include "cset.h"

#include <iostream>
using namespace std;

#define Container CVector<unsigned>
//#define Container vector<unsigned>
int logLevel;
int main(int argc, char* argv[]) {
   CSet<unsigned, Container> ms;
   cout << "sizeof ms: " << sizeof(ms) << endl;
   cout << ms.max_size() << endl;

   ms.insert(11);
   ms.insert(12);
   cout << ms << endl;
   ms.insert(12);
   ms.insert(10);
   ms.insert(12);
   ms.insert(110);
   ms.insert(110);
   ms.insert(111);
   ms.insert(10);
   ms.insert(110);
   ms.insert(111);
   cout << ms << endl;

   CSet<unsigned, Container> ms1, ms2, ms3;

   ms1.insert(12);
   cout << ms.isSubset(ms1) << ms1.isSubset(ms) << endl;

   ms2.insert(10);
   cout << ms.isSubset(ms2) << ms2.isSubset(ms) << endl;

   ms3.insert(111);
   cout << ms.isSubset(ms3) << ms3.isSubset(ms) << endl;

   ms1.insert(10);
   cout << ms.isSubset(ms1) << ms1.isSubset(ms) << endl;

   ms1.insert(111);
   cout << ms.isSubset(ms1) << ms1.isSubset(ms) << endl;

   ms1.insert(110);
   cout << ms.isSubset(ms1) << ms1.isSubset(ms) << endl;

   ms1.insert(11);
   cout << ms.isSubset(ms1) << ms1.isSubset(ms) << endl;

   ms1.insert(112);
   cout << ms.isSubset(ms1) << ms1.isSubset(ms) << endl;

   cout << ms1 << endl;

   ms2.set_union(ms3);
   cout << ms2 << endl;

   ms3.set_union(ms2);
   cout << ms3 << endl;

   ms3.set_union(ms);
   cout << ms3 << endl;

   ms1.set_union(ms3);
   cout << ms1 << endl;

   ms1.set_union(ms3);
   cout << ms1 << endl;

   ms1.set_union(ms);
   cout << ms1 << endl;

   long nu=0, ns=0, ni=0, nil=0;
   for (int j=0; j < 100; j++) {
      CSet<unsigned, Container> s1, s2, s3, s4, s5;
      unsigned k = random();
      while (k > 1000)
         k = random();
      for (unsigned j=0; j < k; j++) {
         unsigned l = random();
         s1.insert(l);
         ni++; nil += sizeof(s1);
         if (l & 0x1) {
            s2.insert(l);
            ni++; nil += sizeof(s2);
         }
         if (l & 0x2) {
            s3.insert(l);
            ni++; nil += sizeof(s3);
         }
         if (!(l &0x1) && !(l & 0x2)) {
            s4.insert(l);
            ni++; nil += sizeof(s4);
         }
         if ((l &0x1) && (l & 0x2)) {
            s5.insert(l);
            ni++; nil += sizeof(s5);
         }
      }
      assert_abort(s1.size() == s2.size()+s3.size()+s4.size()-s5.size());
      if (s4.size() > 0)
         assert_abort(!s1.isSubset(s2) && !s1.isSubset(s3));
      assert_abort(s2.isSubset(s1) && s3.isSubset(s1));
      ns += s1.size() + s2.size() + s3.size();
      // the non-subset operations should take almost no time, so we don't count

      s2.set_union(s3);
      nu += s2.size() + s3.size();
      if (s4.size() > 0)
         assert_abort(!s1.isSubset(s2) && !s1.isSubset(s3));
      assert_abort(s2.isSubset(s1) && s3.isSubset(s1));
      ns += s1.size() + s2.size() + s3.size();

      s2.set_union(s4);
      nu += s2.size() + s4.size();
      assert_abort(s2.isSubset(s1) && s3.isSubset(s1));
      assert_abort(s1.isSubset(s2));
      ns += s1.size() + s2.size() + s3.size() + s2.size();

      for (unsigned i=0; i < 100; i++) {
         s1.set_union(s2);
         nu += s1.size() + s2.size();
         assert_abort(s1.isSubset(s2));
         ns += s1.size() + s2.size();
      }
   }
   cout << "unions involved " << nu/1.e6 << "M elements\n";
   cout << "subset involved " << ns/1.e6 << "M elements\n";
   cout << "insert involved " << nil/1.e6 << "M elements, " 
        << ni/1.e6 << "M elements inserted\n";

   // Inserts are horrendously slow: in this example, 10 microseconds/insert!
   // Even when we consider the linear-time cost of insertion, the cost is
   // high, at about 1 microsecond per element involved in insertion. 
   // Unions in the best case (no element actually added) are reasonably fast, 
   // at 4ns/element. Subset in the worst case (one is a subset of other) is 
   // about the same speed. (This is to be expected because the basic steps
   // are almost identical across best-case union and worst-case subset.)
}
