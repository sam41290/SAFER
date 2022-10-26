#include "../MultiResCtr.h"

typedef MultiResCtr LongCtr;

typedef MultiResCtr C1;
typedef MultiResCtr C2;
typedef MultiResCtr C3;
typedef MultiResCtr C4;

int main(int argc, char *argv[]) {
   C1 c1(1); C2 c2(2); C3 c3(4); //C4 c4(8);

   cout << sizeof(c1) << endl;

   for (unsigned i=1; i < 256; i *= 2) {
      cout << i-1 << ": " << i/2+1 << "\t";
   }
   cout<<endl;

   for (unsigned i=1; i < 256; i *= 2) {
      c1.inc(i-1, i/2+1);
      cout << i-1 << ": C1: " << c1;
      c2.inc(i-1, i/2+1);
      c3.inc(i-1, i/2+1);
      //c4.inc(i-1, i/2+1);
   }
   cout << "C1: " << c1;
   cout << "C2: " << c2;
   cout << "C3: " << c3;
   //cout << "C4: " << c4;

   c1.advance(127);
   for (unsigned i=0; i < 8; i++)
      cout << c1.projCount(i) << ' ';
   cout << endl;
   c1.inc(256);
   c2.inc(256);
   c3.inc(256);
   //c4.inc(256);
   cout << "C1: " << c1;
   cout << "C2: " << c2;
   cout << "C3: " << c3;
   //cout << "C4: " << c4;

   LongCtr ic(2);
   unsigned maxl = (1u<<30)+2;
   for (unsigned i=0; i < maxl; i++)
      ic.inc(i);
   cout << "IC: " << ic;
   for (unsigned i=0; i < 10; i++)
      cout << ic.projCount(i) << ' ';
}
