#include "MultiResCtr.h"

typedef MultiResCtr<short, 10, 3> ShCtr;
typedef MultiResCtr<int, 10, 3> IntCtr;
typedef MultiResCtr<unsigned long, 10, 3> LongCtr;
typedef MultiResCtr<double, 10, 3> DoubleCtr;

typedef MultiResCtr<unsigned short, 8, 1> C1;
typedef MultiResCtr<unsigned short, 4, 2> C2;
typedef MultiResCtr<unsigned short, 2, 4> C3;
typedef MultiResCtr<unsigned short, 1, 8> C4;

int main(int argc, char *argv[]) {
   C1 c1(1); C2 c2(2); C3 c3(4); C4 c4(8);

   cout << sizeof(c1) << ' ' << sizeof(c2) << ' ' 
        << sizeof(c3) << ' ' << sizeof(c4) << endl;
   cout << sizeof(MultiResCtr<unsigned int, 8, 1>) << ' '
        << sizeof(MultiResCtr<unsigned long, 8, 1>) << endl;

   for (unsigned i=1; i < 256; i *= 2) {
      cout << i-1 << ": " << i/2+1 << "\t";
   }
   cout<<endl;
   for (unsigned i=1; i < 256; i *= 2) {
      c1.inc(i-1, i/2+1);
      cout << i-1 << ": C1: " << c1;
      c2.inc(i-1, i/2+1);
      c3.inc(i-1, i/2+1);
      c4.inc(i-1, i/2+1);
   }
   cout << "C1: " << c1;
   cout << "C2: " << c2;
   cout << "C3: " << c3;
   cout << "C4: " << c4;

   c1.advance(127);
   for (unsigned i=0; i < 8; i++)
      cout << c1.projCount(i) << ' ';
   cout << endl;
   c1.inc(256);
   c2.inc(256);
   c3.inc(256);
   c4.inc(256);
   cout << "C1: " << c1;
   cout << "C2: " << c2;
   cout << "C3: " << c3;
   cout << "C4: " << c4;

   LongCtr ic(2);
   unsigned maxl=1000*1000*1000;
   for (unsigned i=0; i < maxl; i++)
      ic.inc(i);
   cout << ic.projCount(9) << endl;
}
