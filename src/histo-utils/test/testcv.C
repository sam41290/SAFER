#include "../cvector.h"
#include <iostream>
using namespace std;

#define sz(x) cout << "sizeof(" << #x << ")=" << sizeof(x) << endl

int logLevel;
int main(int argc, char* argv[]) {
   CVector<int> mv;
   sz(mv);
   cout << mv.max_size() << endl << endl;

   mv.push_back(100);
   mv.push_back(101);
   mv.push_back(102);
   mv.push_back(103);
   mv.push_back(104);
   for (unsigned i=0; i < mv.size(); i++)
      cout << mv[i] << endl;
   cout << endl;
   mv[2]=1001;
   mv[4]=10000;
   mv.push_back(1002);
   mv.push_back(1004);
   for (unsigned i=0; i < mv.size(); i++)
      cout << mv[i] << endl;
   cout << endl;

   cout << "popped " << mv.pop_back_inefficient() << endl;
   cout << "popped " << mv.pop_back_inefficient() << endl;
   cout << "popped " << mv.pop_back_inefficient() << endl;
   cout << "popped " << mv.pop_back_inefficient() << endl;
   cout << "popped " << mv.pop_back_inefficient() << endl;

   for (unsigned i=0; i < mv.size(); i++)
      cout << mv[i] << endl;
   cout << endl;

   for (unsigned i=mv.size(); i < (mv.max_size()*3)/4; i++)
      mv.push_back(i);

   cout << mv.size() << ' ' << mv.max_size() << endl;
   cout << endl;

   mv.freeze();
}
