#include <iostream>
#include <vector>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>
using namespace std;

int main(int argc, char *argv[]) {
   int n=1000;
   if (argc > 1) n = atoi(argv[1]);
   char *s1=0, *s=0;
   for (int i=n; i > 0; i--) {
      s1 = s;
      s = (char*)malloc(1<<20);
      if (s == 0) {
         free(s1);
         cout << "malloc failed after allocating " << n-1 << "MB\n";
         return 1;
      }
      else bzero(s, 1<<20);
   }

   cout << "malloc successfully allocated " << n-1 << "MB\n";

   return 0;
}
