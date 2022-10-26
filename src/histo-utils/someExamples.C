#include <iostream>
#include <array>
#include <functional>

template <class BinType, auto func>
class ttt {
public:
   void print(BinType p) {
      std::cout << p << ' ' << func(p) << std::endl;
   };
};

template <class D, class C, C... B>
class tt {
   //inline static constexpr std::array<int, N> A={B...};
   struct ttt {
      inline static const constexpr C X[]={B...};
      inline static const int n = sizeof(X)/sizeof(C);
      static constexpr auto f(const C* x) {
         std::array<C,n> rv = {23};
         for (int i=1; i < n; i++)
            rv[i] = x[i]*10;
         return rv;
      }
   };
   inline static const constexpr auto A=ttt::f(ttt::X);
   int b;
   int cc[D::N];
public:
   void print() {
      unsigned N = sizeof(A)/sizeof(int);
      for (unsigned i=0; i < N; i++)
         std::cout << A[i] << ' ';
      std::cout << '\n';
   }
};

template<class A, class B>
class tttt {
 public:
   constexpr int f(B p) {
      return 2*A::func(p);
   };
};   

template<int b> struct AA {
   static constexpr int func(int x) { return x*b; };
};

template <int m>
struct Int {
   int val;
   inline static const int N=10;
   inline static const int M=m;

   Int(int x) { val=x;}
};

template <int m>
std::ostream& operator<<(std::ostream& os, const Int<m>& c) { 
   return os << c.val;
};

int main(int argc, char *argv[]) {
  tt<Int<44>, int, Int<44>::M, 10, 11, 12, 13> mytt;
  mytt.print();

  constexpr auto ff = [](int a){return 2*a*a;};
  ttt<int, ff> myttt;
  static_assert(ff(4)==32, "no");
  myttt.print(3);

  constexpr auto f3 = []<auto b>(int a){return 2*a*b;};
  constexpr auto f4 = [f3](int a){return f3.operator()<4>(a);};
  ttt<int, f4> t3;
  static_assert(f4(7)==56, "no");
  t3.print(6);

  tttt<AA<4>, int> t4;
  static_assert(t4.f(7)==56, "nono");
}

