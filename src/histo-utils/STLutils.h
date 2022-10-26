#ifndef STL_UTILS_H
#define STL_UTILS_H

#include <tuple>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <vector>
#include <list>
#include <map>
#include <limits.h>
#include "FastHash.h"
#include "Base.h"

using namespace std;

template <class T>
void print(const vector<T>& t, ostream& os, char ldelim='[', char rdelim=']',
           const char* sep=", ") {
   os << ldelim; bool b = false;
   for (const T& e: t) {
      if (b) os << sep;
      else b = true;
      os << e;
   }
   os << rdelim;
}

template <class T>
void print(const unordered_set<T>& t, ostream& os, char ldelim='{', 
           char rdelim='}', const char* sep=", ") {
   os << ldelim; bool b = false;
   for (auto e: t) {
      if (b) os << sep;
      else b = true;
      os << e;
   }
   os << rdelim;
}

template <class T>
void print(const set<T>& t, ostream& os, char ldelim='{', 
           char rdelim='}', const char* sep=", ") {
   os << ldelim; bool b = false;
   for (auto e: t) {
      if (b) os << sep;
      else b = true;
      os << e;
   }
   os << rdelim;
}

template <class K, class V>
void print(const unordered_map<K, V>& t, ostream& os, char ldelim='{', 
           char rdelim='}', const char* itemsep=", ", const char*keysep=":") {
   os << ldelim; bool b = false;
   for (auto e: t) {
      if (b) os << itemsep;
      else b = true;
      os << e.first << keysep << e.second;
   }
   os << rdelim;
}

template <class K, class V>
void print(const map<K, V>& t, ostream& os, char ldelim='{', 
           char rdelim='}', const char* itemsep=", ", const char*keysep=":") {
   os << ldelim; bool b = false;
   for (auto e: t) {
      if (b) os << itemsep;
      else b = true;
      os << e.first << keysep << e.second;
   }
   os << rdelim;
}

template<class T1, class T2>
void print(const pair<T1, T2>& tp, ostream& os, 
           char ldelim='(', char rdelim=')', const char* sep=", ") {
   os << ldelim << tp.first << sep << tp.second << rdelim;
}

template<class Tuple, std::size_t N>
struct TuplePrinter {
    static void print(const Tuple& t, ostream& os, const char* sep=", ") {
        TuplePrinter<Tuple, N-1>::print(t, sep);
        os << ", " << std::get<N-1>(t);
    }
};
 
template<class Tuple>
struct TuplePrinter<Tuple, 1> {
    static void print(const Tuple& t, ostream& os, const char* sep=", ") {
        os << std::get<0>(t);
    }
};

template<class... Args>
void print(const std::tuple<Args...>& t, ostream& os, 
           char ldelim='(', char rdelim=')', const char* sep=", ") {
    os << ldelim;
    TuplePrinter<decltype(t), sizeof...(Args)>::print(t, os, sep);
    os << rdelim;
};

template <class T>
ostream& operator<<(ostream& os, const vector<T>& t) { print(t, os); return os;};
template <class T>
ostream& operator<<(ostream& os, const set<T>& t) { print(t, os); return os;};
template <class T>
ostream& operator<<(ostream& os, const unordered_set<T>& t) 
  { print(t, os); return os;};
template <class K, class T>
ostream& operator<<(ostream& os, const unordered_map<K, T>& t) 
  { print(t, os); return os;};
template<class... Args>
ostream& operator<<(ostream& os, const tuple<Args...>& t) 
  { print(t, os); return os;};

namespace std {
    namespace
    {

        // Code from boost
        // Reciprocal of the golden ratio helps spread entropy
        //     and handles duplicates.
        // See Mike Seymour in magic-numbers-in-boosthash-combine:
        //     http://stackoverflow.com/questions/4948780

        template <class T>
        inline void hash_combine(std::size_t& seed, T const& v)
        {
            seed ^= std::hash<T>()(v) + 0x9e3779b9 + (seed<<6) + (seed>>2);
        }

        // Recursive template code derived from Matthieu M.
        template <class Tuple, size_t Index = std::tuple_size<Tuple>::value - 1>
        struct HashValueImpl
        {
          static void apply(size_t& seed, Tuple const& tuple)
          {
            HashValueImpl<Tuple, Index-1>::apply(seed, tuple);
            hash_combine(seed, std::get<Index>(tuple));
          }
        };

        template <class Tuple>
        struct HashValueImpl<Tuple,0>
        {
          static void apply(size_t& seed, Tuple const& tuple)
          {
            hash_combine(seed, std::get<0>(tuple));
          }
        };
    }

    template <typename ... TT>
    struct hash<std::tuple<TT...>> 
    {
        size_t
        operator()(std::tuple<TT...> const& tt) const
        {                                              
            size_t seed = 0;                             
            HashValueImpl<std::tuple<TT...> >::apply(seed, tt);    
            return seed;                                 
        }                                              

    };

   template <class T> 
   struct hash<vector<T>> {
   public:
      size_t operator()(const vector<T>& t) const {
         size_t tc[t.size()]; unsigned j=0;
         for (const T& v: t) {
            std::hash<T> x;
            tc[j++] = x(v);
         }
         return fasthash64(&tc[0], t.size()*sizeof(size_t), t.size());
      }
   };

   template <class T> 
   struct hash<set<T>> {
   public:
      size_t operator()(const set<T>& t) const {
         size_t tc[t.size()]; unsigned j=0;
         for (const T& v: t) {
            std::hash<T> x;
            tc[j++] = x(v);
         }
         return fasthash64(&tc[0], t.size()*sizeof(size_t), t.size());
      }
   };

   template <class T1, class T2> 
   struct hash<pair<T1, T2>> {
   public:
      size_t operator()(const pair<T1, T2>& t) const {
         size_t rv = hash<T1>()(t.first);
         hash_combine(rv, t.second);
         return rv;
      }
   };

   template <> struct hash<const char*> {
     public :
      size_t operator()(const char* u) const { return fasthash64(u); }
   };

   template <> class equal_to<const char*> {
     public:
      size_t operator()(const char* s1, const char *s2) const
      { return (strcmp(s1,s2) == 0);  }
   };

};

template <class C>
class IndexAsg  {
   unsigned count_;
   string prefix_;
   unordered_map<C, unsigned> dict_;

 public:
   void setPrefix(string p) { prefix_=p; };
   string getPrefix() const { return prefix_;}

   void clear() { 
      dict_.clear(); 
      count_ = 0; 
   };

   unsigned getIndex(C nm, bool& isNew) {
      if (dict_.find(nm) != dict_.end()) {
         isNew = false;
         return dict_[nm];
      }
      else {
         isNew = true;
         dict_[nm] = count_;
         return count_++;
      }
   };

   string getName(C nm, bool& isNew) {
      unsigned idx = getIndex(nm, isNew);
      return prefix_ + to_string(idx);
   }
};


template <class C> void
serialize(ostream& os, const C& c) {
   c.serialize(os);
}

template <> inline void
serialize<const char*>(ostream& os, const char* const& s) {
   uint64_t l = strlen(s);
   os << l << ' ';
   os.write(s, l);
   //os << endl;
}

template <class C> void
deserialize(istream& is, C& c) {
   new (&c) C(is);
}

template <> inline void
deserialize<const char *>(istream& is, const char*& s) {
   uint64_t l; char c;
   is >> l;
   is.read(&c, 1);
   assert_try(c == ' ');
   char *ss = new char[l+1];
   is.read(ss, l);
   ss[l] = '\0';
   s = ss;
   //is.ignore(1);
}

template <class C> void
serializevs(const vector<C>& v, ostream& os) {
   os << v.size() << endl;
   for (uint64_t i=0; i < v.size(); i++) {
      v[i].serialize(os);
      os << endl;
   }
}

template <class C> void
deserializevs(istream& is, vector<C>& v) {
   uint64_t n;
   is >> n;
   for (uint64_t i=0; i < n; i++) {
      char t;
      is.read(&t, 1);
      assert_try(t == '\n');
      if (i >= v.size())
         v.emplace_back(is);
      else {
         C* e = &v[i];
         new (e) C(is);
      }
   }
   is.ignore(1);
}

#endif
