#ifndef CSET_H
#define CSET_H

#include "cvector.h"
#include "STLutils.h"

using namespace std;
template<class ElemType, class Container = CVector<ElemType>> 
class CSet: public Container{
 public:
   bool isSaturated() const {
      return (this->size() >= this->max_size());
   }

   bool contains(const ElemType& e) const {
      bool rv;
      findpos(e, rv);
      return rv;
   }

   void insert(const ElemType& e) {
      if (isSaturated()) return;
      bool found;
      unsigned pos = findpos(e, found);
      if (found)
         return;
      else 
         if constexpr (std::is_same_v<Container, CVector<ElemType>>)
            Container::insert(pos, e);
         else Container::insert(Container::begin()+pos, e);
   };

   bool isSubset(const CSet<ElemType, Container>& sup) const {
      unsigned i=0, j=0, sz = this->size();
      bool found;

      if (sz == 0) return true;
      if (isSaturated()) return false;

      unsigned l = sup.findpos((*this)[0], found);
      if (!found) return false;
      if (sz == 1) return true;

      unsigned r = sup.findpos((*this)[sz-1], found);
      if (!found) return false;

      for (unsigned k=1; k < sz-1; k++) {
         l = sup.findpos((*this)[k], found, l, r);
         if (!found)
            return false;
      }
      return true;
   };

   void set_union(const CSet<ElemType, Container>& s) {
      if (isSaturated()) return;
      unsigned sz = s.size();
      switch (sz) {
      case 2: insert(s[1]);
      case 1: insert(s[0]); 
      case 0: return;
      default:
         break;
      }

      CSet<ElemType, Container> ns;
      unsigned i, j;
      for (i=0, j=0; (i < this->size() && j < s.size());) {
         if ((*this)[i] < s[j])
            ns.push_back((*this)[i++]);
         else if ((*this)[i] > s[j])
            ns.push_back(s[j++]);
         else {
            ns.push_back(s[j]);
            i++; j++;
         }
         if (ns.isSaturated()) break;
      }
      while (i < this->size() && !ns.isSaturated())
         ns.push_back((*this)[i++]);
      while (j < s.size() && !ns.isSaturated())
         ns.push_back(s[j++]);
      *this = ns;
   };

 private:
   // Binary search for v in positions l through r-1. 
   // Requires: (*this[l] <= v || l == 0) && (v <= *this[r-1] || r == size())
   unsigned findpos(const ElemType& v, bool& fnd, unsigned l, unsigned r) const{
      fnd = false;
      if (l == r)
         return l;
      r--;
      if (v <= (*this)[l]) {
         fnd = (v == (*this)[l]);
         return l;
      }
      if (l+15 <= r && v <= (*this)[l+15]) {
         r = l+15;
         goto seq_search;
      }
      if (v > (*this)[r])
         return r+1;

      // Inv here and post-loop: *this[l] < v <= *this[r]) 
      while (l+15 < r) {
         unsigned mid = (l+r)>>1;
         if (v <= (*this)[mid])
            r = mid;
         else l = mid;
      }

   seq_search:
      for (unsigned j=l+1; j <= r; j++)
         if (v <= (*this)[j]) {
            fnd = (v == (*this)[j]);
            return j;
         }
      assert_abort(0);
   }

   unsigned findpos(const ElemType& v, bool& fnd, unsigned l=0) const {
      return findpos(v, fnd, l, this->size());
   }
};

#endif
