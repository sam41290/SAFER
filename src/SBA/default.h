/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef DEFAULT_H
#define DEFAULT_H

/* -------------------------------------------------------------------------- */
#define DEFAULT_STATE_EXTERN        extern template class State<BaseLH>; \
                                    extern template class State<TaintDomain>;
#define DEFAULT_STATE_INSTANT              template class State<BaseLH>; \
                                           template class State<TaintDomain>;
#define DEFAULT_FLAG_UNIT_EXTERN    extern template class FlagUnit<BaseLH>; \
                                    extern template class FlagUnit<TaintDomain>;
#define DEFAULT_FLAG_UNIT_INSTANT          template class FlagUnit<BaseLH>; \
                                           template class FlagUnit<TaintDomain>;
#define DEFAULT_FLAG_DOMAIN_EXTERN  extern template class FlagDomain<BaseLH>; \
                                    extern template class FlagDomain<TaintDomain>;
#define DEFAULT_FLAG_DOMAIN_INSTANT        template class FlagDomain<BaseLH>; \
                                           template class FlagDomain<TaintDomain>;
#define DEFAULT_CSTR_DOMAIN_EXTERN  extern template class CstrDomain<BaseLH>; \
                                    extern template class CstrDomain<TaintDomain>;
#define DEFAULT_CSTR_DOMAIN_INSTANT        template class CstrDomain<BaseLH>; \
                                           template class CstrDomain<TaintDomain>;
#define DEFAULT_EXPR_VAL_INSTANT           template class ExprVal<BaseLH>; \
                                           template class ExprVal<TaintDomain>;
/* -------------------------------------------------------------------------- */
#define DEFAULT_EXPR_VAL_CPP                                                   \
   template<> string ExprVal<BaseLH>::to_string() const {                      \
      if (subargs_[0] == nullptr && subargs_[1] == nullptr)                    \
         return string("");                                                    \
      switch (op_) {                                                           \
         case BaseLH::EXPR_VAL_OP::AND:                                        \
            return subargs_[0]->to_string().append(" & ")                      \
                  .append(subargs_[1]->to_string());                           \
         default:                                                              \
            return subargs_[0]->to_string();                                   \
      }                                                                        \
   }                                                                           \
                                                                               \
   template<> void ExprVal<BaseLH>::norm(ExprVal<BaseLH>* rhs) {               \
      if (comparable() && rhs->comparable() &&                                 \
      op_==BaseLH::EXPR_VAL_OP::NONE && rhs->op_==BaseLH::EXPR_VAL_OP::NONE) { \
         auto b1 = subargs_[0]->base();                                        \
         auto r1 = subargs_[0]->range();                                       \
         auto b2 = rhs->subargs_[0]->base();                                   \
         auto r2 = rhs->subargs_[0]->range();                                  \
         auto r = r2-r1;                                                       \
         /* (b1 + r1, 0 + r2) --> (b1 + 0, 0 + r2-r1) */                       \
         if (subargs_[0]->abstract() && !rhs->subargs_[0]->abstract()) {       \
            update(BaseLH::create(b1, Range::ZERO));                           \
            rhs->update(BaseLH::create(r));                                    \
         }                                                                     \
         /* (0 + r1, b2 + r2) --> (0 + r1-r2, b2 + 0) */                       \
         else if (!subargs_[0]->abstract() && rhs->subargs_[0]->abstract()) {  \
            update(BaseLH::create(-r));                                        \
            rhs->update(BaseLH::create(b2, Range::ZERO));                      \
         }                                                                     \
         /* (b1 + r1, b2 + r2) --> (b1 + 0, b2 + r2-r1) */                     \
         else if (subargs_[0]->abstract() && rhs->subargs_[0]->abstract()) {   \
            update(BaseLH::create(b1, Range::ZERO));                           \
            rhs->update(BaseLH::create(b2, r));                                \
         }                                                                     \
         /* (0 + r1, 0 + r2) --> (0 + 0, 0 + r2-r1) */                         \
         else {                                                                \
            update(BaseLH::create(Range::ZERO));                               \
            rhs->update(BaseLH::create(r));                                    \
         }                                                                     \
      }                                                                        \
   }                                                                           \
                                                                               \
   template<> vector<pair<BaseLH::ComparableType,Range>>                       \
   ExprVal<BaseLH>::get_cstr(COMPARE cmp, const ExprVal<BaseLH>* rhs) const {  \
      vector<pair<BaseLH::ComparableType,Range>> res;                          \
      if (comparable() && rhs->comparable() &&                                 \
      op_==BaseLH::EXPR_VAL_OP::NONE && rhs->op_==BaseLH::EXPR_VAL_OP::NONE) { \
         auto const& x = subargs_[0];                                          \
         auto const& y = rhs->subargs_[0];                                     \
         /* (0 + r < b + 0) --> (b > r) --> b in [r+1,oo] */                   \
         if (!x->abstract() && y->base() != 0 && y->range() == Range::ZERO) {  \
            auto b = y->base();                                                \
            auto r = x->range();                                               \
            res.push_back(make_pair(b, Range(Util::opposite(cmp),r)));         \
         }                                                                     \
         /* (b + 0 < 0 + r) --> (b < r) --> b in [-oo,r-1] */                  \
         else if (!y->abstract() && x->base()!=0 && x->range()==Range::ZERO) { \
            auto b = x->base();                                                \
            auto r = y->range();                                               \
            res.push_back(make_pair(b, Range(cmp,r)));                         \
         }                                                                     \
      }                                                                        \
      return res;                                                              \
   }
/* -------------------------------------------------------------------------- */
#define IF_MEMORY_ADDR(addr, region, range, CODE)                              \
   auto v = (BaseLH*)addr;                                                     \
   if (!v->top() && !v->bot() && !BaseLH::notlocal(v)) {                       \
      auto sym = v->base();                                                    \
      if (sym == stackSym || sym == staticSym || sym == 0) {                   \
         auto region = (sym == stackSym)? REGION::STACK: REGION::STATIC;       \
         auto range = v->range();                                              \
         CODE                                                                  \
      }                                                                        \
   }


#define IF_REGION_ADDR(addr, region, range, CODE)                              \
   auto v = (BaseLH*)addr;                                                     \
   if (!v->top() && !v->bot() && !BaseLH::notlocal(v)) {                       \
      auto sym = v->base();                                                    \
      if ((region == REGION::STACK && sym == stackSym) ||                      \
      (region == REGION::STATIC && (sym == staticSym || sym == 0))) {          \
         auto range = v->range();                                              \
         CODE                                                                  \
      }                                                                        \
   }


#define CHECK_UNINIT(state, value, init_size, error)                           \
   if (state->enable_analysis() && !TaintDomain::valid(value, init_size)) {    \
      state->loc.func->uninit_error |= error;                                  \
      LOG3((error == 0x1? "uninit memory address":                             \
           (error == 0x2? "uninit control target":                             \
           (error == 0x4? "uninit critical data": ""))));                      \
   }


#define CHECK_TAINT(state, value, type)                                        \
   if (state->enable_analysis() && state->enable_taint()                       \
   && !TaintDomain::valid(value, TaintDomain::MAX_SIZE)) {                     \
      auto taint_src = TaintDomain::taint_src(value);                          \
      auto taint_dst = state->loc.insn;                                        \
      auto& escape_type = state->loc.func->escaped_taint[type];                \
      escape_type[taint_src].insert(taint_dst);                                \
      LOG3("escaped taint [type " << (int)type << "]:"                         \
                 << " taint src " << taint_src->offset() << ","                \
                 << " taint dst " << taint_dst->offset());                     \
   }


#define REG_TO_BLOCK(states, bsize, bnum, dst_addr, src_vec, src_expr)         \
   /* compute number of blocks */                                              \
   auto const& count_id = get_id(ARCH::REG::bnum);                             \
   auto count_val = (BaseLH*)(states[0]->value_unit(count_id));                \
   auto num_block = count_val->range().lo();                                   \
   /* compute dst addr */                                                      \
   auto const& dst_addr_id = get_id(ARCH::REG::dst_addr);                      \
   auto dst_addr_val = (BaseLH*)(states[0]->value_unit(dst_addr_id));          \
   auto dst_i = dst_addr_val->range().lo();                                    \
   auto dst_r = dst_addr_val->base()==stackSym? REGION::STACK: REGION::STATIC; \
   /* compute src addr */                                                      \
   /* src is register or normal mem range */                                   \
   FOR_STATE(states, k, true, {                                                \
      for (int i = -num_block*bsize; i < num_block*bsize; ++i) {               \
         auto dst_id = UnitId(dst_r, dst_i + i);                               \
         states[k]->update_unit(dst_id, src_vec[k], src_expr);                 \
      }                                                                        \
   });                                                                         \
   BaseDomain::safe_delete(count_val);                                         \
   BaseDomain::safe_delete(dst_addr_val);


#define BLOCK_TO_BLOCK(states, bsize, bnum, dst_addr, src_addr)                \
   /* compute number of blocks */                                              \
   auto const& count_id = get_id(ARCH::REG::bnum);                             \
   auto count_val = (BaseLH*)(states[0]->value_unit(count_id));                \
   auto num_block = count_val->range().lo();                                   \
   /* compute dst addr */                                                      \
   auto const& dst_addr_id = get_id(ARCH::REG::dst_addr);                      \
   auto dst_addr_val = (BaseLH*)(states[0]->value_unit(dst_addr_id));          \
   auto dst_i = dst_addr_val->range().lo();                                    \
   auto dst_r = dst_addr_val->base()==stackSym? REGION::STACK: REGION::STATIC; \
   /* compute src addr */                                                      \
   /* src is memory block (platform-specific) */                               \
   auto const& src_addr_id = get_id(ARCH::REG::src_addr);                      \
   auto src_addr_val = (BaseLH*)(states[0]->value_unit(src_addr_id));          \
   auto src_i = src_addr_val->range().lo();                                    \
   auto src_r = src_addr_val->base()==stackSym? REGION::STACK: REGION::STATIC; \
   /* unsound: when DF is unknown, must perform weak update */                 \
   FOR_STATE(states, k, true, {                                                \
      for (int i = -num_block*bsize; i < num_block*bsize; ++i) {               \
         auto dst_id = UnitId(dst_r, dst_i + i);                               \
         auto src_id = UnitId(src_r, src_i + i);                               \
         auto src_val = states[k]->value_unit(src_id);                         \
         states[k]->update_unit(dst_id, src_val, ExprId::EMPTY);               \
         BaseDomain::safe_delete(src_val);                                     \
      }                                                                        \
   });                                                                         \
   BaseDomain::safe_delete(count_val);                                         \
   BaseDomain::safe_delete(dst_addr_val);                                      \
   BaseDomain::safe_delete(src_addr_val);
/* -------------------------------------------------------------------------- */
#define DEFAULT_EXECUTE_ASSIGN(states)                                         \
   auto destination = dst()->simplify();                                       \
   auto source = src()->simplify();                                            \
   auto size_d = destination->mode_size();                                     \
   auto size_s = source->mode_size();                                          \
   auto src_expr = source->eval_expr();                                        \
   auto src_value = source->eval(states);                                      \
   FOR_STATE(states, k, true, {                                                \
      src_value[k] = src_value[k]->mode(size_d);                               \
   });                                                                         \
                                                                               \
   /* dst is register */                                                       \
   IF_RTL_TYPE(Reg, destination, reg, {                                        \
      if (reg->reg() == ARCH::stack_pointer)                                   \
         CHECK_UNINIT(states[2], src_value[2], size_s, 0x4);                   \
      auto const& id = get_id(reg->reg());                                     \
      FOR_STATE(states, k, true, {                                             \
         states[k]->update_unit(id, src_value[k], src_expr);                   \
      });                                                                      \
   }, {                                                                        \
   /* dst is memory */                                                         \
   IF_RTL_TYPE(Mem, destination, mem, {                                        \
      auto addr_val = mem->addr()->eval(states);                               \
      CHECK_UNINIT(states[2], addr_val[2], mem->addr()->mode_size(), 0x1);     \
      CHECK_TAINT(states[2], src_value[2], 0x0);                               \
      CHECK_TAINT(states[2], addr_val[2], 0x1);                                \
      if (states[0]->enable_analysis()) {                                      \
         if (addr_val[0]->top()) {                                             \
            FOR_STATE(states, k, states[k]->enable_clobber_mem(), {            \
               states[k]->clobber(REGION::STACK);                              \
               states[k]->clobber(REGION::STATIC);                             \
            });                                                                \
         }                                                                     \
         else if (BaseLH::notlocal(addr_val[0])) {                             \
            FOR_STATE(states, k, states[k]->enable_clobber_mem(), {            \
               states[k]->clobber(REGION::STATIC);                             \
            });                                                                \
         }                                                                     \
         else if (!addr_val[0]->bot()) {                                       \
            IF_MEMORY_ADDR(addr_val[0], r, range, {                            \
               if (r == REGION::STACK && range == Range::ZERO)                 \
                  CHECK_UNINIT(states[2], src_value[2], size_s, 0x4);          \
               /* mem block operators */                                       \
               if (mem->mode_string().find(":BLK") != string::npos) {          \
                  IF_RTL_TYPE(Mem, source, mem2, {                             \
                     if (mem2->mode_string().find(":BLK") != string::npos) {   \
                        BLOCK_TO_BLOCK(states, size_d, CX, DI, SI);            \
                     }                                                         \
                     else {                                                    \
                        REG_TO_BLOCK(states,size_d,CX,DI,src_value,src_expr);  \
                     }                                                         \
                  }, {});                                                      \
               }                                                               \
               /* normal memory range */                                       \
               else {                                                          \
                  auto const& l = get_id(r, range.lo());                       \
                  auto const& h = get_id(r, range.hi());                       \
                  FOR_STATE(states, k, true, {                                 \
                     states[k]->update_range(l,h,size_d,src_value[k],src_expr);\
                  });                                                          \
               }                                                               \
            });                                                                \
         }                                                                     \
      }                                                                        \
   }, {                                                                        \
   /* dst is pc */                                                             \
   IF_RTL_TYPE(NoType, destination, no_type, {                                 \
      if (no_type->to_string().compare("pc") == 0) {                           \
         CHECK_UNINIT(states[2], src_value[2], size_s, 0x2);                   \
         CHECK_TAINT(states[2], src_value[2], 0x4);                            \
         /* conditional jump can have direct comparison, not through flags */  \
         IF_RTL_TYPE(IfElse, source, ifel, {                                   \
            auto cflag_value = ifel->cmp()->expr()->eval(s);                   \
            FOR_STATE(states, k, states[k]->enable_cstr(), {                   \
               states[k]->update_unit(UnitId::CFLAG, cflag_value[k], src_expr);\
            });                                                                \
         }, {});                                                               \
      }                                                                        \
   }, {});                                                                     \
   });                                                                         \
   });


#define DEFAULT_EXECUTE_CALL(states)                                           \
   bool call_effect = false;                                                   \
   FOR_STATE(states, k, true, {                                                \
      for (auto r: ARCH::return_value)                                         \
         states[k]->clobber(get_id(r));                                        \
      call_effect |= states[k]->enable_call_effect();                          \
   });                                                                         \
                                                                               \
   if (call_effect && states[0]->enable_analysis()) {                          \
      LOG4("scanning for call arguments");                                     \
      IMM L = oo;                                                              \
                                                                               \
      /* collect args */                                                       \
      vector<IMM> args;                                                        \
      for (auto r: ARCH::call_args)                                            \
         args.push_back(get_sym((ARCH::REG)r));                                \
                                                                               \
      auto addr = states[0]->value_unit(get_id(ARCH::stack_pointer));          \
      IF_REGION_ADDR(addr, REGION::STACK, range, {                             \
         auto lo = std::max(range.lo(), get_bound(REGION::STACK,0));           \
         auto hi = std::min(lo+40, get_bound(REGION::STACK,1));                \
         for (auto i = lo; i <= hi; i += 4)                                    \
            args.push_back(get_sym(REGION::STACK,i));                          \
      });                                                                      \
      BaseDomain::safe_delete(addr);                                           \
                                                                               \
      /* collect ptrs from args */                                             \
      for (auto sym: args) {                                                   \
         auto addr = states[0]->value_unit(get_id(sym));                       \
         IF_REGION_ADDR(addr, REGION::STACK, range, {                          \
            if (range.lo() <= get_bound(REGION::STACK,1))                      \
               L = std::min(L,std::max(range.lo(),get_bound(REGION::STACK,0)));\
         });                                                                   \
         BaseDomain::safe_delete(addr);                                        \
      }                                                                        \
                                                                               \
      /* weak update memory regions */                                         \
      if (L != oo) {                                                           \
         auto const& lo = get_id(REGION::STACK, L);                            \
         auto const& hi = get_id(REGION::STACK, get_bound(REGION::STACK,1));   \
         FOR_STATE(states, k, states[k]->enable_call_effect(), {               \
            states[k]->update_range(lo, hi, 4, BaseDomain::TOP);               \
         });                                                                   \
      }                                                                        \
   }                                                                           \
                                                                               \
   if (states[2]->enable_analysis() && states[2]->enable_taint()) {            \
      for (auto r: ARCH::call_args) {                                          \
         auto value = states[2]->value_unit(get_id(r));                        \
         CHECK_TAINT(states[2], value, 0x2);                                   \
      }                                                                        \
   }

#define DEFAULT_EXECUTE_EXIT(states)                                           \
   if (states[2]->enable_analysis() && states[2]->enable_taint() &&            \
   typeExit_ == EXIT_TYPE::RET) {                                              \
      for (auto r: ARCH::return_value) {                                       \
         auto value = states[2]->value_unit(get_id(r));                        \
         CHECK_TAINT(states[2], value, 0x3);                                    \
      }                                                                        \
   }
/* -------------------------------------------------------------------------- */
#define DEFAULT_EVAL_CONST(states)                                             \
   Value res;                                                                  \
   auto range = Range(i_,i_);                                                  \
   switch (typeConst_) {                                                       \
      case CONST_TYPE::INTEGER: {                                              \
         if (states[0]->enable_analysis())                                     \
            res.set_val(0, BaseLH::create(range));                             \
         if (states[1]->enable_analysis())                                     \
            res.set_val(1, BaseLH::create(range));                             \
         if (states[2]->enable_analysis())                                     \
            res.set_val(2, TaintDomain::create(0, nullptr));                   \
         break;                                                                \
      }                                                                        \
      case CONST_TYPE::LABEL: {                                                \
         if (states[0]->enable_analysis())                                     \
            res.set_val(0, BaseLH::create(get_base(REGION::STATIC), range));   \
         if (states[1]->enable_analysis())                                     \
            res.set_val(1, BaseLH::create(get_base(REGION::STATIC), range));   \
         if (states[2]->enable_analysis())                                     \
            res.set_val(2, TaintDomain::create(0, nullptr));                   \
         break;                                                                \
      }                                                                        \
      default:                                                                 \
         break;                                                                \
   }                                                                           \
   return res;


#define DEFAULT_EVAL_MEMORY(states)                                            \
   Value res;                                                                  \
   auto addr_val = addr()->eval(states);                                       \
   CHECK_UNINIT(states[2], addr_val[2], addr()->mode_size(), 0x1);             \
   CHECK_TAINT(states[2], addr_val[2], 0x1);                                   \
   IF_MEMORY_ADDR(addr_val[0], r, range, {                                     \
      if (range.lo() == range.hi())                                            \
         cachedId_ = get_id(r, range.lo());                                    \
      auto const& lo = get_id(r, range.lo());                                  \
      auto const& hi = get_id(r, range.hi());                                  \
      FOR_STATE(states, k, true, {                                             \
         res.set_val(k, states[k]->value_range(lo, hi, mode_size()));          \
         res.set_val(k, res[k]->mode(mode_size()));                            \
      });                                                                      \
   });                                                                         \
   return res;


#define DEFAULT_EVAL_REGISTER(states)                                          \
   Value res;                                                                  \
   /* replace %rip with next_offset() */                                       \
   if (reg() == ARCH::insn_pointer) {                                          \
      auto pc = states[0]->loc.insn->next_offset();                            \
      auto range = Range(pc,pc);                                               \
      if (states[0]->enable_analysis())                                        \
         res.set_val(0, BaseLH::create(get_base(REGION::STATIC), range));      \
      if (states[1]->enable_analysis())                                        \
         res.set_val(1, BaseLH::create(get_base(REGION::STATIC), range));      \
      if (states[2]->enable_analysis())                                        \
         res.set_val(2, TaintDomain::create(0, nullptr));                      \
   }                                                                           \
   /* otherwise retrieve BaseLH and TaintDomain value */                       \
   else {                                                                      \
      FOR_STATE(states, k, true, {                                             \
         res.set_val(k, states[k]->value_unit(id()));                          \
      });                                                                      \
   }                                                                           \
   FOR_STATE(states, k, true, {                                                \
      res.set_val(k, res[k]->mode(mode_size()));                               \
   });                                                                         \
   return res;


#define DEFAULT_EVAL_SUBREG(states)                                            \
   auto res = expr()->eval(states);                                            \
   FOR_STATE(states, k, true, {                                                \
      if (bytenum() == 0)                                                      \
         res.set_val(k, res[k]->mode(mode_size()));                            \
      else                                                                     \
         res.set_val(k, BaseDomain::TOP);                                      \
   });                                                                         \
   return res;


#define DEFAULT_EVAL_IFELSE(states)                                            \
   auto res = if_expr()->eval(states);                                         \
   auto else_val = else_expr()->eval(states);                                  \
   FOR_STATE(states, k, true, {                                                \
      if (res[k]->ref() > 0) {                                                 \
         res.set_val(k, res[k]->clone());                                      \
         res[k] = res[k]->abs_union(else_val[k]);                              \
         if (res[k] == else_val[k])                                            \
            else_val.set_own(k, false);                                        \
      }                                                                        \
   });                                                                         \
   return res;


#define DEFAULT_EVAL_CONVERSION(states)                                        \
   auto res = simplify()->eval(states);                                        \
   FOR_STATE(states, k, true, {                                                \
      res.set_val(k, res[k]->mode(mode_size()));                               \
   });                                                                         \
   return res;


#define DEFAULT_EVAL_NOTYPE(states)                                            \
   Value res;                                                                  \
   if (to_string().compare("pc") == 0) {                                       \
      auto pc = states[0]->loc.insn->next_offset();                            \
      auto range = Range(pc,pc);                                               \
      if (states[0]->enable_analysis())                                        \
         res.set_val(0, BaseLH::create(get_base(REGION::STATIC), range));      \
      if (states[1]->enable_analysis())                                        \
         res.set_val(1, BaseLH::create(get_base(REGION::STATIC), range));      \
      if (states[2]->enable_analysis())                                        \
         res.set_val(2, TaintDomain::create(0, nullptr));                      \
   }                                                                           \
   return res;


#define DEFAULT_EVAL_UNARY(states)                                             \
   auto res = operand()->eval(states);                                         \
   FOR_STATE(states, k, res[k]->ref() > 0, {                                   \
      res.set_val(k, res[k]->clone());                                         \
   });                                                                         \
                                                                               \
   switch (op()) {                                                             \
      case OP::NEG:                                                            \
         cachedId_ = -operand()->id();                                         \
         if (states[0]->enable_analysis())                                     \
            BaseLH::abs_neg(res[0]);                                           \
         if (states[1]->enable_analysis())                                     \
            BaseLH::abs_neg(res[1]);                                           \
         if (states[2]->enable_analysis())                                     \
            TaintDomain::unary_op(res[2]);                                     \
         break;                                                                \
      case OP::ABS:                                                            \
         if (states[0]->enable_analysis())                                     \
            BaseLH::abs_abs(res[0]);                                           \
         if (states[1]->enable_analysis())                                     \
            BaseLH::abs_abs(res[1]);                                           \
         if (states[2]->enable_analysis())                                     \
            TaintDomain::unary_op(res[2]);                                     \
         break;                                                                \
      default:                                                                 \
         FOR_STATE(states, k, true, {                                          \
            res.set_val(k, BaseDomain::TOP);                                   \
         });                                                                   \
         break;                                                                \
   }                                                                           \
                                                                               \
   FOR_STATE(states, k, true, {                                                \
      res.set_val(k, res[k]->mode(mode_size()));                               \
   });                                                                         \
   return res;


#define DEFAULT_EVAL_BINARY(states)                                            \
   auto res = operand(0)->eval(states);                                        \
   auto op2 = operand(1)->eval(states);                                        \
   FOR_STATE(states, k, res[k]->ref() > 0, {                                   \
      res.set_val(k, res[k]->clone());                                         \
   });                                                                         \
                                                                               \
   switch (op_) {                                                              \
      case OP::PLUS:                                                           \
         if (states[0]->enable_analysis())                                     \
            BaseLH::abs_plus(res[0], op2[0]);                                  \
         if (states[1]->enable_analysis())                                     \
            BaseLH::abs_plus(res[1], op2[1]);                                  \
         if (states[2]->enable_analysis())                                     \
            TaintDomain::binary_op(res[2], op2[2]);                            \
         break;                                                                \
      case OP::MINUS:                                                          \
         if (states[0]->enable_analysis())                                     \
            BaseLH::abs_minus(res[0], op2[0]);                                 \
         if (states[1]->enable_analysis())                                     \
            BaseLH::abs_minus(res[1], op2[1]);                                 \
         if (states[2]->enable_analysis())                                     \
            TaintDomain::binary_op(res[2], op2[2]);                            \
         break;                                                                \
      case OP::MULT:                                                           \
         if (states[0]->enable_analysis())                                     \
            BaseLH::abs_mult(res[0], op2[0]);                                  \
         if (states[1]->enable_analysis())                                     \
            BaseLH::abs_mult(res[1], op2[1]);                                  \
         if (states[2]->enable_analysis())                                     \
            TaintDomain::binary_op(res[2], op2[2]);                            \
         break;                                                                \
      case OP::DIV:                                                            \
         if (states[0]->enable_analysis())                                     \
            BaseLH::abs_div(res[0], op2[0]);                                   \
         if (states[1]->enable_analysis())                                     \
            BaseLH::abs_div(res[1], op2[1]);                                   \
         if (states[2]->enable_analysis())                                     \
            TaintDomain::binary_op(res[2], op2[2]);                            \
         break;                                                                \
      case OP::MOD:                                                            \
         if (states[0]->enable_analysis())                                     \
            BaseLH::abs_mod(res[0], op2[0]);                                   \
         if (states[1]->enable_analysis())                                     \
            BaseLH::abs_mod(res[1], op2[1]);                                   \
         if (states[2]->enable_analysis())                                     \
            TaintDomain::binary_op(res[2], op2[2]);                            \
         break;                                                                \
      case OP::XOR:                                                            \
         if (states[0]->enable_analysis())                                     \
            BaseLH::abs_xor(res[0], op2[0]);                                   \
         if (states[1]->enable_analysis())                                     \
            BaseLH::abs_xor(res[1], op2[1]);                                   \
         if (states[2]->enable_analysis())                                     \
            TaintDomain::binary_op(res[2], op2[2]);                            \
         break;                                                                \
      case OP::IOR:                                                            \
         if (states[0]->enable_analysis())                                     \
            BaseLH::abs_ior(res[0], op2[0]);                                   \
         if (states[1]->enable_analysis())                                     \
            BaseLH::abs_ior(res[1], op2[1]);                                   \
         if (states[2]->enable_analysis())                                     \
            TaintDomain::binary_op(res[2], op2[2]);                            \
         break;                                                                \
      case OP::AND:                                                            \
         if (states[0]->enable_analysis())                                     \
            BaseLH::abs_and(res[0], op2[0]);                                   \
         if (states[1]->enable_analysis())                                     \
            BaseLH::abs_and(res[1], op2[1]);                                   \
         if (states[2]->enable_analysis())                                     \
            TaintDomain::binary_op(res[2], op2[2]);                            \
         break;                                                                \
      case OP::ASHIFT:                                                         \
         if (states[0]->enable_analysis())                                     \
            BaseLH::abs_ashift(res[0], op2[0]);                                \
         if (states[1]->enable_analysis())                                     \
            BaseLH::abs_ashift(res[1], op2[1]);                                \
         if (states[2]->enable_analysis())                                     \
            TaintDomain::binary_op(res[2], op2[2]);                            \
         break;                                                                \
      case OP::COMPARE: {                                                      \
         /* FlagDomain for CstrDomain<BaseLH> */                               \
         res.set_val(0, BaseDomain::TOP);                                      \
         res.set_val(1, BaseDomain::TOP);                                      \
         res.set_val(2, BaseDomain::TOP);                                      \
         if (states[1]->enable_analysis()) {                                   \
            /* ExprId */                                                       \
            array<ExprId*,2> args_id = {nullptr, nullptr};                     \
            array<ExprVal<BaseLH>*,2> args_val = {nullptr, nullptr};           \
            for (int i = 0; i < 2; ++i) {                                      \
               IF_RTL_TYPE(Binary, operand(i), bin, {                          \
                  args_id[i] = operand(i)->eval_expr().clone();                \
                  if (bin->op() == OP::AND) {                                  \
                     auto v0 = bin->operand(0)->eval(states);                  \
                     auto v1 = bin->operand(1)->eval(states);                  \
                     args_val[i]=new ExprVal<BaseLH>(BaseLH::EXPR_VAL_OP::AND, \
                                              (BaseLH*)v0[1], (BaseLH*)v1[1]); \
                  }                                                            \
               }, {                                                            \
                  args_id[i] = ExprId(operand(i)->id()).clone();               \
               });                                                             \
               if (args_val[i] == nullptr) {                                   \
                  auto args = (i == 0)? res[1]: op2[1];                        \
                  args_val[i] = new ExprVal<BaseLH>((BaseLH*)args);            \
               }                                                               \
            }                                                                  \
            res.set_val(1, new FlagDomain<BaseLH>(                             \
                               FlagUnit<BaseLH>(args_id,args_val)));           \
         }                                                                     \
         break;                                                                \
      }                                                                        \
      default:                                                                 \
         FOR_STATE(states, k, true, {                                          \
            res.set_val(k, BaseDomain::TOP);                                   \
         });                                                                   \
         break;                                                                \
   }                                                                           \
                                                                               \
   FOR_STATE(states, k, true, {                                                \
      res.set_val(k, res[k]->mode(mode_size()));                               \
   });                                                                         \
   return res;


#define DEFAULT_EVAL_COMPARE(states)                                           \
   return Value();

#endif
