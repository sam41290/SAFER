/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef ARCH_H
#define ARCH_H

#include <string>
#include <unordered_set>
// -----------------------------------------------------------------------------
class X86_64 {
 public:
   static const int NUM_REG = 63;
   enum class REG: char {
      UNKNOWN,
      AX, BX, CX, DX, SP, BP, SI, DI,
      R8, R9, R10, R11, R12, R13, R14, R15,
      XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
      XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,
      XMM16, XMM17, XMM18, XMM19, XMM20, XMM21, XMM22, XMM23,
      XMM24, XMM25, XMM26, XMM27, XMM28, XMM29, XMM30, XMM31,
      ST, ST1, ST2, ST3, ST4, ST5, ST6, ST7,
      ES, FS, GS, FLAGS, IP,
      CF_FLAGS
   };
   static inline const std::string REG_STR[NUM_REG] = {
      "",
      "ax", "bx", "cx", "dx", "sp", "bp", "si", "di",
      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
      "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6",
      "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13",
      "xmm14", "xmm15", "xmm16", "xmm17", "xmm18", "xmm19", "xmm20",
      "xmm21", "xmm22", "xmm23", "xmm24", "xmm25", "xmm26", "xmm27",
      "xmm28", "xmm29", "xmm30", "xmm31",
      "st", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
      "es", "fs", "gs", "flags", "ip",
      "cf_flags"
   };
   static const REG stackPtr = X86_64::REG::SP;
   static const REG framePtr = X86_64::REG::BP;
   static const REG insnPtr  = X86_64::REG::IP;
   static const REG compareFlags = X86_64::REG::FLAGS;
   static const REG controlFlags = X86_64::REG::CF_FLAGS;

   static inline const std::unordered_set<REG> argsReg = {
      REG::DI, REG::SI, REG::DX, REG::CX, REG::R8, REG::R9, REG::R10,
      REG::XMM0, REG::XMM1, REG::XMM2, REG::XMM3, REG::XMM4, REG::XMM5,
      REG::XMM6, REG::XMM7, REG::XMM8, REG::XMM9, REG::XMM10, REG::XMM11,
      REG::XMM12, REG::XMM13, REG::XMM14, REG::XMM15
   };
   static inline const std::unordered_set<REG> calleeSaved = {
      REG::SP, REG::BX, REG::BP, REG::R12, REG::R13, REG::R14, REG::R15
   };
   static inline const std::unordered_set<REG> criticalReg = {
      REG::SP
   };
   static inline const std::unordered_set<REG> callClobberedReg = {
      REG::CX, REG::SI, REG::DI, REG::R8, REG::R9, REG::R10, REG::R11,
      REG::XMM2, REG::XMM3, REG::XMM4, REG::XMM5, REG::XMM6, REG::XMM7,
      REG::XMM8, REG::XMM9, REG::XMM10, REG::XMM11,
      REG::XMM12, REG::XMM13, REG::XMM14, REG::XMM15,
      REG::ST2, REG::ST3, REG::ST4, REG::ST5, REG::ST6, REG::ST7
   };
   static inline const std::unordered_set<REG> callReturnValueReg = {
      REG::AX, REG::DX, REG::XMM0, REG::XMM1, REG::ST, REG::ST1
   };

 public:
   static REG from_string(const std::string& reg) {
      for (int i = 0; i < NUM_REG; ++i)
         if (!reg.compare(X86_64::REG_STR[i]))
            return (REG)i;
      return REG::UNKNOWN;
   };
   static std::string to_string(REG reg) {
      return X86_64::REG_STR[(int)reg];
   };
   static bool critical(REG reg) {
      return X86_64::criticalReg.find(reg) != X86_64::criticalReg.end();
   };
   static bool args(REG reg) {
      return X86_64::argsReg.find(reg) != X86_64::argsReg.end();
   };
   static bool callee_saved(REG reg) {
      return X86_64::calleeSaved.find(reg) != X86_64::calleeSaved.end();
   };
};


#endif