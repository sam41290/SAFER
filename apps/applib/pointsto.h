
#ifndef POINTSTO_H
#define POINTSTO_H


#include <stdio.h>
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "Binary.h"
#include "Dfs.h"
#include "lifter.h"
#include "domain.h"
#include "analysishandler.h"

using namespace std;

enum class BlockType { STACK, HEAP, GLOBAL, REGISTER, CONSTANT, UNKNOWN };

class MemBlock {
  private:
    string ID_;
    BlockType T_;
    RegValType rval_;
    vector <uint64_t> cstvals_;
    vector <MemBlock *> pointsTo_;

}

#endif
