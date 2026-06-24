#ifndef LIFTER_H
#define LIFTER_H

#include "type.h"
#include "rtl_config.h"
#include "analysishandler.h"
namespace SBI {
    AnalysisHandler * load(vector<IMM> entry, const string& attFile, const string& sizeFile, const string& jtableFile);
    SBAFunction * analyze_function(AnalysisHandler *p, int64_t fptr);
    vector<tuple<IMM,RTL*,vector<uint8_t>>> load_2(const string& attFile, unordered_map<int64_t, int64_t>& insnSize);
    AnalysisHandler* create_handler_2(const vector<tuple<IMM,RTL*,vector<uint8_t>>>& offset_rtl_raw,const vector<IMM>& fptr_list, const unordered_map<IMM,unordered_set<IMM>>& icfs);
}
#endif
