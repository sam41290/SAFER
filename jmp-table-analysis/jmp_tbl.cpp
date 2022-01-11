#include "interface.h"
#include <iostream>
#include <fstream>
#include <string>
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <iterator>
#include <vector>

#include "../run/config.h"

using namespace std;

void load_model()
{
	/*
    string s2 = "/home/soumyakant/Static_binary_instrumentation_elf_x86-64/jmp-table-analysis/total.auto";
    //Interface* ai = new Interface();
    // Interface::ocaml_train_imap(s0, string(""));
    Interface::ocaml_load_auto(s2);
*/
}

Interface* ai;
string s2 = TOOL_PATH"auto/jmp_tbl_total.auto";

int main( int argc, char *args[]) {
        string s;
	ai = new Interface();
	Interface::ocaml_load_auto(s2);
	string fname(args[1]);
	ifstream inp(fname);
	ofstream out;
	out.open("tmp/result.txt",ios_base::app);
	while (getline(inp, s)) {
	      std::istringstream iss(s);
              std::vector<std::string> results(std::istream_iterator<std::string>{iss},std::istream_iterator<std::string>());
              cout<<"Analyzing :"<< results[1]<<endl;
              ai->analyze(results[1]);
	      cout<<"analyzing complete\n";
	      vector<pair<pair<int64,int64>,int>> t = ai->get_jump_table_target_base_entrysize(10000,TRACK_TYPE_LAST);
	      vector<pair<pair<int64,int64>,int>>::iterator it;
	      int ctr = 0;
	      for (it = t.begin(); it != t.end(); ++it) {
	          pair<int64,int64> t2 = get<0>(*it);
                  int t3 = get<1>(*it);
		  int64 t4 = get<0>(t2);
		  int64 t5 = get<1>(t2);
		  out << t4 << " " << t5 << " " << t3 << " " << results[0] << endl;
		 ctr++; 
	      }
	      cout<<"jump table printed: "<<ctr<<"\n";

	}
	inp.close();
	out.close();
	return 0;
}
