/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include <iostream>
#include <cstdlib>
#include "x64.h"
using namespace std;

int n;
string s;
fstream myFile;

int main(int argc, char *argv[]) {
  // auto-setup
  x64 myTool;
  myTool.auto_setup();

  // retrieve PLUGIN_OUTPUT_DIR
  string OUTPUT_DIR = getenv(argv[1]);
  if (OUTPUT_DIR[OUTPUT_DIR.length()-1] != '/')
    OUTPUT_DIR.push_back('/');

  // retrieve number of temporary files
  s = OUTPUT_DIR + "tmpCount.txt";
  myFile.open(s.c_str(), fstream::in);
  myFile >> n;
  myFile.close();

  // truncate the output file
  myFile.open(argv[2], fstream::out | fstream::trunc);
  myFile.close();

  // process all temporary files
  for (int i = 0; i < n; ++i) {
    if (i % 3 == 0) {
      cout << "\rGenerating " << argv[2] << ": " << 100*(i+1)/n << "% ...";
      cout.flush();
    }
    s = OUTPUT_DIR + "tmp_" + to_string(i) + ".txt";
    STR_STR myAsmRtl = myTool.read_all(s.c_str());
    myTool.print_list(argv[2], myAsmRtl);
  }
  cout << "\rGenerated " << argv[2] << "!          " << endl;
}