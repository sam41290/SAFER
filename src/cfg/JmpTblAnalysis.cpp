#include "JmpTblAnalysis.h"
#include <unistd.h>

using namespace SBI;

JmpTblAnalysis::JmpTblAnalysis (uint64_t memstrt, uint64_t memend) :
                 CFValidity(memstrt,memend,INSVALIDITY) {}
void
JmpTblAnalysis::readTargets (JumpTable & jt, uint64_t jloc)
{
  string binary_path = exePath();
  uint64_t start = jt.location();
  int entry_size = jt.entrySize();

  DEF_LOG("Jump table location: "<<hex<<start<<" end: "<<jt.end()
      <<" type: "<<jt.type()<<" entry size: "<<entry_size);

  while (start < jt.end()) {
    //LOG("Decoding at: "<<hex<<start);
    int64_t offt = 0;
    if(jt.type() != 2) {
      uint64_t file_offt = utils::GET_OFFSET(binary_path,start);
      utils::READ_FROM_FILE(binary_path, (void *) &offt, file_offt,
          entry_size);
    }
    uint64_t tgt = TARGET(offt,start,jt.type(),jt.base(),entry_size);
    if (tgt != 0) {
      LOG("Target = "<<hex<<tgt);
      //Jump table target conflicts with previously determined definite code.
      auto bb = withinBB(jloc);
      rootSrc(bb->rootSrc());
      if (addToCfg(tgt, PointerSource::JUMPTABLE) == false)
        break;
      uint64_t end = dataSegmntEnd(jt.location ());
      jt.end(min(jt.end(),end));
      //linkAllBBs();
      //bb = withinBB(jloc);
      //bb->isJmpTblBlk(true);
      //DEF_LOG("Updating indirect target for bb: "<<hex<<bb->start()<<" tgt: "
      //    <<hex<<tgt);
      //while(bb->fallThrough() != 0)
      //  bb = bb->fallThroughBB();
      auto tgt_bb = getBB(tgt);
      if(tgt_bb != NULL) {
        addIndrctTgt(bb->end(),tgt_bb);
        newPointer(tgt,PointerType::UNKNOWN,PointerSource::JUMPTABLE,bb->start());
        //LOG("indirect target added");
        jt.addTarget(tgt);
      }
    }
    start += entry_size;
  }
  jt.displayTgts();
  LOG("jump table end: "<<hex<<jt.end());
}

void
JmpTblAnalysis::preCachedJumpTables() {
  string dir = get_current_dir_name();
  ifstream ifile;
  ifile.open(dir+"/jmp_table/result.jtable");
  string line;
  while(getline(ifile,line)) {
    vector <string> words = utils::split_string(line,' ');
    if(words.size() > 0) {
      int type = stol(words[0],0,10);
      if(type == 1) {
        JumpTable j;
        j.type(1);
        uint64_t cf_loc = stoull(words[1],0,10);
        j.cfLoc(cf_loc);
        j.base(stoull(words[2],0,10));
        j.location(stoull(words[3],0,10));
        DEF_LOG("Pre cached Type 1 Location: "<<hex<<j.location()<<" base: "<<j.base());
        j.entrySize(stoull(words[4],0,10));
        cachedJTables_[cf_loc].push_back(j);
        //jmp_tbls.push_back(j);
      }
      else if(type == 2) {
        JumpTable j;
        j.type(2);
        uint64_t cf_loc = stoull(words[1],0,10);
        j.cfLoc(cf_loc);
        j.location(stoull(words[2],0,10));
        j.base(j.location());
        DEF_LOG("Pre cached Type 2 Location: "<<hex<<j.location());
        j.entrySize(stoull(words[3],0,10));
        cachedJTables_[cf_loc].push_back(j);
        //jmp_tbls.push_back(j);
      }
      else if(type == 3) {
        JumpTable j;
        j.type(3);
        uint64_t cf_loc = stoull(words[1],0,10);
        j.cfLoc(cf_loc);
        j.location(stoull(words[2],0,10));
        j.base(j.location());
        DEF_LOG("Pre cached Type 3 Location: "<<hex<<j.location());
        j.entrySize(stoull(words[3],0,10));
        cachedJTables_[cf_loc].push_back(j);
        //jmp_tbls.push_back(j);
      }
    }
  }
  ifile.close();
  /*
  ifile.open(dir+"/jmp_table/result.njtable");
  while(getline(ifile,line)) {
    uint64_t no_jtable_cf = stoull(line,0,10);
    noJTable_.insert(no_jtable_cf);
  }
  ifile.close();
  */
}

void
JmpTblAnalysis::processJTable(JumpTable &j) {
  if (jmpTblExists(j) == false) {
    map <uint64_t, Function *>funMap = funcMap();
    if(CFValidity::validAddrs(j.base()) == false ||
       isMetadata(j.base()))
      return;
    if(CFValidity::validAddrs(j.location()) == false ||
       isMetadata(j.location()))
      return;
    j.end(dataSegmntEnd(j.location()));
    if (j.end() == 0) {
      LOG ("Unexpected end!!!");
      return;
    }
    LOG("Decoding jump table: ");
    DEF_LOG("Location: "<<hex<<j.location()<<" base: "<<j.base()<<" end: "<<hex<<j.end());
    auto cf_loc = j.cfLoc();
    auto fn = is_within(cf_loc[0],funMap);
    j.function(fn->first);
    readTargets(j,cf_loc[0]);
    if(j.base() != 0) {
      auto basebb = getBB(j.base());
      if(basebb != NULL)
        j.baseBB(basebb);
    }
    jumpTable(j);
  }
}

void
JmpTblAnalysis::decodeJmpTblTgts(analysis::JTable j_lst) {
  map <uint64_t, Function *>funMap = funcMap();
  vector <JumpTable> jmp_tbls;
  for (auto& [jloc, jtable]: j_lst.type1()) {
  /* ~~ offset + *(base + index * stride) ~~ */
    JumpTable j;
    j.type(1);
    j.base(jtable.offset.val);

    j.location(jtable.mem.addr.base.val);
    DEF_LOG("Type 1 Location: "<<hex<<j.location()<<" base: "<<j.base()<<" end: "<<hex<<j.end());
    if (definiteCode(j.location()))
      continue;
    j.entrySize(jtable.mem.addr.range.stride);
    j.cfLoc(jloc);
    jmp_tbls.push_back(j);
  }
  for (auto& [jloc, jtable]: j_lst.type2()) {
  /* ~~~~~~~~ base + index * stride ~~~~~~~~ */
    JumpTable j;
    j.type(2);
    j.base(jtable.base.val);
    j.location(jtable.base.val);
    if (definiteCode(j.location()))
      continue;
    j.entrySize(jtable.range.stride);
    j.cfLoc(jloc);
    jmp_tbls.push_back(j);
  }
  /* ~~~~~~ *(base + index * stride) ~~~~~~~ */
  for (auto& [jloc, jtable]: j_lst.type3()) {
    JumpTable j;
    j.type(3);
    j.base(jtable.addr.base.val);
    j.location(jtable.addr.base.val);
    if (definiteCode(j.location()))
      continue;
    j.entrySize(jtable.addr.range.stride);
    j.cfLoc(jloc);
    jmp_tbls.push_back(j);
  }
  for(auto & j : jmp_tbls) {
    if (jmpTblExists(j) == false) {
      //auto h = (uint64_t)(j.location()+jtable.mem.addr.range.h);
      //j.end(std::min(h,dataSegmntEnd(j.location())));
      if(CFValidity::validAddrs(j.base()) == false ||
         isMetadata(j.base()))
        continue;
      if(CFValidity::validAddrs(j.location()) == false ||
         isMetadata(j.location()))
        continue;
      j.end(dataSegmntEnd(j.location()));
      if (j.end() == 0) {
        LOG ("Unexpected end!!!");
        continue;
      }
      LOG("Decoding jump table: ");
      DEF_LOG("Location: "<<hex<<j.location()<<" base: "<<j.base()<<" end: "<<hex<<j.end());
      //BasicBlock *cfbb = withinBB(jloc);
      //cfbb->isJmpTblBlk(true);
      auto cf_loc = j.cfLoc();
      auto fn = is_within(cf_loc[0],funMap);
      j.function(fn->first);
      readTargets(j,cf_loc[0]);
      if(j.base() != 0) {
        auto basebb = getBB(j.base());
        if(basebb != NULL)
          j.baseBB(basebb);
      }
      if(j.targets().size() > 0) {
        DEF_LOG("Adding jump table: "<<hex<<j.location());
        jumpTable(j);
      }
    }
  }
}

bool
hasIndJmp(vector <BasicBlock *> & bb_list) {
  for(auto & bb : bb_list)
    if(bb->indirectCFWithReg())
      return true;
  return false;
}

void
JmpTblAnalysis::analyzeAddress(vector <int64_t> &entries) {
  vector <BasicBlock *> fin_bb_list;
  vector <int64_t> entries_to_analyze;
  for(auto & entry : entries) {
    auto bb = getBB(entry);
    if(bb != NULL) {
      DEF_LOG("Analyzing jump table for: "<<hex<<entry);
      vector <BasicBlock *> bb_list = bbSeq(bb);
      if(validIns(bb_list)) {
        fin_bb_list.insert(fin_bb_list.end(),bb_list.begin(),bb_list.end());
        entries_to_analyze.push_back(entry);
      }
    }
  }
  if(hasIndJmp(fin_bb_list)) {
    unordered_set <uint64_t> cache_checked;
    bool all_cached = true;
    for(auto & bb : fin_bb_list) {
      if(bb->indirectCFWithReg()) {
        auto last_ins = bb->lastIns();
        auto cf = last_ins->location();
        if(cache_checked.find(cf) == cache_checked.end()) {
          cache_checked.insert(cf);
          if(cachedJTables_.find(cf) != cachedJTables_.end()) {
            for(auto & j : cachedJTables_[cf])
              processJTable(j);
          }
          else
            all_cached = false;
        }
      }
    }
    if(all_cached)
      return;
    string dir = get_current_dir_name();
    string file_name = /*TOOL_PATH + exeName_*/ dir  + "/jmp_table/" + to_string(entries_to_analyze[0]) + ".s";
    unordered_map<int64_t, vector<int64_t>> ind_tgts;
    indTgts(fin_bb_list,ind_tgts);
    dumpIndrctTgt(/*TOOL_PATH + exeName_*/ dir  + "/jmp_table/" + to_string(entries_to_analyze[0])
        + ".ind",ind_tgts);
    genFnFile(file_name,entries_to_analyze[0],fin_bb_list);
    unordered_map<int64_t,int64_t> ins_sz = insSizes(fin_bb_list);
    dumpInsSizes(/*TOOL_PATH + exeName_*/ dir  + "/jmp_table/" + to_string(entries_to_analyze[0])
        + ".sz",ins_sz);
    //vector <int64_t> all_entries;
    //all_entries.push_back(entry);
    DEF_LOG("indirect targets size: "<<ind_tgts.size());
    if(analysis::load(file_name,ins_sz,ind_tgts,entries_to_analyze)) {
      for (int func_index = 0; ; ++func_index) {
        bool valid_func = analysis::analyze(func_index);
        if (valid_func) {
          DEF_LOG("Analyzing jump table for: "<<hex<<entries_to_analyze[func_index]);
           decodeJmpTblTgts(analysis::jump_table_analysis());
           linkAllBBs();
        }
        else
           break;
      }
      //analysis::reset();
    }
  }
}

void
JmpTblAnalysis::analyzeFn(Function * fn) {
  while(true) {
    unsigned int size = jumpTableCnt();
    set <uint64_t> alreadyAnalyzed = fn->jmpTblAnalyzed();
    set <uint64_t> entries = fn->entryPoints();
    set <uint64_t> psbl_entries = fn->probableEntry();
    entries.insert(psbl_entries.begin(),psbl_entries.end());
    vector <int64_t> to_analyze;
    for (auto & entry : entries) {
      if(alreadyAnalyzed.find(entry) == alreadyAnalyzed.end())
        to_analyze.push_back(entry);
        //analyzeAddress(entry);
    }
    analyzeAddress(to_analyze);
    to_analyze.clear();
    vector <BasicBlock *> all_leas = fn->leaBBs();
    for(auto & lea_bb : all_leas) {
      if(alreadyAnalyzed.find(lea_bb->start()) == alreadyAnalyzed.end()) {
        auto ins_list = lea_bb->insList();
        for(auto & ins : ins_list) {
          if(ins->isLea() && isJmpTblLoc(ins->ripRltvOfft()) == false) {
            //analyzeAddress(lea_bb->start());
            to_analyze.push_back(lea_bb->start());
            break;
          }
        }
      }
    }
    analyzeAddress(to_analyze);
    if (jumpTableCnt() == size) {
      for(auto & entry : entries)
        if(getBB(entry) != NULL)
          fn->jmpTblAnalyzed(entry);
      for(auto & lea_bb : all_leas)
        fn->jmpTblAnalyzed(lea_bb->start());
      break;
    }
  }
}

void
JmpTblAnalysis::jmpTblAnalysis() {
  LOG("Analyzing jump tables");
  while (true) {
    unsigned int size = jumpTableCnt();
    map <uint64_t, Function *>funMap = funcMap();
    for(auto & fn : funMap)
      analyzeFn(fn.second);
    //Loop continues untill the size of the jump table vector doesn't
    //change.
    if (jumpTableCnt() == size)
      break;
  }
  LOG("Adding target BBs to jump tables");
  updateJmpTblTgts();
  LOG("Jmp table analysis complete");


}


//-----------------OLD JUMP TABLE CODE---------------------

void
JmpTblAnalysis::analyze() {
  /* Recursively performs jump table analysis until no more jump tables are
   * discovered.
   */

  jmpTblAnalysis();
  return;

  LOG("Analyzing jump table");
#ifdef NOJMPTBLANALYSIS
  analyzeGaps();
  return;
#endif
  while(true) {
    //dp.clear();
    unsigned int size = jumpTableCnt();
    vector <string> pathFiles;
    map <uint64_t, Function *>funMap = funcMap();
    for(auto fn: funMap) {
      vector <BasicBlock *> bbList;
      vector <BasicBlock *> leaBBs;
      vector <BasicBlock *> indCfBBs;
      bbList = fn.second->getDefCode();
      fillBlocks(leaBBs,indCfBBs, bbList);
      bbList = fn.second->getUnknwnCode();
      fillBlocks(leaBBs,indCfBBs, bbList);
      vector <string> files = pairUp(leaBBs,
                              indCfBBs);
      pathFiles.insert(pathFiles.end(), files.begin(),files.end ());

    }
    processPathFiles(pathFiles);
    linkAllBBs();
    //Loop continues untill the size of the jump table vector doesn't
    //change.
    if (jumpTableCnt() == size)
      break;
  }
  LOG("Adding target BBs to jump tables");
  updateJmpTblTgts();
  LOG("Jmp table analysis complete");
}

void
JmpTblAnalysis::fillBlocks (vector <BasicBlock *> &leaBlks, vector <BasicBlock *>
    &indCfBlks,vector <BasicBlock *> &bbList) {

  //Iterates over all BBs and lists out BBs that have an indirect jump or an
  //"LEA".
  for (auto bb:bbList) {
    if (bb->indirectCFWithReg()) {
      //LOG("Indirect CF bb: "<<hex<<bb->start());
      indCfBlks.push_back(bb);
    }
     
    if (bb->isLea()) {
      //LOG("Lea bb: "<<hex<<bb->start());
      leaBlks.push_back(bb);
    }
  }
}

vector <string>  
JmpTblAnalysis::pairUp(vector <BasicBlock *> &leas,vector <BasicBlock *>
    &indCfs) {
  //For each indirect jump and "LEA" instruction pair, it checks if there is
  //a path from "LEA" to the jump.
  //If yes, then generates an assembly file of the path.

  vector <string> pathFIles;

  for (auto lea:leas) {
    for (auto jmp:indCfs) {
      string jmp_pair = to_string(lea->start()) + " " + to_string(jmp->start());
      if (leaToJmpPairs.find(jmp_pair) != leaToJmpPairs.end())
        continue;

      map <uint64_t, bool> visited;
      stack <BasicBlock *> path;
      bool found = findPath(lea,jmp,visited,path);
      if (found == true) {
        vector <BasicBlock *> basic_block_path;
        while (!path.empty ()) {
          basic_block_path.push_back (path.top ());
          path.pop ();
        }
        reverse(basic_block_path.begin (), basic_block_path.end ());
        //populate_dp_map(dp, basic_block_path, jmp);
        genFile(basic_block_path, lea->start(), jmp->start(), pathFIles);
      }
    }
  }

  return pathFIles;
}

/*
// void JmpTblAnalysis::populate_dp_map(map<string, vector<uint64_t>> &dp, vector<uint64_t> basic_block_path, uint64_t target)
// {
// 	while(basic_block_path.size() != 1)
// 	{
// 		string path_to_end = to_string(basic_block_path[0]) + " " + to_string(target);
// 		if(dp.find(path_to_end) == dp.end())
// 		{
// 			dp[path_to_end] = basic_block_path;
// 		}
// 		basic_block_path.erase(basic_block_path.begin());	
// 	}
// }
*/

void
JmpTblAnalysis::updateTargets (JumpTable & jt, BasicBlock *bb)
{
  string binary_path = exePath();
  uint64_t start = jt.location();
  int entry_size = jt.entrySize();

  LOG("Jump table location: "<<hex<<start<<" end: "<<jt.end()<<" entry size: "<<hex<<entry_size);

  while (start < jt.end()) {
    uint64_t tgt;
    if(entry_size == 4) {
      int32_t offt;
      uint64_t file_offt = utils::GET_OFFSET(binary_path,start);
      utils::READ_FROM_FILE(binary_path, (void *) &offt, file_offt, entry_size);
      tgt = jt.base() + offt;
    }
    else {
      int64_t offt;
      uint64_t file_offt = utils::GET_OFFSET(binary_path,start);
      utils::READ_FROM_FILE(binary_path, (void *) &offt, file_offt, entry_size);
      tgt = jt.base() + offt;
    }

    if (tgt != 0) {
      //Jump table target conflicts with previously determined definite code.
      rootSrc(bb->rootSrc());
      if (addToCfg(tgt, PointerSource::JUMPTABLE) == false)
        break;
      uint64_t end = dataSegmntEnd(jt.location ());
      jt.end(end);
      linkAllBBs();
      LOG("Updating indirect target for bb: "<<hex<<bb->start()<<" tgt: "
          <<hex<<tgt);
      while(bb->fallThrough() != 0)
        bb = bb->fallThroughBB();
      bb->addIndrctTgt(getBB(tgt));
      newPointer(tgt,PointerType::UNKNOWN,PointerSource::JUMPTABLE,bb->start());
      jt.addTarget(tgt);
    }
    start += entry_size;
  }
  jt.displayTgts();
  LOG("jump table end: "<<hex<<jt.end());
}

//uint64_t
//JmpTblAnalysis::dataSegmntEnd (uint64_t addrs)
//{
//  //Takes an address  and returns the location of next pointer access.
//  //The whole region starting from addrs to the next pointer access is
//  //considered as one data blk.
//
//  uint64_t next_code = nextCodeBlock(addrs);
//  //if(next_code != 0)
//  //  return next_code;
//
//  uint64_t ro_data_end = 0;
//  /*
//  map < uint64_t, Pointer * >&pointer_map = pointers ();
//
//  auto ptr_it = pointer_map.lower_bound (addrs);
//  ptr_it++;
//  if (ptr_it != pointer_map.end ()) {
//    if(ptr_it->second->source() == PointerSource::RIP_RLTV ||
//       ptr_it->second->source() == PointerSource::CONSTMEM ||
//       ptr_it->second->type() == PointerType::DP) { 
//      if(next_code == 0 ||
//        (next_code != 0 && next_code > ptr_it->first))
//        return ptr_it->first;
//      else if(next_code != 0 && next_code < ptr_it->first)
//        return next_code;
//    }
//  }
//  */
//  //else if no subsequent pointer access is found, return the end of read-only
//  //data section.
//
//  if(next_code != 0)
//    return next_code;
//
//  vector < section > rodata_sections = roSections ();
//
//  bool found = false;
//  for (section & sec : rodata_sections)
//  {
//    if (found == true)
//      return sec.vma;
//
//    if (addrs >= sec.vma && addrs <= (sec.vma + sec.size))
//      found = true;
//
//    ro_data_end = sec.vma + sec.size;
//  }
//
//  return ro_data_end;
//}

void
JmpTblAnalysis::decode()
{
  //Reads the analysis resuts and updates the jump tables.
  //Analysis results are produced in tmp/result.txt.
  map <uint64_t, Function *>funMap = funcMap();
  ifstream ifile;
  ifile.open ("tmp/result.txt");
  string jmp_tbl;
  //map <uint64_t, basic_block * >&basic_block_map = basicBlocks ();
  while (getline(ifile, jmp_tbl))
  {
    std::istringstream iss (jmp_tbl);
    std::vector < std::string > results (std::istream_iterator < std::string >
  				   {iss},
  				   std::istream_iterator < std::string >
  				   ());
    uint64_t b1 = stoi (results[0]);
    uint64_t b2 = stoi (results[1]);
    uint64_t entry_sz = stoi (results[2]);
    uint64_t cf_block = stoi (results[3]);
    BasicBlock *cfbb = getBB(cf_block);
    cfbb->isJmpTblBlk(true);
    if (definiteCode(b2))
      continue;
    if (isJmpTblLoc(b2))
      continue;
  
    JumpTable j;
    j.type(1);
    j.base (b1);
    j.location (b2);
    auto fn = is_within(cf_block,funMap);
    j.function(fn->first);
    uint64_t end = dataSegmntEnd (j.location ());
    j.end (end);
    j.entrySize(entry_sz / 8);
    if (j.end() == 0) {
      LOG ("Unexpected end!!!");
      continue;
    }

    updateTargets (j,cfbb);
    auto basebb = getBB(j.base());
    if(basebb != NULL)
      j.baseBB(basebb);
    jumpTable(j);
  }

//  LOG ("Decode complete. Size of vector: " << jmpTables_.size ());
}

void
JmpTblAnalysis::processPathFiles(vector <string> pathFIles)
{
  //Executes the jump table analysis program.
  //Input assembly files are processed in batches of 100.

  string inp_file = "tmp/all_files.txt";
  ofstream ofile;
  ofile.open (inp_file);
  for (unsigned int l = 0; l < pathFIles.size (); l++) {
    string file = pathFIles[l];
    ofile << file << endl;
    if ((l > 0 && (l % 100) == 0) || l == (pathFIles.size () - 1)) {
      ofile.close();
      string cmd = TOOL_PATH "jmp-table-analysis/jmp_tbl " + inp_file;
      if(system(cmd.c_str ()) == -1) {
        LOG("Failed to execute shell - jmp_tbl");
        exit(0);
      }
      ofile.open(inp_file);
    }
  }
  ofile.close();
  decode();
}


void
JmpTblAnalysis::genFile(vector <BasicBlock *> &basic_block_path,
				 uint64_t source, uint64_t target,
				 vector <string> &pathFIles)
{

  //Takes a path as input and generates an assembly file.
  //A path is just a list of basic blocks.

  string jmp_pair = to_string(source) + " " + to_string(target);
  leaToJmpPairs.insert(jmp_pair);
  string dir = get_current_dir_name();
  string file_name = /*TOOL_PATH + exeName_*/ dir  + "/jmp_table/" + to_string(source) + "-"
    + to_string(target);

  LOG ("File name: " << file_name);
  LOG ("Length of path: " << basic_block_path.size());
  //int offset = 0;
  ofstream ofile;
  ofile.open(file_name);
  for(auto bb:basic_block_path) {
    vector <string> all_ins = bb->allAsm();
    for (string str:all_ins) {
      vector <string> words = utils::split_string(str,' ');
      for(auto & w : words) {
        if(w == "lea")
          w = "leaq";
        else if(w == "add")
          w = "addq";
        else if(w == "notrack")
          continue;
        ofile<<w<<" ";
      }
      ofile<<endl;
      //ofile << str << endl;
    }
    if (bb->isLea())
      leaToJmpPairs.insert(to_string(bb->start()) + " " + to_string(target));
  }
  ofile.close ();
  file_name = to_string(target) + " " + file_name;
  pathFIles.push_back(file_name);
}

bool
JmpTblAnalysis::findPath(BasicBlock *bb_start, BasicBlock *bb_target,
			     map <uint64_t, bool> &visited,
			     stack <BasicBlock *> &path)
{
  //LOG("Source: "<<hex<<bb_start->start()<<" target: "<<hex<<bb_target->start());
  //Performs a DFS from bb_start to bb_target and generates a stack of BBs in
  //the path.

  string path_to_end = to_string(bb_start->start())
    + " " + to_string(bb_target->start());
  visited[bb_start->start()] = true;
  path.push(bb_start);
  if (bb_start->start() == bb_target->start())
    return true;

  BasicBlock *fallBB = bb_start->fallThroughBB();
  BasicBlock *tgtBB = bb_start->targetBB();

  if (fallBB != NULL
      && visited.find (fallBB->start()) == visited.end ()) {
    //LOG("Following fall through: "<<hex<<bb_start->fallThrough()<<" "
    //    <<fallBB->start());
    bool found = findPath(fallBB, bb_target,visited, path);
    if (found == true) {
      //dp[bb_start][bb_target] = fallBB;
      return found;
    }
  }

  //Since we are searching for intra-function paths, we do not need to
  //consider call targets.

  if (bb_start->isCall() == false && tgtBB != NULL
      && visited.find(tgtBB->start()) == visited.end ()) {
    bool found = findPath(tgtBB, bb_target,visited, path);
    if (found == true) {
      //dp[bb_start][bb_target] = tgtBB;
      return found;
    }
  }

  //Indirect targets found during previous iteration of jump table analysis
  //are also considered while searching for paths.

  if (tgtBB == NULL && fallBB == NULL) {
    auto indirect_targets = bb_start->indirectTgts();
    for (auto ind_target:indirect_targets) {
      if (visited.find (ind_target->start()) == visited.end ()) {
        bool found = findPath(ind_target, bb_target,visited, path);
        if (found == true) {
          return found;
        }
      }
    }
  }
  path.pop ();
  return false;
}

