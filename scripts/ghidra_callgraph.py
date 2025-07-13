from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.symbol import RefType
from ghidra.util.task import ConsoleTaskMonitor

visited_funcs = set()
visited_bbs = set()
edges = []

def process_function(func):
    if func is None:
        return
    func_id = func.getEntryPoint()
    if func_id in visited_funcs:
        return
    visited_funcs.add(func_id)

    print(f"\n[+] Processing function: {func.getName()} @ {func_id}")

    bb_model = BasicBlockModel(currentProgram)
    task_monitor = ConsoleTaskMonitor()
    try:
        # Get all basic blocks reachable from entry by direct control flow
        bb_iter = bb_model.getBasicBlocksContaining(func.getBody(), task_monitor)
    except Exception as e:
        print(f"Error getting basic blocks for {func.getName()}: {e}")
        return

    # Collect BBs reachable from entry - BFS style
    entry_bb = None
    for bb in bb_iter:
        if bb.getFirstStartAddress() == func.getEntryPoint():
            entry_bb = bb
            break
    if entry_bb is None:
        print(f"Could not find entry BB for {func.getName()}")
        return

    queue = [entry_bb]

    while queue:
        bb = queue.pop(0)
        bb_id = bb.getFirstStartAddress()
        if bb_id in visited_bbs:
            continue
        visited_bbs.add(bb_id)
        print(f"  Processing BB @ {bb_id}")

        # Process instructions in BB
        instr = getInstructionAt(bb.getFirstStartAddress())
        bb_end = bb.getLastEndAddress()

        while instr is not None and instr.getAddress() <= bb_end:
            flow_type = instr.getFlowType()
            refs = instr.getReferencesFrom()

            # --- Direct calls ---
            if flow_type.isCall():
                if refs:
                    for ref in refs:
                        if ref.getReferenceType().isCall():
                            target_func = getFunctionAt(ref.getToAddress())
                            if target_func:
                                print(f"    CALL: {instr} -> {target_func.getName()}")
                                edges.append((func, target_func))
                                process_function(target_func)
                            else:
                                print(f"    CALL: unresolved target {ref.getToAddress()} at {instr.getAddress()}")

                else:
                    print(f"    Indirect CALL unresolved at {instr.getAddress()}")

            # --- Indirect jump (e.g., jump table) ---
            elif flow_type.isJump() and flow_type.isIndirect():
                if refs:
                    for ref in refs:
                        if ref.getReferenceType().isComputed():
                            target_addr = ref.getToAddress()

                            # Is this a PLT stub? (cross-module)
                            target_func = getFunctionAt(target_addr)
                            if target_func and target_func.getName().endswith("@plt"):
                                ext_name = target_func.getName().split("@")[0]
                                ext_func = getExternalFunction(ext_name)
                                if ext_func:
                                    print(f"    Indirect JMP PLT: {instr} → External function {ext_func.getName()}")
                                    edges.append((func, ext_func))
                                    # Optionally process ext_func if desired
                                else:
                                    print(f"    Indirect JMP PLT: {instr} → Unresolved external function {ext_name}")
                                continue

                            # Normal jump table target: get BBs from target and process recursively
                            target_bb_iter = bb_model.getBasicBlocksContaining(target_addr, task_monitor)
                            for target_bb in target_bb_iter:
                                if target_bb.getFirstStartAddress() not in visited_bbs:
                                    print(f"    Indirect JMP jump table target BB @ {target_bb.getFirstStartAddress()}")
                                    queue.append(target_bb)

                else:
                    print(f"    Indirect JMP unresolved at {instr.getAddress()}")

            instr = instr.getNext()

        # Enqueue successor BBs by direct control flow (excluding calls and indirect jumps)
        successors = bb.getDestinations(task_monitor)
        for dest in successors:
            dest_bb = dest.getDestinationBlock()
            if dest_bb and dest_bb.getFirstStartAddress() not in visited_bbs:
                queue.append(dest_bb)

# --- MAIN ---

# Example: process a specific function by name or entry address
func_name = "main"
start_func = getFunction(func_name)
if start_func is None:
    print(f"Function {func_name} not found")
else:
    process_function(start_func)
    print(f"\n[+] Traversal finished. Processed {len(visited_funcs)} functions and {len(visited_bbs)} basic blocks.")
