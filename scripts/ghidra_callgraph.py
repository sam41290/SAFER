#@author 
#@category Analysis
#@menupath 
#@toolbar 

from ghidra.program.model.symbol import RefType
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

visited = set()
edges = []

def process_function(func):
    if not func:
        return

    addr_str = str(func.getEntryPoint())
    if addr_str in visited:
        return
    visited.add(addr_str)

    print(f"\n[+] Visiting function: {func.getName()} @ {func.getEntryPoint()}")

    instructions = getInstructionIterator(func.getBody(), True)
    for instr in instructions:
        addr = instr.getAddress()
        flow_type = instr.getFlowType()

        # --- Handle CALLs ---
        if flow_type.isCall():
            refs = instr.getReferencesFrom()
            if refs:
                for ref in refs:
                    if ref.getReferenceType().isCall():
                        callee = getFunctionAt(ref.getToAddress())
                        if callee:
                            print(f"  CALL: {func.getName()} -> {callee.getName()} @ {callee.getEntryPoint()}")
                            edges.append((func, callee))
                            process_function(callee)
                        else:
                            print(f"  CALL: unresolved to {ref.getToAddress()}")
            else:
                print(f"  Indirect CALL (unresolved) at {addr}")

        # --- Handle JUMPs (e.g., jump tables) ---
        elif flow_type.isJump():
            if flow_type.isIndirect():
                refs = instr.getReferencesFrom()
                if refs:
                    for ref in refs:
                        if ref.getReferenceType().isComputed():
                            jump_target = getFunctionAt(ref.getToAddress())
                            if jump_target:
                                print(f"  JMP_TABLE: {func.getName()} -> {jump_target.getName()} @ {jump_target.getEntryPoint()}")
                                edges.append((func, jump_target))
                                process_function(jump_target)
                            else:
                                print(f"  JMP_TABLE: Unresolved jump target @ {ref.getToAddress()}")
                else:
                    print(f"  Indirect JMP (unresolved) at {addr}")

def find_entry_function():
    # Try common entry symbols
    for name in ["main", "_start", "__libc_start_main"]:
        sym = getSymbol(name)
        if sym:
            return getFunctionAt(sym.getAddress())

    # Fallback: find the lowest address function
    funcs = list(getFunctionManager().getFunctions(True))
    if funcs:
        return funcs[0]

    return None

# --- Main ---
entry_func = find_entry_function()
if not entry_func:
    print("[-] No entry function found.")
else:
    print(f"[+] Starting traversal from: {entry_func.getName()} @ {entry_func.getEntryPoint()}")
    process_function(entry_func)
