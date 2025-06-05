"""
Minimum Python version: 3.9

This Binary Ninja script adds comments in the decompiler view for all references to constants in
BCC functions.

IMPORTANT: For this to work, the pointer variable must be of type QWORD* in every function.
Unlike the IDA one, the first dereference is not our target expressions, instead, it follows the pattern:
r12 = *(arg1 + (sx.q(*(arg1 + 0x10)) << 3) + 0x10)

Also unlike IDA, there are no v4[1], v4[2], v4[3]... Instead, Binary Ninja display those access as pointer arithmetics like:
int64_t rsi = (*(rax_4 + 0x1d0))()  
"""

import re
import json
from typing import Optional

# This should be the path to your *.elf.json
JSON_PATH = ""

def wait_modification():
    return bv.update_analysis_and_wait()

def open_json_file(json_path: str):
    if not json_path:
        return
    with open(json_path, 'r') as fp:
        print(f"Opened file {json_path} with read permissions.")
        return json.load(fp)


def create_and_rename_function(offset: int, name: str) -> None:
    """Create function at offset and rename it."""
    existing_func = bv.get_function_at(offset)
    if existing_func:
        print(f"Function already exists at {hex(offset)}, renaming to '{name}'")
        existing_func.name = name
        return
    
    func = bv.create_user_function(offset)
    if not func:
        print(f"Failed to create function at {hex(offset)}")
        return
    
    wait_modification()
    
    func.name = name
    print(f"Created and named function '{name}' at {hex(offset)}")

class ConstsAnnotator():

    def __init__(self, func, consts: list) -> None:
        self.alias_map: dict[str, str] = {}
        self.comments_added = 0
        self.func = func
        self.consts = consts
        self.target_var = None

    def find_target_constant(self):
        """Find the target constant pointer and set consts_base."""
        for block in self.func.hlil:
            for instr in block:
                if (type(instr) == HighLevelILVarInit and 
                    hasattr(instr, 'detailed_operands') and
                    type(instr.detailed_operands[1][1]) == HighLevelILDeref): # HighLevelILDeref (arg1 + (sx.q(*(arg1 + 0x10)) << 3) + 0x10)

                    target_var = instr.operands[0]

                    print(f"Found consts pointer identifier {instr}")
                    return target_var
        return None

    def map_constant_xrefs(self, target_var):
        refs = self.func.get_hlil_var_refs(target_var)
        print(f"Found XRefs: {refs}" if refs else "There are no XRefs")
        
        for ref in refs:
            ref_dest = ref.func.hlil[ref.expr_id].operands[0]
            if hasattr(ref_dest, 'identifier'): # Variable type
                ref_dest_id = ref_dest.identifier
            elif hasattr(ref_dest, 'var') and hasattr(ref_dest.var, 'identifier'): # HighLevelILVar
                ref_dest_id = ref_dest.var.identifier
            else:
                continue
            
            ref_src = ref.func.hlil[ref.expr_id].operands[1]
            # We will only track variable aliases, like v1012 = v4
            # Deref's won't be tracked
            if hasattr(ref_src, 'var') and hasattr(ref_src.var, 'identifier'): # HighLevelILVar
                ref_src_id = ref_src.var.identifier
            else:
                continue

            if ref_src_id == target_var.identifier:
                self.alias_map[ref_dest_id] = ref_src_id

    def find_constant(self):
        self.target_var = self.find_target_constant()
        if self.target_var: 
            self.map_constant_xrefs(self.target_var)

        print("\nAlias Mapping Results:")
        if self.alias_map:
            for dest_var, src_var in self.alias_map.items():
                print(f"  {dest_var} -> {src_var}")
        else:
            print("  No aliases found")

    def place_comments(self):            
        def visit_expr(expr):
            # Check if this is a dereference of our target variable + offset
            if (type(expr) == HighLevelILDeref and 
                type(expr.src) == HighLevelILAdd and
                type(expr.src.left) == HighLevelILVar and
                type(expr.src.right) == HighLevelILConst):
                
                var_id = expr.src.left.var.identifier
                offset = expr.src.right.constant
                
                # Check if this is our target variable or an alias to it
                if (var_id == self.target_var.identifier or 
                    self.alias_map.get(var_id) == self.target_var.identifier):
                    
                    # Convert byte offset to array index (offset >= 24 means index >= 3)
                    if offset >= 24 and (offset - 24) % 8 == 0:
                        array_index = (offset - 24) // 8 + 3
                        
                        if 0 <= array_index - 3 < len(self.consts):
                            comment = self.consts[array_index - 3]
                            addr = getattr(expr, 'address', None) or getattr(expr.instr, 'address', None)
                            if addr:
                                try:
                                    self.func.set_comment_at(addr, comment)
                                    self.comments_added += 1
                                    print(f"Added comment '{comment}' at {hex(addr)}")
                                except Exception as e:
                                    print(f"Failed to set comment: {e}")
        
            if hasattr(expr, 'operands'):
                for operand in expr.operands:
                    if hasattr(operand, '__iter__') and not isinstance(operand, str):
                        for sub_op in operand:
                            visit_expr(sub_op)
                    elif hasattr(operand, 'operands'):
                        visit_expr(operand)
        
        for block in self.func.hlil:
            for instr in block:
                visit_expr(instr)


def annotate_consts_in_decompilation(ea: int, consts: list) -> None:
    func = bv.get_function_at(ea)
    if not func:
        print(f"No function found at {hex(ea)}")
        return

    if not func.hlil:
        print(f"No HLIL for function at {hex(ea)}")
        return
    
    annotator = ConstsAnnotator(func, consts)
    annotator.find_constant()
    annotator.place_comments()
    
    print(f"Added {annotator.comments_added} comments to function at {hex(ea)}")

    wait_modification()

def main() -> None:
    data = open_json_file(JSON_PATH)
    if data is None:
        print("Failed to load JSON data")
        return

    print(f"Processing {len(data)} entries...")
    
    for entry in data:
        offset = entry['offset']
        name = entry['name']
        consts = entry['consts']
        
        print("-------------------------------------------------------")
        print(f"Offset: {hex(offset)}, Name: {name}, Constants: {len(consts)}")
        
        create_and_rename_function(offset, name)
        annotate_consts_in_decompilation(offset, consts)

main()