"""
Minimum Python version: 3.9

This IDA script adds comments in the decompiler view for all references to constants in
BCC functions.

IMPORTANT: For this to work, the pointer variable must be of type QWORD* in every function.
The pointer in question is usually assigned at the top of the function:
v4 = *(_QWORD **)(a1 + 8LL * *(int *)(a1 + 16) + 16);

Then you'll see lots of references like v4[3], v4[4], v4[5], etc., which are targeted
by this script.
"""

import idaapi
import ida_funcs
import ida_kernwin
import ida_hexrays
import idc
import json
from typing import Optional


def open_json_file() -> Optional[list[dict]]:
    """Simple file selector function. Returns loaded list."""
    path = ida_kernwin.ask_file(0, "*.json", "Select .elf.json file")
    if not path:
        print("No file selected.")
        return None
    with open(path, 'r') as f:
        return json.load(f)


def create_and_rename_function(offset: int, name: str) -> None:
    if not ida_funcs.get_func(offset):
        if not ida_funcs.add_func(offset):
            print(f"Failed to create function at {hex(offset)}")
            return
    idc.set_name(offset, name, idc.SN_CHECK)


class ConstsAnnotator(ida_hexrays.ctree_visitor_t):
    """
    Tree visitor class that adds comments to statements that reference the constants.
    """

    def __init__(self, cfunc, consts: list) -> None:
        super().__init__(ida_hexrays.CV_FAST)
        self.alias_map: dict[str, str] = {}
        self.consts_base = ""
        self.comments_added = 0
        self.cfunc = cfunc
        self.consts = consts

    def visit_insn(self, i) -> int:
        return 0

    def visit_expr(self, expr) -> int:
        if expr.op == ida_hexrays.cot_asg and expr.x and expr.y:
            # Look for v4 = *(...)
            if self.consts_base == "" and expr.y.op == ida_hexrays.cot_ptr and expr.y.x:
                # We could check if expr.y.x matches (a1 + 8 * *(int *)(a1 + 16) + 16),
                # but we're just going to assume the first ptr deref is the one we need.
                assigned_var = expr.x.v.idx if expr.x.op == ida_hexrays.cot_var else None
                if assigned_var:
                    self.consts_base = assigned_var
                    print(f"Found consts pointer v{assigned_var}")

            # Track alias like v1012 = v4
            if expr.x.op == ida_hexrays.cot_var and expr.y.op == ida_hexrays.cot_var:
                if expr.y.v.idx == self.consts_base:
                    self.alias_map[expr.x.v.idx] = expr.y.v.idx

        # Look for pointer index accesses...
        if expr.op == ida_hexrays.cot_idx:
            if expr.y and expr.x.op == ida_hexrays.cot_var and expr.y.op == ida_hexrays.cot_num:
                varname = expr.x.v.idx
                index = expr.y.numval()
                # ...check if base is our pointer of interest
                base_var = self.alias_map.get(varname, varname)
                if base_var == self.consts_base and index >= 3 and (index - 3) < len(self.consts):
                    # ...add comment
                    comment = self.consts[index - 3]
                    if expr.ea != idaapi.BADADDR:
                        loc = ida_hexrays.treeloc_t()
                        loc.ea = expr.ea
                        # Add after semicolon; if the line doesn't have one, the comment will be orphaned :/
                        loc.itp = ida_hexrays.ITP_SEMI
                        self.cfunc.set_user_cmt(loc, comment)
                        self.comments_added += 1
                    else:
                        print(f"[!] ea not available for {expr.dstr()}, unable add comment {comment}")

        return 0  # Continue traversal


def annotate_consts_in_decompilation(ea: int, consts: list) -> None:
    """Annotates the given function with the given constants."""
    cfunc = ida_hexrays.decompile(ea)
    if not cfunc:
        print(f"Failed to decompile function at {hex(ea)}")
        return

    annotator = ConstsAnnotator(cfunc, consts)

    cfunc.get_eamap()  # Ensure mapping is available
    annotator.apply_to(cfunc.body, None)

    cfunc.save_user_cmts()
    print(f"Added {annotator.comments_added} comments to function at {hex(ea)}")


def main() -> None:
    hexrays_avail = ida_hexrays.init_hexrays_plugin()
    if not hexrays_avail:
        print("Hex-Rays plugin not available - won't annotate")

    data = open_json_file()
    if data is None:
        return

    for entry in data:
        offset = entry['offset']
        name = entry['name']
        consts = entry['consts']
        create_and_rename_function(offset, name)
        if hexrays_avail:
            annotate_consts_in_decompilation(offset, consts)


main()
