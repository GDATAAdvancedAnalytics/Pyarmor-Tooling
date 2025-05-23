# To be run with customized python3!
"""
This script analyzes BCC data. It works with the .dec2 and .dec.elf files generated
by the other scripts.

It prints some information about BCC functions and generates a JSON file for ida_annotate_bcc.py.
"""

import json
import marshal
import os
import sys
from io import BytesIO
from typing import Optional


def decode_compact_int(p: bytes) -> tuple[int, int]:
    """
    Decodes a compact int from the beginning of the given bytes string.
    :return: Tuple of (value, number of bytes consumed).
    """
    if len(p) < 2:
        raise ValueError("Input too short to decode")

    val = p[1]
    i = 2
    expected_len = (p[0] >> 6) + 2

    while i < len(p) and i < expected_len:
        val = p[i] | (val << 8)
        i += 1

    return val, i


def parse_pyarmor_data(code_obj, bcc_list: list[tuple[int, str]]) -> Optional[tuple[int, str, list]]:
    """
    Parses pyarmor data attached to code_obj. This data describes how the runtime should
    patch entries in co_consts. The runtime replaces strings with references to native functions.

    :param code_obj: The code object to inspect.
    :param bcc_list: List of all BCC functions in the ELF.
    :return: Tuple (offset, func name, constants) or None if code_obj does not use BCC.
    """
    extradata = code_obj.co_pyarmor_data
    if len(extradata) <= 0:
        return None

    first = extradata[0]
    patch_count = first & 0x3
    method_count = (first >> 2) & 0x3
    has_bcc = bool(first & 0x10)
    has_locals_patch = bool(first & 0x20)

    print(f"Parsed extradata flags: patch_count={patch_count}, "
          f"method_count={method_count}, BCC={'yes' if has_bcc else 'no'}, "
          f"locals_patch={'yes' if has_locals_patch else 'no'}")

    offset = 4
    p = extradata[offset:]

    for i in range(patch_count):
        if len(p) < 1:
            print("  Insufficient data for patch")
            break

        function_id = p[0] & 0x3F
        compact_val, consumed = decode_compact_int(p)
        const_value = code_obj.co_consts[compact_val]

        # These are relatively boring, they map to the assert/enter/leave C functions in the Pyarmor runtime.
        print(f"  Patch {i}: consts[{compact_val} : {const_value}] = method_table[{function_id}]")

        p = p[consumed:]
        offset += consumed

    if has_bcc and len(p) > 0:
        const_index = p[0] & 0x3F
        const_value = code_obj.co_consts[const_index]
        compact_val, _ = decode_compact_int(p)
        bcc_offset, bcc_name = bcc_list[compact_val]
        print(f"  BCC: consts[{const_index} : {const_value}] = {bcc_name} at ELF offset {hex(bcc_offset)}")

        bcc_consts = []
        if isinstance(code_obj.co_consts[const_index + 1], tuple):
            print("  Constants:")
            for i, c in enumerate(code_obj.co_consts[const_index + 1]):
                print(f"    {i + 3}: {c}")
                if isinstance(const, type((lambda: None).__code__)):
                    bcc_consts.append(str(c))
                else:
                    bcc_consts.append(c)

        return bcc_offset, f"{bcc_name}_{code_obj.co_name}", bcc_consts

    return None


def read_null_term(data: bytes, offset: int) -> str:
    """Reads a null-terminated string from data at offset."""
    length = 0
    while data[offset+length] != 0:
        length += 1

    return data[offset:offset+length].decode()


def parse_custom_elf(elf: bytes) -> list[tuple[int, str]]:
    # These offsets can be found in the method that allocates the bcc code.
    shdr_off = int.from_bytes(elf[40:48], 'little')
    info_section_off = shdr_off + 64 * elf[62]
    func_table_off = info_section_off + 24

    i = int.from_bytes(elf[func_table_off:func_table_off+8], 'little')
    reader = BytesIO(elf[i:])
    bcc_list = []
    while True:
        name_off = int.from_bytes(reader.read(8), 'little')
        if name_off == 0:  # table seems to end with an all zero entry
            break
        func_off = int.from_bytes(reader.read(8), 'little')
        reader.read(8)
        reader.read(8)
        bcc_list.append((func_off, read_null_term(elf, name_off)))

    return bcc_list


if len(sys.argv) < 2 or not os.path.exists(sys.argv[1]):
    print(f"Usage: {sys.argv[0]} <path to .dec2>")
    sys.exit(1)

elf_name = sys.argv[1].replace(".dec2", ".dec.elf")
if not os.path.exists(elf_name):
    print(f"{elf_name} does not exist! BCC mode is not in use or was not dumped.")
    sys.exit(1)

# Parse ELF to get BCC func table.
with open(elf_name, "rb") as fp:
    bcc_list = parse_custom_elf(fp.read())

# Unmarshal Python module containing the calls to BCC.
with open(sys.argv[1], "rb") as fp:
    fp.seek(0x20)
    data = fp.read()

obj = marshal.load(BytesIO(data))

# Process pyarmor_data bytes in code objects.
output_list = []
print(str(obj))
if obj.co_pyarmor_data is not None:
    output_list.append(parse_pyarmor_data(obj, bcc_list))

for const in obj.co_consts:
    if isinstance(const, type((lambda: None).__code__)):
        print("\n\n" + str(const))
        if const.co_pyarmor_data is not None:  # type: ignore
            output_list.append(parse_pyarmor_data(const, bcc_list))

# Dump info to disk as json.
output_list_f = list(filter(None, output_list))
output_list_named = [{"offset": offset, "name": name, "consts": consts} for offset, name, consts in output_list_f]
json.dump(output_list_named, open(elf_name + ".json", "w"))

print(elf_name + ".json saved for IDA script.")
