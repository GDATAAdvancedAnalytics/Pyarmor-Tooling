# To be run with customized python3!
"""
This script processes the decrypted pyarmor bytes string and outputs
a json file that describes how to decrypt the individual code objects.
"""

import dis
import json
import marshal
import opcode
import sys
from io import BytesIO


def display_code(code_obj):
    """Prints all relevant attributes of the given code object."""
    attributes = dir(code_obj)
    for attr in attributes:
        if attr == "co_code":
            continue
        if not attr.startswith("co") and not attr.startswith("_co"):
            continue
        try:
            value = getattr(code_obj, attr)
            vstr = str(value)
            if len(vstr) < 1000:
                print(f"{attr}: {vstr}")
            else:
                print(f"{attr}: {vstr[:500]}  <<< SNIP >>>  {vstr[-500:]}")
        except AttributeError:
            print(f"{attr}: [Attribute not accessible]")

    # try:
    #     dis.dis(code_obj)
    # except Exception:
    #     print("    --- code crypted after this offset ---")


# The dis() call would print something like this:
"""

  0           0 NOP

  1           2 NOP
              4 PUSH_NULL
              6 LOAD_CONST               1 ('__pyarmor_enter_60307__')

  2           8 LOAD_CONST               2 (b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x1a@\x00\x00\x00\x00\x00\x00\x00')
             10 BUILD_TUPLE              1
             12 CALL_FUNCTION_EX         0
             14 POP_TOP
             16 RESUME                   0
             18 NOP
             20 NOP
             22 NOP
             24 NOP

"""


def get_crypto_info(all_data: bytes, code_obj) -> dict:
    """Returns a dictionary with information about the ciphered region in the code object."""

    # NOTES:
    # 1. co_code is sanitized before being given out to a script (invalid opcodes are zeroed), so it's useless for us
    # 2. Using _co_code_adaptive only works because we disable specialization in our custom Python build
    code: bytes = code_obj._co_code_adaptive
    code_offset_in_data = all_data.index(code)

    if code[8] != opcode.opmap["LOAD_CONST"]:
        raise Exception("Expected LOAD_CONST at offset 8")

    # Get the LOAD_CONST bytes that can be seen above at offset 8.
    crypto_info = code_obj.co_consts[code[9]]

    if not isinstance(crypto_info, bytes):
        raise Exception(f"Expected LOAD_CONST to load bytes, got {type(crypto_info)}")

    if crypto_info[8] & 4:
        raise Exception("Bit for mask 4 is set! Probably special nonce handling")

    ciphertext_offset = crypto_info[11]
    ciphertext_size = int.from_bytes(crypto_info[12:16], 'little')

    nonce_offset = crypto_info[9]
    if (crypto_info[8] & 2) == 0:
        nonce_offset += ciphertext_offset + ciphertext_size

    nonce = code[nonce_offset:nonce_offset+12]

    return {
        'ciphertext_offset': code_offset_in_data + ciphertext_offset,
        'ciphertext_size': ciphertext_size,
        'nonce': nonce.hex()
    }


with open(sys.argv[1], "rb") as fp:
    fp.seek(0x20)
    data = fp.read()

obj = marshal.load(BytesIO(data))

display_code(obj)

crypted_regions = []

for const in obj.co_consts:
    if isinstance(const, type((lambda: None).__code__)):
        print("Found " + str(const))
        display_code(const)
        crypted_regions.append(get_crypto_info(data, const))

crypted_regions.append(get_crypto_info(data, obj))

json.dump(crypted_regions, open(sys.argv[1] + ".json", "w"))

print(f"Found {len(crypted_regions)} encrypted code objects. {sys.argv[1]}.json saved.")
