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

    # NOTES (Python 3.11+):
    # 1. co_code is sanitized before being given out to a script (invalid opcodes are zeroed), so it's useless for us
    # 2. Using _co_code_adaptive only works because we disable specialization in our custom Python build
    if sys.version_info.major > 3 or sys.version_info.minor > 10:
        code: bytes = code_obj._co_code_adaptive
    else:
        code = code_obj.co_code
    code_offset_in_data = all_data.index(code)

    case1 = code[8] == opcode.opmap["LOAD_CONST"] and code[12] == opcode.opmap["CALL_FUNCTION_EX"]
    case2 = code[14] == opcode.opmap["LOAD_CONST"] and code[16] == opcode.opmap["CALL_FUNCTION"]
    if not case1 and not case2:
        print("Method does not seem to be encrypted")
        return {}

    # Get the constant that is loaded by LOAD_CONST at offset 8 or 14.
    crypto_info = code_obj.co_consts[code[(8 if case1 else 14) + 1]]

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


def process_code_object(code_obj, filedata: bytes, crypted_regions: list[dict]) -> None:
    """
    Recursively processes a code object and its nested code objects in constants
    in order to extract encryption information.

    Args:
        code_obj: The code object to process
        filedata: Entire contents of the Python module
        crypted_regions: List that is appended to
    """
    if info := get_crypto_info(filedata, code_obj):
        crypted_regions.append(info)

    for const in code_obj.co_consts:
        if isinstance(const, type((lambda: None).__code__)):
            print("Found nested code object: " + str(const))
            display_code(const)

            process_code_object(const, filedata, crypted_regions)


def main(filename: str) -> None:
    with open(filename, "rb") as fp:
        skip = int.from_bytes(fp.read(4), 'little') + int.from_bytes(fp.read(4), 'little')
        fp.seek(skip)
        data = fp.read()

    obj = marshal.load(BytesIO(data))
    display_code(obj)

    crypted_regions: list[dict] = []
    process_code_object(obj, data, crypted_regions)

    json.dump(crypted_regions, open(filename + ".json", "w"))

    print(f"Found {len(crypted_regions)} encrypted code objects. {filename}.json saved.")


if __name__ == "__main__":
    main(sys.argv[1])
