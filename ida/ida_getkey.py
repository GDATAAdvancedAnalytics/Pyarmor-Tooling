"""IDAPython implementation of "get_key_via_md5" for statically obtaining key."""

import ida_bytes
import hashlib

# This string is a unique license ID of the person who obfuscated the script, in the free version it would always be 000000 and in paid versions its unique per person
PYARMOR_STRING = b"pyarmor-vax-007106\x00\x00"

# References to these are in the "get_key_via_md5" function
"""
  md5_process(
    v6,
    (char *)&unk_64944060 + g_dword_64944050_0x20_rsaoffset,
    (unsigned int)g_dword_64944054_0x10E_rsakeylen);// rsa key
"""
INFO_BLOB_ADDR = 0x64944060
# First xmmword that is xored:
# xmmword_64948140 = (__int128)_mm_xor_si128(_mm_load_si128((const __m128i *)&xmmword_64948140), si128);
RSA_KEY2_ADDR = 0x64948140
# From a global dword passed to md5_process
RSA_KEY2_SIZE = 0x10E
# Byte value that RSA_KEY2 is xored with
RSA_XOR_KEY = 0xF1


md = hashlib.md5()
md.update(PYARMOR_STRING)

rsakey_size = int.from_bytes(ida_bytes.get_bytes(INFO_BLOB_ADDR - 0xC, 4), 'little')
rsakey = ida_bytes.get_bytes(INFO_BLOB_ADDR + 0x20, rsakey_size)

sig_offset = int.from_bytes(ida_bytes.get_bytes(INFO_BLOB_ADDR - 0x8, 4), 'little')
hashed_area_size = int.from_bytes(ida_bytes.get_bytes(INFO_BLOB_ADDR + sig_offset + 4, 4), 'little')
hashed_area = ida_bytes.get_bytes(INFO_BLOB_ADDR + sig_offset + 0x20, hashed_area_size)

rsakey2 = bytes([b ^ RSA_XOR_KEY for b in ida_bytes.get_bytes(RSA_KEY2_ADDR, RSA_KEY2_SIZE)])

md.update(rsakey)
md.update(hashed_area)
md.update(rsakey2)

print(md.hexdigest())
