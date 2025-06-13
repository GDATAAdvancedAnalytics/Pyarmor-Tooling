# @author
# @category Analysis
# @keybinding
# @menupath
# @toolbar

"""Ghidra Jython implementation of "get_key_via_md5" for statically obtaining key."""

import hashlib
import struct
from ghidra.program.model.address import Address
from ghidra.program.model.mem import MemoryAccessException

# This string is a unique license ID of the person who obfuscated the script, in the free version it would always be 000000 and in paid versions its unique per person
PYARMOR_STRING = b"pyarmor-vax-000000\x00\x00"

# References to these are in the "get_key_via_md5" function
"""
  md5_process(auStack_1c8,s_pyarmor-vax-000000_003bc98c,0x14);
  md5_process(auStack_1c8,&DAT_003bc9c0 + DAT_003bc9b0,(long)DAT_003bc9b4);
"""
INFO_BLOB_ADDR = 0x003BC9C0

# First xmmword that is xored:
# puVar1 = (ulong *)&DAT_003bc860;

# md5_process(auStack_1c8,&DAT_003bc860,0x10e);
#                              ^ addr   ^ size
RSA_KEY2_ADDR = 0x003BC860
RSA_KEY2_SIZE = 0x10E

# Byte value that RSA_KEY2 is xored with
RSA_XOR_KEY = 0xF1


# https://gist.github.com/c3rb3ru5d3d53c/de02e869f64a551bfcd78fb318668292
def get_address(addr):
    return currentProgram.getAddressFactory().getAddress(str(hex(addr)))


def get_bytes(addr, size):
    address = get_address(addr)
    return bytearray(map(lambda b: b & 0xFF, getBytes(address, size)))


def read_dword(addr):
    b = get_bytes(addr, 4)
    return (b[3] << 24) | (b[2] << 16) | (b[1] << 8) | b[0]


md = hashlib.md5()
md.update(PYARMOR_STRING)

rsakey_size = read_dword(INFO_BLOB_ADDR - 0xC)
print("RSA Key size: 0x%x" % rsakey_size)

rsakey = get_bytes(INFO_BLOB_ADDR + 0x20, rsakey_size)

sig_offset = read_dword(INFO_BLOB_ADDR - 0x8)
print("Signature offset: 0x%x" % sig_offset)

hashed_area_size = read_dword(INFO_BLOB_ADDR + sig_offset + 4)
print("Hashed area size: 0x%x" % hashed_area_size)

hashed_area = get_bytes(INFO_BLOB_ADDR + sig_offset + 0x20, hashed_area_size)

rsakey2_raw = get_bytes(RSA_KEY2_ADDR, RSA_KEY2_SIZE)
rsakey2 = bytearray([b ^ RSA_XOR_KEY for b in rsakey2_raw])

md.update(str(rsakey))
md.update(str(hashed_area))
md.update(str(rsakey2))

print("MD5 Hash: " + md.hexdigest())
