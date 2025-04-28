"""Binary Ninja implementation of "get_key_via_md5" for statically obtaining key."""

import hashlib

# This string is a unique license ID of the person who obfuscated the script, in the free version it would always be 000000 and in paid versions its unique per person
PYARMOR_STRING = b"pyarmor-vax-007106\x00\x00"

# References to these are in the "get_key_via_md5" function
"""
  get_key_via_md5(&var_1c8, sx.q(data_65642050) + &data_65642060, data_65642054)
"""
INFO_BLOB_ADDR = 0x65642060

# First xmmword that is xored:
# 	int128_t zmm0 = data_656479c0
#	data_65646140 ^= zmm0
#	data_65646150.o ^= zmm0
#	data_65646160 ^= zmm0
RSA_KEY2_ADDR = 0x65646140

# From a global dword passed to md5_process
RSA_KEY2_SIZE = 0x10E

# Byte value that RSA_KEY2 is xored with
RSA_XOR_KEY = 0xF1


md = hashlib.md5()
md.update(PYARMOR_STRING)

br = BinaryReader(bv, Endianness.BigEndian)

rsakey_size = int.from_bytes(br.read(4, INFO_BLOB_ADDR - 0xC), 'little')
rsakey = br.read(rsakey_size, INFO_BLOB_ADDR + 0x20)

sig_offset = int.from_bytes(br.read(4, INFO_BLOB_ADDR - 0x8), 'little')
hashed_area_size = int.from_bytes(br.read(4, INFO_BLOB_ADDR + sig_offset + 4), 'little')
hashed_area = br.read(hashed_area_size, INFO_BLOB_ADDR + sig_offset + 0x20)

rsakey2 = bytes([b ^ RSA_XOR_KEY for b in br.read(RSA_KEY2_SIZE, RSA_KEY2_ADDR)])

md.update(rsakey)
md.update(hashed_area)
md.update(rsakey2)
print(md.hexdigest())
