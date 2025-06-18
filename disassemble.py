# To be run with customized python3!
"""
Small helper script that simply unmarshals and disassembles the input file.
"""

import dis
import marshal
import sys
from io import BytesIO


with open(sys.argv[1], "rb") as fp:
    skip = int.from_bytes(fp.read(4), 'little') + int.from_bytes(fp.read(4), 'little')
    fp.seek(skip)
    data = fp.read()

obj = marshal.load(BytesIO(data))
dis.dis(obj)
