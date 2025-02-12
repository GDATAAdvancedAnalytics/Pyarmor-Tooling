import dis
import marshal
import sys
from io import BytesIO


with open(sys.argv[1], "rb") as fp:
    fp.seek(0x20)
    data = fp.read()

obj = marshal.load(BytesIO(data))
dis.dis(obj)
