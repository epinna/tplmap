import json
import base64
from itertools import izip_longest
import hashlib

def quote(command):
    return command.replace("\\", "\\\\").replace("\"", "\\\"")

def base64encode(data):
    return base64.b64encode(data)

def base64decode(data):
    return base64.b64decode(data)

def chunkit( seq, n ):
    """A generator to divide a sequence into chunks of n units."""
    while seq:
        yield seq[:n]
        seq = seq[n:]

def md5(data):
    return hashlib.md5(data).hexdigest()
