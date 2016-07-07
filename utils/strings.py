import json

def quote(command):
    return command.replace("\\", "\\\\").replace("\"", "\\\"")