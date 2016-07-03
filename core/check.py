from core.plugin import Plugin
import random
import re


class Check(Plugin):
    
    def __init__(self, channel):
        
        # HTTP channel
        self.channel = channel
        
        # Payload wrappers
        self.rand_left = str(random.randint(10, 100))
        self.rand_right = str(random.randint(10, 100))
        self.payload_left = ''
        self.payload_right = ''
    
        self.init()
        
    def req(self, payload, wrap = True):
        
        if wrap and self.payload_left and self.payload_right:
            response = self.channel.req(self.payload_left + payload + self.payload_right)
            before,_,result = response.partition(self.rand_left)
            result,_,after = result.partition(self.rand_right)
        else:
            result = self.channel.req(payload)
        
        return result.strip()
    
    def set(self, key, value):
        self.channel.data[key] = value
        
    def get(self, key, default = None):
        return self.channel.data.get(key, default)