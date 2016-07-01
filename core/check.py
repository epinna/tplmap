from core.plugin import Plugin
import random
import re


class Check(Plugin):
    
    def __init__(self, channel):
        
        # HTTP channel
        self.channel = channel
        
        # Current state
        self.state = {}
        
        # Payload wrappers
        self.rand_left = str(random.randint(10, 100))
        self.rand_right = str(random.randint(10, 100))
        self.payload_left = '${%s}' % self.rand_left
        self.payload_right = '${%s}' % self.rand_right
    
        self.init()
        
    def req(self, payload, wrap = True):
        
        if wrap:
            response = self.channel.req(self.payload_left + payload + self.payload_right)
            before,_,result = response.partition(self.rand_left)
            result,_,after = result.partition(self.rand_right)
        else:
            result = self.channel.req(payload)
        
        return result.strip()
            
    def check(self):
        pass
            
    def setup(self):
        pass
    