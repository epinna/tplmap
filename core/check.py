from core.plugin import Plugin
import random
import re


class Check(Plugin):
    
    def __init__(self, channel):
        
        # HTTP channel
        self.channel = channel
        
        # Random header and trailer
        self.req_header_rand = str(random.randint(99, 1000))
        self.req_trailer_rand = str(random.randint(99, 1000))
    
        self.init()
        
    def req(self, payload):
        
        req_header = self.base_tag % self.req_header_rand
        req_trailer = self.base_tag % self.req_trailer_rand
        
        response = self.channel.req(req_header + payload + req_trailer)
        before,_,result = response.partition(self.req_header_rand)
        result,_,after = result.partition(self.req_trailer_rand)
        
        return result.strip()
    
    def set(self, key, value):
        self.channel.data[key] = value
        
    def get(self, key, default = None):
        return self.channel.data.get(key, default)