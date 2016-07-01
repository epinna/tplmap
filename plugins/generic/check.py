from core.plugin import Plugin
from random import randint


class Check(Plugin):
    
    def __init__(self, channel):
        
        self.channel = channel
        self.state = {}
        
        self.init()
            
    def check(self):
        pass
            
    def setup(self):
        pass
    