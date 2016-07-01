from core.check import Check
from utils.loggers import log
import random
import string
import requests
import urlparse
import os

class Twig(Check):
    
    def init(self):
        
        # Declare payload
        self.payload_left = '{{%s}}' % self.rand_left
        self.payload_right = '{{%s}}' % self.rand_right
        
        self._check_reflection()
        
        if not self.state.get('reflection'):
            return
            
        log.warn('Reflection detected')
        
        self._check_engine()
            
        if not self.state.get('language') or  not self.state.get('engine'):
            return
            
        log.warn('Twig engine detected')   
            
    def _check_engine(self):
        
        rand = random.randint(0, 10)
        
        payload = '{{7*\'%s\'}}' % (rand)
        expected = str(rand*7)
        
        if expected == self.req(payload):
            self.state['language'] = 'php'
            self.state['engine'] = 'twig-*'
    
    def _check_reflection(self):
        
        randA = random.randint(10, 100)
        randB = random.randint(10, 100)

        payload = '{{%i*%i}}' % (randA, randB)
        expected = str(randA*randB)
        
        if expected == self.req(payload):
            self.state['reflection'] = True
        