from core.check import Check
from utils.loggers import log
from utils import rand
import string
import requests
import urlparse
import os

class Twig(Check):
    
    def init(self):
        
        # Declare payload
        self.base_tag = '{{%s}}'
        
        self._check_reflection()
        
        if not self.get('reflection'):
            return
            
        log.warn('Reflection detected')
        
        self._check_engine()
            
        if not self.get('language') or not self.get('engine'):
            return
            
        log.warn('Twig engine detected')   
            
    def _check_engine(self):
        
        randA = rand.randint_n(1)
        
        payload = '{{7*\'%s\'}}' % (randA)
        expected = str(randA*7)
        
        if expected == self.req(payload):
            self.set('language', 'php')
            self.set('engine', 'twig-*')
    
    def _check_reflection(self):
        
        randA = rand.randint_n(1)
        randB = rand.randint_n(1)

        payload = '{{%i*%i}}' % (randA, randB)
        expected = str(randA*randB)
        
        if expected == self.req(payload):
            self.set('reflection', True)
        