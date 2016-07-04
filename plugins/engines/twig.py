from core.check import Check
from utils.loggers import log
from utils import rand
import string
import requests
import urlparse
import os

class Twig(Check):
    
    def detect(self):
        
        # Declare payload
        self.base_tag = '{{%s}}'
        
        # Skip reflection check if same tag has been detected before
        if self.get('reflect_tag') != self.base_tag:
            self._check_reflection()
        
            # Return if reflect_tag is not set
            if not self.get('reflect_tag'):
                return
                
            log.warn('Reflection detected with tag \'%s\'' % self.get('reflect_tag'))
        
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
            self.set('reflect_tag', self.base_tag)
        